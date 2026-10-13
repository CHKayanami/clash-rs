//! Common connection executor for selection policies. Group implementations
//! never dial a protocol; nested groups are walked with an explicit stack.

use super::{group::{ProxyGroup, WeakProxyGroup, UdpPolicy}, ProtocolOutbound, WeakProtocolOutbound};
use crate::{
    app::dns::ThreadSafeDNSResolver,
    proxy::{
        AnyOutboundDatagram, AnyStream,
        OutboundType,
    },
    session::Session,
};
use erased_serde::Serialize;
use super::utils::dialer_route;
use futures::future::BoxFuture;
use std::{collections::{HashMap, HashSet}, future::Future, io, sync::Arc, time::Instant};

pub(crate) trait DatagramConnector: Sync {
    type Datagram: Send;
    fn connect<'a>(&'a self, handler: &'a ProtocolOutbound, sess: &'a Session,
        resolver: ThreadSafeDNSResolver,
    ) -> BoxFuture<'a, io::Result<Self::Datagram>>;
}

/// Execute a leaf operation using the common nested group and retry policy.
pub(crate) trait ProtocolOperation: Sync {
    type Output: Send;
    fn execute<'a>(&'a self, handler: &'a ProtocolOutbound, sess: &'a Session)
        -> impl Future<Output = io::Result<Self::Output>> + Send + 'a;
}

struct PhysicalOperation<'a, C> {
    connector: &'a C,
    resolver: ThreadSafeDNSResolver,
    udp: bool,
}

impl<C: DatagramConnector> ProtocolOperation for PhysicalOperation<'_, C> {
    type Output = Connection<C::Datagram>;
    fn execute<'a>(&'a self, handler: &'a ProtocolOutbound, sess: &'a Session)
        -> impl Future<Output = io::Result<Self::Output>> + Send + 'a
    {
        async move {
            if self.udp {
                self.connector.connect(handler, sess, self.resolver.clone()).await
                    .map(Connection::Datagram)
            } else {
                handler.connect_stream(sess, self.resolver.clone()).await
                    .map(Connection::Stream)
            }
        }
    }
}

struct PhysicalDatagramConnector;
impl DatagramConnector for PhysicalDatagramConnector {
    type Datagram = AnyOutboundDatagram;
    fn connect<'a>(&'a self, handler: &'a ProtocolOutbound, sess: &'a Session,
        resolver: ThreadSafeDNSResolver,
    ) -> BoxFuture<'a, io::Result<Self::Datagram>> {
        handler.connect_datagram(sess, resolver)
    }
}

/// Registry node: selection policies and protocol dialers have separate contracts.
/// Cloning a node only clones its existing Arc; no additional allocation is needed.
#[derive(Debug, Clone)]
pub enum OutboundNode {
    Protocol(ProtocolOutbound),
    Group(ProxyGroup),
}

#[derive(Debug, Clone)]
pub enum WeakOutboundNode {
    Protocol(WeakProtocolOutbound),
    Group(WeakProxyGroup),
}

impl WeakOutboundNode {
    pub fn ptr_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Protocol(a), Self::Protocol(b)) => a.ptr_eq(b),
            (Self::Group(a), Self::Group(b)) => a.ptr_eq(b),
            _ => false,
        }
    }

    pub fn identity(&self) -> usize {
        match self {
            Self::Protocol(handler) => handler.identity(),
            Self::Group(group) => group.identity(),
        }
    }

    pub fn upgrade(&self) -> Option<OutboundNode> {
        match self {
            Self::Protocol(handler) => handler.upgrade().map(OutboundNode::Protocol),
            Self::Group(group) => group.upgrade().map(OutboundNode::Group),
        }
    }
}

impl OutboundNode {
    pub fn protocol<T>(handler: Arc<T>) -> Self where ProtocolOutbound: From<Arc<T>> { Self::Protocol(handler.into()) }
    pub fn group<T>(group: Arc<T>) -> Self where ProxyGroup: From<Arc<T>> { Self::Group(group.into()) }

    pub fn identity(&self) -> usize {
        match self {
            Self::Protocol(handler) => handler.identity(),
            Self::Group(group) => group.identity(),
        }
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Protocol(a), Self::Protocol(b)) => a.identity() == b.identity(),
            (Self::Group(a), Self::Group(b)) => a.identity() == b.identity(),
            _ => false,
        }
    }

    pub fn downgrade(&self) -> WeakOutboundNode {
        match self {
            Self::Protocol(handler) => WeakOutboundNode::Protocol(handler.downgrade()),
            Self::Group(group) => WeakOutboundNode::Group(group.downgrade()),
        }
    }

    pub fn name(&self) -> &str {
        match self { Self::Protocol(handler) => handler.name(), Self::Group(group) => group.name() }
    }
    pub fn proto(&self) -> OutboundType {
        match self { Self::Protocol(handler) => handler.proto(), Self::Group(group) => group.proto() }
    }
    pub fn server_name(&self) -> Option<&str> {
        match self { Self::Protocol(handler) => handler.server_name(), Self::Group(_) => None }
    }
    pub fn support_dialer(&self) -> Option<&str> {
        match self { Self::Protocol(handler) => handler.support_dialer(), Self::Group(_) => None }
    }
    pub fn dialer_dependency(&self) -> Option<OutboundNode> {
        match self { Self::Protocol(handler) => handler.dialer_dependency(), Self::Group(_) => None }
    }
    pub fn as_group(&self) -> Option<&ProxyGroup> {
        match self { Self::Group(group) => Some(group), Self::Protocol(_) => None }
    }
    pub fn as_protocol(&self) -> Option<&ProtocolOutbound> {
        match self { Self::Protocol(handler) => Some(handler), Self::Group(_) => None }
    }
    pub async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        match self { Self::Protocol(handler) => handler.as_map().await, Self::Group(group) => group.as_map().await }
    }

    /// Iterative capability inspection preserves group policies and rejects cycles.
    pub async fn support_udp(&self) -> bool {
        if let Self::Protocol(handler) = self { return handler.support_udp(); }
        let mut node = self.clone();
        let mut visited = [0; 64];
        for depth in 0..64 {
            let id = node.identity();
            if visited[..depth].contains(&id) { return false; }
            visited[depth] = id;
            match &node {
                Self::Protocol(handler) => return handler.support_udp(),
                Self::Group(group) => match group.udp_policy() {
                    UdpPolicy::Enabled => return true,
                    UdpPolicy::Disabled => return false,
                    UdpPolicy::Selected => match group.get_active_proxy().await {
                        Some(selected) => node = selected,
                        None => return false,
                    },
                },
            }
        }
        false
    }
    pub async fn connect_stream(&self, sess: &Session, resolver: ThreadSafeDNSResolver) -> io::Result<AnyStream> {
        match self {
            Self::Protocol(handler) => handler.connect_stream(sess, resolver).await,
            Self::Group(group) => match connect(group, sess, resolver, false, &PhysicalDatagramConnector).await? {
                Connection::Stream(stream) => Ok(stream),
                _ => unreachable!(),
            },
        }
    }
    pub async fn connect_datagram(&self, sess: &Session, resolver: ThreadSafeDNSResolver) -> io::Result<AnyOutboundDatagram> {
        match self {
            Self::Protocol(handler) => handler.connect_datagram(sess, resolver).await,
            Self::Group(group) => match connect(group, sess, resolver, true, &PhysicalDatagramConnector).await? {
                Connection::Datagram(datagram) => Ok(datagram),
                _ => unreachable!(),
            },
        }
    }

    pub(crate) async fn execute_protocol<O: ProtocolOperation>(
        &self, sess: &Session, operation: O,
    ) -> io::Result<O::Output> {
        match self {
            Self::Protocol(handler) => operation.execute(handler, sess).await,
            Self::Group(group) => execute(group, sess, false, operation).await,
        }
    }

    pub(crate) async fn connect_datagram_using<C: DatagramConnector>(
        &self, sess: &Session, resolver: ThreadSafeDNSResolver, connector: &C,
    ) -> io::Result<C::Datagram> {
        match self {
            Self::Protocol(handler) => connector.connect(handler, sess, resolver).await,
            Self::Group(group) => match connect(group, sess, resolver, true, connector).await? {
                Connection::Datagram(datagram) => Ok(datagram),
                _ => unreachable!(),
            },
        }
    }
}

enum Connection<D> {
    Stream(AnyStream),
    Datagram(D),
}

enum Policy<'a> {
    Root(&'a ProxyGroup),
    Nested(OutboundNode),
}

impl Policy<'_> {
    fn group(&self) -> &ProxyGroup {
        match self {
            Self::Root(group) => *group,
            Self::Nested(handler) => handler.as_group().expect("selected group"),
        }
    }
}

struct Frame<'a> {
    policy: Policy<'a>,
    excluded: HashSet<String>,
    attempts: u32,
    limit: u32,
    selected: Option<OutboundNode>,
    started: Instant,
}

impl<'a> Frame<'a> {
    async fn new(policy: Policy<'a>, sess: &Session, single_attempt: bool) -> Self {
        let limit = if single_attempt { 1 } else { policy.group().attempts(sess).await.max(1) };
        Self { policy, excluded: HashSet::new(), attempts: 0, limit, selected: None, started: Instant::now() }
    }
}

/// Keep the common single-group frame inline; nested groups allocate on demand.
struct Frames<'a> {
    root: Option<Frame<'a>>,
    nested: Vec<Frame<'a>>,
}

impl<'a> Frames<'a> {
    fn new(root: Frame<'a>) -> Self { Self { root: Some(root), nested: Vec::new() } }
    fn last_mut(&mut self) -> Option<&mut Frame<'a>> {
        if self.nested.is_empty() { self.root.as_mut() } else { self.nested.last_mut() }
    }
    fn len(&self) -> usize { usize::from(self.root.is_some()) + self.nested.len() }
    fn iter(&self) -> impl Iterator<Item = &Frame<'a>> { self.root.iter().chain(self.nested.iter()) }
    fn push(&mut self, frame: Frame<'a>) { self.nested.push(frame); }
    fn pop(&mut self) {
        if self.nested.is_empty() { self.root.take(); } else { self.nested.pop(); }
    }
    fn is_empty(&self) -> bool { self.root.is_none() }
}

fn connect<'a, C: DatagramConnector>(
    root: &'a ProxyGroup,
    sess: &'a Session,
    resolver: ThreadSafeDNSResolver,
    udp: bool,
    connector: &'a C,
) -> impl Future<Output = io::Result<Connection<C::Datagram>>> + Send + 'a {
    execute(root, sess, udp, PhysicalOperation { connector, resolver, udp })
}

async fn execute<O: ProtocolOperation>(
    root: &ProxyGroup, sess: &Session, single_attempt: bool, operation: O,
) -> io::Result<O::Output> {
    // Retain the association once; derived TCP connections share its UDP route.
    let route = dialer_route::retain();
    let mut frames = Frames::new(Frame::new(Policy::Root(root), sess, single_attempt).await);
    loop {
        let frame = frames.last_mut().expect("root frame");
        frame.attempts += 1;
        let group = frame.policy.group();
        let result = {
            let selection = match route.as_ref().and_then(|route| route.selected(group.identity())) {
                Some(node) => Ok(Some(node)),
                None => group.select(sess, &frame.excluded).await,
            };
            match selection {
                Ok(Some(handler)) => {
                    if let Some(route) = &route {
                        route.remember(frame.policy.group().identity(), &handler);
                    }
                    if frame.limit > 1 {
                        frame.excluded.insert(handler.name().to_owned());
                    }
                    frame.started = Instant::now();
                    frame.selected = Some(handler.clone());
                    if let Some(group) = handler.as_group() {
                        if frames.len() >= 64 || frames.iter().any(|f| f.policy.group().name() == group.name()) {
                            Err(io::Error::other(format!("cyclic or too deep proxy group: {}", group.name())))
                        } else {
                            let nested = Frame::new(Policy::Nested(handler), sess, single_attempt).await;
                            frames.push(nested);
                            continue;
                        }
                    } else {
                        let handler = handler.as_protocol().expect("protocol leaf");
                        operation.execute(handler, sess).await
                    }
                }
                Ok(None) => {
                    frame.attempts = frame.limit;
                    Err(io::Error::other(format!(
                        "no proxy available for {}", frame.policy.group().name()
                    )))
                }
                Err(err) => {
                    frame.attempts = frame.limit;
                    Err(err)
                }
            }
        };
        loop {
            let frame = frames.last_mut().expect("root frame");
            if let Some(selected) = frame.selected.as_ref() {
                if !single_attempt {
                    frame.policy.group().record_result(
                        sess, selected.name(), frame.started.elapsed(), result.is_ok(),
                    ).await;
                }
            }
            frame.selected = None;
            if result.is_err() {
                if let Some(route) = &route { route.forget(frame.policy.group().identity()); }
            }
            if result.is_ok() {
                sess.push_chain(frame.policy.group().name());
            } else if frame.attempts < frame.limit {
                let delay = frame.policy.group().retry_delay(frame.attempts);
                drop(result);
                if !delay.is_zero() {
                    // Only failed connections with a delay allocate a timer.
                    Box::pin(tokio::time::sleep(delay)).await;
                }
                break;
            }
            frames.pop();
            if frames.is_empty() { return result; }
            // Propagate the complete child outcome to its parent's policy.
            // Parents retry only after the child's retry budget is exhausted.
        }
    }
}

#[cfg(feature = "allocation-tests")]
impl OutboundNode {
    pub(crate) fn executor_layout(
        group: &ProxyGroup, sess: &Session, resolver: ThreadSafeDNSResolver,
    ) -> [(&'static str, usize); 10] {
        use std::{mem::{size_of, size_of_val}, time::Duration};
        let node = OutboundNode::Group(group.clone());
        [
            ("executor policy", size_of::<Policy<'_>>()),
            ("executor frame", size_of::<Frame<'_>>()),
            ("executor frames", size_of::<Frames<'_>>()),
            ("executor connection result", size_of::<io::Result<Connection<AnyOutboundDatagram>>>()),
            ("root frame initialization", size_of_val(&Frame::new(Policy::Root(group), sess, false))),
            ("nested frame initialization", size_of_val(&Frame::new(Policy::Nested(OutboundNode::Group(group.clone())), sess, false))),
            ("group executor TCP", size_of_val(&connect(group, sess, resolver.clone(), false, &PhysicalDatagramConnector))),
            ("group executor UDP", size_of_val(&connect(group, sess, resolver.clone(), true, &PhysicalDatagramConnector))),
            ("node TCP connect", size_of_val(&node.connect_stream(sess, resolver.clone()))),
            ("retry sleep", size_of_val(&tokio::time::sleep(Duration::ZERO))),
        ]
    }
}
