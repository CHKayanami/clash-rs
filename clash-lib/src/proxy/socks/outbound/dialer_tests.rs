use super::{Handler, HandlerOptions};
use crate::{
    app::{dns::ThreadSafeDNSResolver, net::OutboundInterface},
    proxy::{
        AnyOutboundDatagram, AnyStream, HandlerCommonOptions, OutboundHandler,
        datagram::UdpPacket, utils::{DirectConnector, RemoteConnector, test_utils::noop::NoopResolver},
    },
    session::{Session, SocksAddr},
};
use futures::{SinkExt, StreamExt};
use std::{io, net::SocketAddr, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, UdpSocket}};

#[derive(Debug)]
pub struct RecordingConnector(Arc<AtomicUsize>);
impl RecordingConnector {
    pub async fn connect_stream(&self, resolver: ThreadSafeDNSResolver, address: &str, port: u16, tfo: bool, iface: Option<&Arc<OutboundInterface>>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> io::Result<AnyStream> {
        DirectConnector.connect_stream(resolver, address, port, tfo, iface,
            #[cfg(target_os = "linux")] packet_mark,
        ).await
    }
    pub async fn connect_datagram(&self, resolver: ThreadSafeDNSResolver, src: Option<SocketAddr>, destination: SocksAddr, iface: Option<&Arc<OutboundInterface>>,
        #[cfg(target_os = "linux")] packet_mark: Option<u32>,
    ) -> io::Result<AnyOutboundDatagram> {
        self.0.fetch_add(1, Ordering::Relaxed);
        DirectConnector.connect_datagram(resolver, src, destination, iface,
            #[cfg(target_os = "linux")] packet_mark,
        ).await
    }
}

#[tokio::test]
async fn socks_udp_data_uses_dialer_connector() { socks_udp_association(false).await; }

#[tokio::test]
async fn socks_udp_pins_nested_round_robin_dialer_route() { socks_udp_association(true).await; }

async fn socks_udp_association(pin_route: bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp.local_addr().unwrap();
        let control = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut command = [0; 3];
            stream.read_exact(&mut command).await.unwrap();
            assert_eq!(command, [5, 3, 0]);
            SocksAddr::read_from(&mut stream).await.unwrap();
            let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
            response.extend_from_slice(&udp_address.port().to_be_bytes());
            stream.write_all(&response).await.unwrap();
            let mut remaining = Vec::new();
            stream.read_to_end(&mut remaining).await.unwrap();
        });
        let relay = tokio::spawn(async move {
            let mut data = [0; 1024];
            let (len, source) = udp.recv_from(&mut data).await.unwrap();
            assert_eq!(&data[..3], &[0, 0, 0]);
            udp.send_to(&data[..len], source).await.unwrap();
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let connector = if pin_route {
            use arc_swap::ArcSwap;
            use std::collections::HashMap;
            use crate::{
                app::remote_content_manager::ProxyManager,
                config::internal::proxy::LoadBalanceStrategy,
                proxy::{OutboundNode, loadbalance, selector, mocks::{MockDummyOutboundHandler, MockDummyProxyProvider}, utils::DialerProxyConnector},
            };
            let mut first = MockDummyOutboundHandler::new();
            first.expect_name().return_const("first".to_owned());
            let stream = tokio::net::TcpStream::connect(server).await.unwrap();
            first.expect_connect_stream().times(1).return_once(move |_, _| Ok(stream.into()));
            let datagram = DirectConnector.connect_datagram(Arc::new(NoopResolver), None, udp_address.into(), None,
                #[cfg(target_os = "linux")] None,
            ).await.unwrap();
            first.expect_connect_datagram().times(1).return_once(move |_, _| Ok(datagram));
            let mut second = MockDummyOutboundHandler::new();
            second.expect_name().return_const("second".to_owned());
            second.expect_connect_stream().times(0);
            second.expect_connect_datagram().times(0);
            let snapshot = Arc::new(vec![OutboundNode::protocol(Arc::new(first)), OutboundNode::protocol(Arc::new(second))]);
            let mut provider = MockDummyProxyProvider::new();
            provider.expect_proxies().returning(move || snapshot.clone());
            let round_robin = OutboundNode::group(Arc::new(loadbalance::Handler::new(loadbalance::HandlerOptions {
                name: "rr".to_owned(), udp: true, strategy: LoadBalanceStrategy::RoundRobin, ..Default::default()
            }, vec![Arc::new(provider)], ProxyManager::new(Arc::new(NoopResolver), None))));
            let snapshot = Arc::new(vec![round_robin]);
            let mut provider = MockDummyProxyProvider::new();
            provider.expect_proxies().returning(move || snapshot.clone());
            provider.expect_touch().return_const(());
            let entry = OutboundNode::group(Arc::new(selector::Handler::new(selector::HandlerOptions {
                name: "entry".to_owned(), udp: true, ..Default::default()
            }, vec![Arc::new(provider)], None).await));
            let registry = Arc::new(ArcSwap::from_pointee(HashMap::from([("entry".to_owned(), entry)])));
            let connector = Arc::new(RemoteConnector::DialerProxy(DialerProxyConnector::new("entry".to_owned(), &registry)));
            (connector, Some(registry))
        } else {
            (Arc::new(RemoteConnector::Recording(Arc::new(RecordingConnector(calls.clone())))), None)
        };
        let handler = Handler::new(HandlerOptions {
            name: "socks".to_owned(), server: "127.0.0.1".to_owned(), port: server.port(), udp: true,
            common_opts: HandlerCommonOptions { connector: Some("entry".to_owned()), ..Default::default() },
            ..Default::default()
        }, Some(connector.0.clone()));
        let target: SocksAddr = "127.0.0.1:9000".parse().unwrap();
        let sess = Session { destination: target.clone(), ..Default::default() };
        let mut datagram = handler.connect_datagram(&sess, Arc::new(NoopResolver)).await.unwrap();
        datagram.send(UdpPacket { dst_addr: target.clone(), data: b"ping".as_slice().into(), ..Default::default() }).await.unwrap();
        let response = datagram.next().await.unwrap();
        assert_eq!(response.src_addr, target);
        assert_eq!(response.dst_addr, udp_address.into());
        assert_eq!(response.data.as_ref(), b"ping");
        assert_eq!(calls.load(Ordering::Relaxed), usize::from(!pin_route));
        drop(datagram);
        control.await.unwrap();
        relay.await.unwrap();
        drop(handler);
        drop(connector);
    }).await.unwrap();
}
