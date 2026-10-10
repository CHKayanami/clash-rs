#[macro_export]
macro_rules! impl_default_connector {
    ($handler:ident) => {
                impl DialWithConnector for $handler {
            fn dialer_dependency(&self) -> Option<$crate::proxy::OutboundNode> {
                self.connector.as_ref().and_then(|connector| connector.outbound_dependency())
            }

            fn support_dialer(&self) -> Option<&str> {
                self.opts.common_opts.connector.as_deref()
            }
        }
    };
}

/// Shared Arc ownership and weak identity for closed handler sets.
/// `$d` passes a dollar token through to the local dispatch macro.
macro_rules! handler_enum {
    ($name:ident, $weak:ident, $d:tt; $( $(#[$meta:meta])* $variant:ident($handler:ty) ),+ $(,)?) => {
        #[derive(Debug, Clone)]
        pub enum $name { $( $(#[$meta])* $variant(Arc<$handler>), )+ }
        #[derive(Debug, Clone)]
        pub enum $weak { $( $(#[$meta])* $variant(Weak<$handler>), )+ }

        $( $(#[$meta])*
        impl From<Arc<$handler>> for $name {
            fn from(handler: Arc<$handler>) -> Self { Self::$variant(handler) }
        })+

        impl $name {
            pub fn identity(&self) -> usize {
                match self { $( $(#[$meta])* Self::$variant(h) => Arc::as_ptr(h) as usize, )+ }
            }
            pub fn downgrade(&self) -> $weak {
                match self { $( $(#[$meta])* Self::$variant(h) => $weak::$variant(Arc::downgrade(h)), )+ }
            }
        }
        impl $weak {
            pub fn identity(&self) -> usize {
                match self { $( $(#[$meta])* Self::$variant(h) => Weak::as_ptr(h) as usize, )+ }
            }
            pub fn ptr_eq(&self, other: &Self) -> bool {
                match (self, other) {
                    $( $(#[$meta])* (Self::$variant(a), Self::$variant(b)) => Weak::ptr_eq(a, b), )+
                    _ => false,
                }
            }
            pub fn upgrade(&self) -> Option<$name> {
                match self { $( $(#[$meta])* Self::$variant(h) => h.upgrade().map($name::$variant), )+ }
            }
        }
        macro_rules! dispatch {
            ($d value:expr, $d handler:ident, $d body:expr) => {
                match $d value { $( $(#[$meta])* Self::$variant($d handler) => $d body, )+ }
            };
        }
    };
}
pub(super) use handler_enum;
