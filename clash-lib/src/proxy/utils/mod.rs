#[cfg(test)]
pub mod test_utils;

mod platform;
pub(crate) use platform::must_bind_socket_on_interface;

pub mod provider_helper;
mod proxy_connector;
mod dialer_proxy;
pub(crate) mod dialer_route;
pub use dialer_proxy::DialerProxyConnector;
mod shared_handler;
mod socket_helpers;

pub use proxy_connector::*;
pub use shared_handler::{OutboundNodeRegistry, ProviderRegistry, ProviderSnapshot};
pub use socket_helpers::*;

#[cfg(test)]
pub(crate) mod dialer_proxy_tests;
