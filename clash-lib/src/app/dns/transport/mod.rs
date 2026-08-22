//! Encrypted and pooled DNS transports (DoT / DoH / DoQ / DoH3 / TCP / UDP).

mod body;
mod dial;
mod doh;
mod doh3;
mod doh_message;
mod doq;
mod dot;
mod idle_pool;
mod lifecycle;
mod owned_task;
mod quic;
mod retry;
mod tcp_pool;
mod udp_pool;

pub use body::{DnsMessageBody, doh_content_length};
pub use dial::{DialContext, dial_candidates};
pub use doh::DohClient;
pub use doh3::Doh3Client;
pub use doq::DoqClient;
pub use dot::DotPool;
pub use idle_pool::{IdlePoolState, close_idle_pool, idle_pool_exchange};
pub use lifecycle::LifecycleSlot;
pub use owned_task::OwnedTask;
pub use quic::{SharedQuicEndpoint, dns_quic_config, quic_connect_endpoint};
pub use retry::exchange_with_retry;
pub use tcp_pool::TcpPool;
pub use udp_pool::UdpPool;
