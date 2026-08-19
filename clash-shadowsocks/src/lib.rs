//! Shadowsocks Core Library for clash-rs

#![crate_type = "lib"]

pub use self::{
    config::{ServerAddr, ServerConfig},
    relay::{
        tcprelay::proxy_stream::ProxyClientStream,
        udprelay::proxy_socket::ProxySocket,
    },
};

pub use shadowsocks_crypto as crypto;

pub mod config;
pub mod context;
pub mod net;
pub mod relay;
mod security;
