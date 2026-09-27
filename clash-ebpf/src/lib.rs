#[cfg(not(target_os = "linux"))]
compile_error!("clash-ebpf is supported only on Linux");

pub mod bpf;
pub mod config;
pub mod listener;
pub mod manager;

pub mod netlink;
pub mod netns;
pub mod session;

pub use clash_ebpf_common::DAE_BYPASS_MARK;
pub use config::{
    EbpfConfig, EbpfHostConfig, EbpfLanConfig, EbpfTargetConfig, parse_mac_addr,
};
pub use listener::EbpfListener;
pub use manager::{EbpfError, EbpfManager};
pub use session::{EbpfSession, TransportProtocol, get_original_dst};
