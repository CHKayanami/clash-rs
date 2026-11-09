pub(crate) mod socket;

mod segments;
pub use segments::{split_udp_packet, udp_payload_segments, UdpPayloadSegments};
