use bytes::Bytes;
use clash_netstack::Packet;

/// Ordinary buffers have complete checksums; protocol packets may carry native
/// segmentation metadata that must survive queueing until the device write.
pub(in crate::proxy::tun) trait Frame: AsRef<[u8]> {
    #[cfg(any(target_os = "linux", test))]
    fn parts(&self) -> Option<(&[u8], &[u8])> { None }
    #[cfg(target_os = "linux")]
    fn compact(&mut self) {}
    #[cfg(any(target_os = "linux", test))]
    fn udp_partial(&self) -> bool { false }
    #[cfg(any(target_os = "linux", test))]
    fn tcp_segmentation(&self) -> Option<u16> { None }
    #[cfg(any(target_os = "linux", test))]
    fn udp_segmentation(&self) -> Option<u16> { None }
}
impl Frame for Bytes {}
impl Frame for Packet {
    #[cfg(any(target_os = "linux", test))]
    fn parts(&self) -> Option<(&[u8], &[u8])> { self.parts() }
    #[cfg(target_os = "linux")]
    fn compact(&mut self) { self.compact_payload(); }
    #[cfg(any(target_os = "linux", test))]
    fn udp_partial(&self) -> bool { self.udp_checksum_partial() }
    #[cfg(any(target_os = "linux", test))]
    fn tcp_segmentation(&self) -> Option<u16> { self.tcp_segmentation() }
    #[cfg(any(target_os = "linux", test))]
    fn udp_segmentation(&self) -> Option<u16> { self.udp_segmentation() }
}
