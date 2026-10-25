//! Integration behavior of the platform-independent Reader wrapper. Native
//! syscall/framing tests live in darwin_tests.rs.
use std::{os::{fd::IntoRawFd, unix::net::UnixDatagram}, time::Duration};
use tokio::time::timeout;

use super::*;

#[test]
fn native_io_override_is_explicit_and_rejects_invalid_values() {
    for value in ["0", "false"] { assert!(!parse_native_io(value).unwrap()); }
    for value in ["1", "true"] { assert!(parse_native_io(value).unwrap()); }
    assert_eq!(parse_native_io("auto").unwrap_err().kind(), io::ErrorKind::InvalidInput);
}

fn pair(frame_size: usize, native_io: bool) -> (UnixDatagram, AsyncDevice, Reader) {
    let (sender, receiver) = UnixDatagram::pair().unwrap();
    // SAFETY: ownership of one open FD transfers exactly once. Only datagram
    // I/O is exercised, with utun framing and no TUN control operations.
    let device = unsafe { AsyncDevice::from_fd(receiver.into_raw_fd()) }.unwrap();
    let reader = Reader::new(&device, frame_size, native_io).unwrap();
    (sender, device, reader)
}

fn send(sender: &UnixDatagram, payload: &[u8]) {
    let mut frame = (libc::AF_INET as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    sender.send(&frame).unwrap();
}

#[tokio::test]
async fn ordinary_mode_disables_both_native_sides_and_preserves_framing() {
    let (peer, device, mut reader) = pair(64, false);
    let mut writer = Writer::new(&reader, true).unwrap();
    assert!(reader.darwin.is_none());
    assert!(writer.darwin.is_none());
    send(&peer, &[0x45; 80]);
    let payload = [0x45; 40];
    send(&peer, &payload);
    let mut packets = Vec::new();
    assert_eq!(timeout(Duration::from_secs(1), reader.recv(&device, &mut packets))
        .await.unwrap().unwrap(), 1);
    assert_eq!(&packets[0][..], &payload);
    writer.send(&device, &[Bytes::copy_from_slice(&payload)]).await.unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut frame = [0; 128];
    let size = peer.recv(&mut frame).unwrap();
    assert_eq!(size, payload.len() + 4);
    assert_eq!(&frame[..4], &(libc::AF_INET as u32).to_be_bytes());
    assert_eq!(&frame[4..size], &payload);
}

#[tokio::test]
async fn invalid_frames_do_not_discard_the_valid_suffix_or_poison_the_next_receive() {
    let (sender, device, mut reader) = pair(8, true);
    send(&sender, b"before");
    send(&sender, b"payload-too-large");
    sender.send(&(libc::AF_INET as u32).to_be_bytes()).unwrap();
    sender.send(b"xx").unwrap();
    let mut invalid_family = (libc::AF_UNIX as u32).to_be_bytes().to_vec();
    invalid_family.extend_from_slice(b"invalid");
    sender.send(&invalid_family).unwrap();
    send(&sender, b"after");
    let mut packets = Vec::new();
    assert_eq!(timeout(Duration::from_secs(1), reader.recv(&device, &mut packets))
        .await.unwrap().unwrap(), 2);
    assert_eq!(&packets[0][..], b"before");
    assert_eq!(&packets[1][..], b"after");
    packets.clear();
    send(&sender, b"next");
    assert_eq!(timeout(Duration::from_secs(1), reader.recv(&device, &mut packets))
        .await.unwrap().unwrap(), 1);
    assert_eq!(&packets[0][..], b"next");
}

#[tokio::test]
async fn invalid_only_batch_is_not_eof_and_does_not_prevent_cancellation() {
    let (sender, device, mut reader) = pair(8, true);
    send(&sender, b"payload-too-large");
    sender.send(b"bad").unwrap();
    let mut packets = Vec::new();
    assert!(timeout(Duration::from_millis(20), reader.recv(&device, &mut packets))
        .await.is_err());
    assert!(packets.is_empty());
    send(&sender, b"next");
    assert_eq!(timeout(Duration::from_secs(1), reader.recv(&device, &mut packets))
        .await.unwrap().unwrap(), 1);
    assert_eq!(&packets[0][..], b"next");
}

#[tokio::test]
async fn cancelled_receive_does_not_consume_the_next_packet() {
    let (sender, device, mut reader) = pair(1500, true);
    let mut packets = Vec::new();
    assert!(timeout(Duration::from_millis(20), reader.recv(&device, &mut packets))
        .await.is_err());
    send(&sender, b"after-cancel");
    assert_eq!(timeout(Duration::from_secs(1), reader.recv(&device, &mut packets))
        .await.unwrap().unwrap(), 1);
    assert_eq!(&packets[0][..], b"after-cancel");
}

#[tokio::test]
async fn invalid_send_packets_preserve_valid_neighbors_in_both_modes() {
    for native in [false, true] {
        let (peer, device, reader) = pair(1500, native);
        let mut writer = Writer::new(&reader, true).unwrap();
        let before = Bytes::from_static(b"\x45before");
        let after = Bytes::from_static(b"\x60after");
        let packets = [Bytes::new(), before.clone(), Bytes::from_static(b"\x30bad"),
            after.clone(), Bytes::new()];
        timeout(Duration::from_secs(1), writer.send(&device, &packets)).await.unwrap().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut frame = [0; 64];
        for (family, expected) in [(libc::AF_INET, before), (libc::AF_INET6, after)] {
            let count = peer.recv(&mut frame).unwrap();
            assert_eq!(&frame[..4], &(family as u32).to_be_bytes());
            assert_eq!(&frame[4..count], expected.as_ref());
        }
        writer.send(&device, &[Bytes::new(), Bytes::from_static(b"\x10")]).await.unwrap();
        peer.set_nonblocking(true).unwrap();
        assert_eq!(peer.recv(&mut frame).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
}
