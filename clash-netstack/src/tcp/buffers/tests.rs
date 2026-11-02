use super::*;

#[test]
fn receive_consumption_without_pressure_never_grows() {
    let (mut buffers, mut socket) = Buffers::new();
    let now = Instant::now();
    for step in 1..=20 {
        assert!(!buffers.grow_at(&mut socket, INITIAL_CAPACITY * 2, Duration::from_millis(10),
            0, now + Duration::from_millis(10) * step as u32,
            false, true));
    }
    assert_eq!(socket.recv_capacity(), INITIAL_CAPACITY);
    assert_eq!(socket.send_capacity(), INITIAL_CAPACITY);
}

#[test]
fn growth_requests_never_exceed_configured_storage_limits() {
    let (_, mut socket) = Buffers::new();
    for _ in 0..20 {
        Buffers::grow_one(&mut socket, true, usize::MAX);
        Buffers::grow_one(&mut socket, false, usize::MAX);
    }
    assert_eq!(socket.recv_capacity(), MAX_CAPACITY);
    assert_eq!(socket.send_capacity(), MAX_CAPACITY);
    assert!(!Buffers::grow_one(&mut socket, true, usize::MAX));
    assert!(!Buffers::grow_one(&mut socket, false, usize::MAX));
}

#[test]
fn receive_reclaim_is_not_skipped_when_tx_has_no_reclaim_request() {
    let (mut buffers, mut socket) = Buffers::new();
    while socket.recv_capacity() < 256 * 1024 {
        Buffers::grow_one(&mut socket, true, 256 * 1024);
    }
    let now = Instant::now() + Duration::from_secs(31);
    assert!(buffers.reclaim(&mut socket, now));
    assert_eq!(socket.recv_capacity(), INITIAL_CAPACITY);
    assert_eq!(socket.send_capacity(), INITIAL_CAPACITY);
}
