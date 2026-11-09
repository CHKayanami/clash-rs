use super::*;

fn allocated(capacity: usize) -> BytesMut {
    let mut packet = BytesMut::with_capacity(capacity);
    packet.extend_from_slice(b"x");
    packet
}

#[tokio::test]
async fn reader_allocations_share_one_budget() {
    let (sender, mut receiver) = channel();
    for capacity in [100, 200, 4096] { sender.send(allocated(capacity)).await.unwrap(); }
    assert_eq!(sender.budget.available_permits(), BYTE_BUDGET - 4396);
    for capacity in [100, 200, 4096] {
        let packet = receiver.recv().await.unwrap();
        assert_eq!(packet.budget.num_permits(), capacity);
        drop(packet);
    }
    assert_eq!(sender.budget.available_permits(), BYTE_BUDGET);
}

#[tokio::test]
async fn budget_is_held_until_writer_releases_packet_storage() {
    let (sender, mut receiver) = channel();
    sender.send(allocated(BYTE_BUDGET)).await.unwrap();
    let packet = receiver.recv().await.unwrap();
    assert_eq!(sender.budget.available_permits(), 0);
    assert!(sender.budget.clone().try_acquire_owned().is_err());
    drop(packet);
    assert_eq!(sender.budget.available_permits(), BYTE_BUDGET);
}

#[tokio::test]
async fn closed_queue_and_cancelled_admission_return_budget() {
    let (sender, receiver) = channel();
    drop(receiver);
    assert!(sender.send(allocated(1)).await.is_err());
    assert_eq!(sender.budget.available_permits(), BYTE_BUDGET);
    let (sender, mut receiver) = channel();
    sender.send(allocated(BYTE_BUDGET)).await.unwrap();
    let held = receiver.recv().await.unwrap();
    assert!(tokio::time::timeout(std::time::Duration::from_millis(10), sender.send(allocated(1))).await.is_err());
    drop(held);
    assert_eq!(sender.budget.available_permits(), BYTE_BUDGET);
    assert!(receiver.try_recv().is_err());
}
