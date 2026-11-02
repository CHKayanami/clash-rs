use super::*;

fn allocated(capacity: usize) -> BytesMut {
    let mut packet = BytesMut::with_capacity(capacity);
    packet.extend_from_slice(b"x");
    packet
}

#[tokio::test]
async fn compact_replies_and_reader_allocations_share_the_same_budget() {
    let (compact, mut receiver) = channel();
    let mut replies = vec![Bytes::from(vec![0; 100]), Bytes::from(vec![0; 200])];
    compact.send_batch(&mut replies).await.unwrap();
    compact.send(allocated(4096)).await.unwrap();
    assert_eq!(compact.budget.available_permits(), BYTE_BUDGET - 4396);
    let first = receiver.recv().await.unwrap();
    let second = receiver.recv().await.unwrap();
    let third = receiver.recv().await.unwrap();
    assert_eq!(first.budget.num_permits(), 100);
    assert_eq!(second.budget.num_permits(), 200);
    assert_eq!(third.budget.num_permits(), 4096);
    drop((first, second, third));
    assert_eq!(compact.budget.available_permits(), BYTE_BUDGET);
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
    let mut packets = vec![Bytes::from_static(b"one"), Bytes::from_static(b"two")];
    assert!(sender.send_batch(&mut packets).await.is_err());
    assert_eq!(sender.budget.available_permits(), BYTE_BUDGET);
    assert_eq!(packets.len(), 2);
    let (sender, mut receiver) = channel();
    sender.send(allocated(BYTE_BUDGET)).await.unwrap();
    let held = receiver.recv().await.unwrap();
    assert!(tokio::time::timeout(std::time::Duration::from_millis(10),
        sender.send(allocated(1))).await.is_err());
    drop(held);
    assert_eq!(sender.budget.available_permits(), BYTE_BUDGET);
    assert!(receiver.try_recv().is_err());
}
