use super::*;

#[tokio::test]
async fn zero_limit_does_not_consume_an_empty_datagram() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(b"", receiver.local_addr().unwrap())
        .await
        .unwrap();
    assert_eq!(
        recv_batch(&receiver, 0, |_, _| panic!("unexpected packet")).unwrap(),
        0
    );
    loop {
        receiver.readable().await.unwrap();
        match recv_batch(&receiver, MAX_RECV_BATCH + 1, |data, address| {
            assert!(data.is_empty());
            assert_eq!(address, sender.local_addr().unwrap());
        }) {
            Ok(count) => {
                assert_eq!(count, 1);
                break;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => panic!("receive failed: {err}"),
        }
    }
}

#[tokio::test]
async fn receive_batch_preserves_boundaries_senders_and_empty_packets() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = receiver.local_addr().unwrap();
    let first_addr = first.local_addr().unwrap();
    let second_addr = second.local_addr().unwrap();
    for (sender, data) in [
        (&first, &b"one"[..]),
        (&second, &b"three"[..]),
        (&first, &b""[..]),
    ] {
        sender.send_to(data, destination).await.unwrap();
    }
    let mut packets = Vec::new();
    let mut shared_pairs = 0;
    while packets.len() < 3 {
        receiver.readable().await.unwrap();
        let mut previous_end = None;
        match recv_batch(&receiver, 2, |data, addr| {
            if !data.is_empty() {
                if let Some(end) = previous_end {
                    assert_eq!(data.as_ptr(), end);
                    shared_pairs += 1;
                }
                previous_end = Some(data.as_ptr().wrapping_add(data.len()));
            }
            packets.push((data, addr))
        }) {
            Ok(count) => assert!(count <= 2),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => panic!("receive failed: {err}"),
        }
    }
    assert!(
        shared_pairs > 0,
        "nonempty payloads should share batch storage"
    );
    assert_eq!(
        packets,
        vec![
            (Bytes::from_static(b"one"), first_addr),
            (Bytes::from_static(b"three"), second_addr),
            (Bytes::new(), first_addr),
        ]
    );
    // Reusing scratch for another batch must not overwrite queued packets.
    second.send_to(b"replacement", destination).await.unwrap();
    loop {
        receiver.readable().await.unwrap();
        match recv_batch(&receiver, 1, |_, _| {}) {
            Ok(1) => break,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => (),
            other => panic!("unexpected receive result: {other:?}"),
        }
    }
    assert_eq!(packets[0].0.as_ref(), b"one");
    assert_eq!(packets[1].0.as_ref(), b"three");
    assert!(packets[2].0.is_empty());
}
