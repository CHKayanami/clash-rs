use super::*;
use futures::future::poll_fn;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn batches_preserve_headers_payloads_empty_datagrams_and_ipv6() {
    timeout(Duration::from_secs(3), async {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let sender = UdpSocket::bind(bind).await.unwrap();
            let receiver = UdpSocket::bind(bind).await.unwrap();
            let destination = receiver.local_addr().unwrap();
            let packets = [
                DatagramSlice { header: b"head:", payload: b"one", destination },
                DatagramSlice { header: b"", payload: b"", destination },
                DatagramSlice { header: b"head:", payload: b"two", destination },
            ];
            let mut sent = 0;
            while sent < packets.len() {
                let result = poll_fn(|cx| poll_send_batch(&sender, destination.is_ipv6(), cx, &packets[sent..])).await;
                assert!(result.error.is_none());
                assert!(result.sent > 0);
                sent += result.sent;
            }
            let mut buffer = [0; 32];
            for expected in [b"head:one".as_slice(), b"".as_slice(), b"head:two".as_slice()] {
                let (len, source) = receiver.recv_from(&mut buffer).await.unwrap();
                assert_eq!(source, sender.local_addr().unwrap());
                assert_eq!(&buffer[..len], expected);
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn send_error_keeps_successful_prefix_and_retryable_suffix() {
    timeout(Duration::from_secs(3), async {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let oversized = vec![0; 70_000];
        let packets = [
            DatagramSlice { header: b"", payload: b"first", destination },
            DatagramSlice { header: b"", payload: &oversized, destination },
            DatagramSlice { header: b"", payload: b"last", destination },
        ];
        let result = poll_fn(|cx| poll_send_batch(&sender, false, cx, &packets)).await;
        assert_eq!(result.sent, 1);
        assert!(result.error.is_none());
        let result = poll_fn(|cx| poll_send_batch(&sender, false, cx, &packets[1..])).await;
        assert_eq!(result.sent, 0);
        assert!(result.error.is_some());
        let result = poll_fn(|cx| poll_send_batch(&sender, false, cx, &packets[2..])).await;
        assert_eq!(result.sent, 1);
        assert!(result.error.is_none());
        let mut buffer = [0; 32];
        for expected in [b"first".as_slice(), b"last".as_slice()] {
            let len = receiver.recv(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..len], expected);
        }
        assert!(receiver.try_recv(&mut buffer).is_err());
    }).await.unwrap();
}
