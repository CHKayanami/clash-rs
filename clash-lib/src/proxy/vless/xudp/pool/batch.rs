use super::*;
use crate::proxy::datagram::batch::{DatagramBatch, PacketBatch, BatchResult};

impl DatagramBatch for XudpChildDatagram {
    fn poll_send_batch(&mut self, cx: &mut Context<'_>, batch: &mut PacketBatch) -> Poll<BatchResult> {
        let mut sent = 0;
        for packet in batch.packets() {
            let result = Pin::new(&mut *self).poll_ready(cx);
            match result {
                Poll::Pending => break,
                Poll::Ready(Err(error)) => return Poll::Ready(BatchResult { sent, fatal: true, error: Some(error) }),
                Poll::Ready(Ok(())) => {}
            }
            match self.writer_tx.poll_reserve(cx) {
                Poll::Pending => break,
                Poll::Ready(Err(_)) => return Poll::Ready(BatchResult { sent, fatal: true,
                    error: Some(io::Error::new(io::ErrorKind::BrokenPipe, "XUDP carrier writer closed")) }),
                Poll::Ready(Ok(())) => {}
            }
            let frame = match XudpFrame::encode_data_frame(self.session_id, self.first_packet,
                Some(&packet.dst_addr), &packet.data) {
                Ok(frame) => frame,
                Err(error) => {
                    self.writer_tx.abort_send();
                    return Poll::Ready(BatchResult { sent, fatal: false, error: Some(error) });
                }
            };
            if self.writer_tx.send_item(frame).is_err() {
                return Poll::Ready(BatchResult { sent, fatal: true,
                    error: Some(io::Error::new(io::ErrorKind::BrokenPipe, "XUDP carrier writer closed")) });
            }
            self.first_packet = false;
            sent += 1;
        }
        if sent == 0 { Poll::Pending } else { Poll::Ready(BatchResult::sent(sent)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::time::{timeout, Duration};
    use futures::future::poll_fn;

    #[tokio::test]
    async fn batch_preserves_new_keep_and_end_order_with_partial_writes() {
        timeout(Duration::from_secs(3), async {
            let (client, mut server) = duplex(3);
            let carrier = XudpCarrier::new(AnyStream::new(client), 1, 8);
            let target: SocksAddr = "1.1.1.1:53".parse().unwrap();
            let mut child = carrier.open_child(target.clone()).unwrap();
            let mut batch = PacketBatch::default();
            for payload in [b"one".as_slice(), b"", b"three"] {
                batch.push(UdpPacket { data: Bytes::copy_from_slice(payload), dst_addr: target.clone(), ..Default::default() }).unwrap();
            }
            let result = poll_fn(|cx| child.poll_send_batch(cx, &mut batch)).await;
            assert_eq!(result.sent, 3);
            assert!(result.error.is_none());
            drop(child);
            let mut buffer = BytesMut::new();
            for (index, payload) in [Some(b"one".as_slice()), Some(b""), Some(b"three"), None].iter().enumerate() {
                let frame = loop {
                    if let Some(frame) = decode_xudp_frame_from_buf(&mut buffer).unwrap() { break frame; }
                    assert_ne!(server.read_buf(&mut buffer).await.unwrap(), 0);
                };
                assert_eq!(frame.status, match index { 0 => SessionStatus::New, 3 => SessionStatus::End, _ => SessionStatus::Keep });
                assert_eq!(frame.payload.as_deref(), *payload);
            }
        }).await.unwrap();
    }
}
