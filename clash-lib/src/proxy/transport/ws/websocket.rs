use std::{
    cmp::min,
    fmt::{self, Debug},
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

use crate::{
    common::errors::{map_io_error, new_io_error},
    proxy::AnyStream,
};

pub struct WebsocketConn {
    inner: WebSocketStream<AnyStream>,
    read_buffer: Bytes,
}

impl crate::proxy::ProxyStream for WebsocketConn {}

impl Debug for WebsocketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebsocketConn")
            .field("read_buffer", &self.read_buffer)
            .finish()
    }
}

impl WebsocketConn {
    pub fn from_websocket(stream: WebSocketStream<AnyStream>) -> Self {
        Self {
            inner: stream,
            read_buffer: Bytes::new(),
        }
    }
}

impl AsyncRead for WebsocketConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.read_buffer.is_empty() {
            let to_read = min(buf.remaining(), self.read_buffer.len());
            let for_read = self.read_buffer.split_to(to_read);
            buf.put_slice(&for_read);
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(ready!(Pin::new(&mut self.inner).poll_next(cx)).map_or(
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "ws broken pipe")),
            |item| {
                item.map_or(
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "ws broken pipe")),
                    |msg| match msg {
                        Message::Binary(data) => {
                            let to_read = min(buf.remaining(), data.len());
                            buf.put_slice(&data[..to_read]);
                            if to_read < data.len() {
                                self.read_buffer = data.slice(to_read..);
                            }
                            Ok(())
                        }
                        Message::Close(_) => Ok(()),
                        _ => Err(new_io_error("ws invalid message type")),
                    },
                )
            },
        ))
    }
}

impl AsyncWrite for WebsocketConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        // poll_ready flushes any previously queued frame before accepting a
        // new one.  Once it returns Ready the sink is empty and we can safely
        // queue the next frame with start_send.
        //
        // We intentionally do NOT call poll_flush here.  Per the AsyncWrite
        // contract poll_write should only buffer data; the caller is
        // responsible for calling poll_flush when it needs the data on the
        // wire.  Flushing inside poll_write caused a data-duplication bug:
        // if poll_flush returned Poll::Pending, poll_write returned Pending
        // without updating the caller's position counter, so the next
        // poll_write call would re-queue the same frame and send it twice.
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(map_io_error)?;
        let message = Message::Binary(Bytes::copy_from_slice(buf));
        Pin::new(&mut self.inner)
            .start_send(message)
            .map_err(map_io_error)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let Self { inner, .. } = self.get_mut();
        Pin::new(inner).poll_flush(cx).map_err(map_io_error)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let Self { inner, .. } = self.get_mut();
        let mut pin = Pin::new(inner);

        let message = Message::Close(None);
        #[allow(unused_must_use)]
        {
            pin.as_mut().start_send(message);
        }
        pin.poll_close(cx).map_err(map_io_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::SinkExt;
    use tokio::{
        io::{AsyncReadExt, duplex},
        spawn,
    };
    use tokio_tungstenite::tungstenite::protocol::Role;

    #[tokio::test]
    async fn large_frames_survive_small_reads_and_empty_reads() {
        let (client, server) = duplex(256);
        let mut sender =
            WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let stream: AnyStream = AnyStream::new(client);
        let mut receiver = WebsocketConn::from_websocket(
            WebSocketStream::from_raw_socket(stream, Role::Client, None).await,
        );
        let expected: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        let sent = expected.clone();
        let writer = spawn(async move {
            sender.send(Message::Binary(sent.into())).await.unwrap();
            sender
                .send(Message::Binary(Bytes::from_static(b"tail")))
                .await
                .unwrap();
        });
        assert_eq!(receiver.read(&mut []).await.unwrap(), 0);
        let mut received = Vec::new();
        let mut chunk = [0; 137];
        while received.len() < expected.len() + 4 {
            let n = receiver.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            received.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(&received[..expected.len()], expected);
        assert_eq!(&received[expected.len()..], b"tail");
        writer.await.unwrap();
    }
}
