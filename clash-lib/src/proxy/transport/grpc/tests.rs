use super::*;
use http::{HeaderValue, Response};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    time::timeout,
};

#[tokio::test]
async fn shutdown_before_response_preserves_read_side() {
    let (client_io, server_io) = duplex(4096);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) =
            connection.accept().await.unwrap().unwrap();
        let responder = tokio::spawn(async move {
            let mut recv = request.into_body();
            let mut received = Vec::new();
            while let Some(data) = recv.data().await {
                let data = data.expect("shutdown must not reset the request");
                received.extend_from_slice(&data);
                recv.flow_control().release_capacity(data.len()).unwrap();
            }
            assert_eq!(received, b"\x00\x00\x00\x00\x06\x0a\x04ping");

            // Respond only after the client's write side reaches EOF.
            let mut send =
                respond.send_response(grpc_response(), false).unwrap();
            send.send_data(
                Bytes::from_static(b"\x00\x00\x00\x00\x06\x0a\x04pong"),
                false,
            )
            .unwrap();
            send.send_trailers(ok_trailers()).unwrap();
        });
        while connection.accept().await.is_some() {}
        responder.await.unwrap();
    });

    timeout(Duration::from_secs(2), async {
        let client =
            Client::new("example.com".into(), "/service".parse().unwrap());
        let mut stream = client
            .proxy_stream(AnyStream::new(client_io))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
        stream.shutdown().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"pong");
        assert_eq!(
            stream.write_all(b"closed").await.unwrap_err().kind(),
            ErrorKind::BrokenPipe,
        );
        drop(stream);
        server.await.unwrap();
    })
    .await
    .expect("half-close must preserve the response without stalling");
}

#[tokio::test]
async fn reads_frame_split_across_h2_data_chunks() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (_, mut respond) = connection.accept().await.unwrap().unwrap();
        let response = grpc_response();
        let mut send = respond.send_response(response, false).unwrap();

        // The protobuf length is a two-byte varint. Split both the
        // varint and payload at HTTP/2 DATA frame boundaries.
        let mut frame = vec![0, 0, 0, 0, 133, 0x0a, 0x82, 0x01];
        frame.extend_from_slice(&[b'x'; 130]);
        send.send_data(Bytes::copy_from_slice(&frame[..7]), false)
            .unwrap();
        send.send_data(Bytes::copy_from_slice(&frame[7..8]), false)
            .unwrap();
        send.send_data(Bytes::copy_from_slice(&frame[8..20]), false)
            .unwrap();
        send.send_data(Bytes::copy_from_slice(&frame[20..]), false)
            .unwrap();
        send.send_trailers(ok_trailers()).unwrap();
        while connection.accept().await.is_some() {}
    });

    let client = Client::new("example.com".into(), "/service".parse().unwrap());
    let mut stream = client
        .proxy_stream(AnyStream::new(client_io))
        .await
        .unwrap();
    let mut received = [0; 130];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_exact(&mut received),
    )
    .await
    .expect("fragmented frame must not stall")
    .unwrap();
    assert_eq!(received, [b'x'; 130]);
    drop(stream);
    server.abort();
}

mod response;
mod flow;

fn grpc_response() -> Response<()> {
    Response::builder()
        .header("content-type", "application/grpc")
        .body(())
        .unwrap()
}

fn ok_trailers() -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    trailers
}

fn client() -> Client {
    Client::new("example.com".into(), "/service".parse().unwrap())
}

struct ServerTask(tokio::task::JoinHandle<()>);

impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
