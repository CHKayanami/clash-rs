use super::*;
use tokio::io::ReadBuf;
use futures::future::poll_fn;

async fn response_stream(
    response: Response<()>,
    chunks: Vec<Bytes>,
    trailers: Option<HeaderMap>,
    finish: bool,
) -> (AnyStream, ServerTask) {
    let (client_io, server_io) = duplex(4096);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.headers()["te"], "trailers");
        let mut send = respond.send_response(
            response, finish && chunks.is_empty() && trailers.is_none(),
        ).unwrap();
        let count = chunks.len();
        for (index, chunk) in chunks.into_iter().enumerate() {
            send.send_data(chunk, finish && trailers.is_none() && index + 1 == count)
                .unwrap();
        }
        if let Some(trailers) = trailers {
            send.send_trailers(trailers).unwrap();
        }
        while connection.accept().await.is_some() {}
        drop((request, send));
    });
    let stream = client().proxy_stream(AnyStream::new(client_io)).await.unwrap();
    (stream, ServerTask(server))
}

#[tokio::test]
async fn http_error_returns_without_waiting_for_body() {
    let response = Response::builder().status(403).body(()).unwrap();
    let (mut stream, _server) = response_stream(response, vec![], None, false).await;
    let error = timeout(Duration::from_secs(2), stream.read(&mut [0]))
        .await.unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
    assert!(error.to_string().contains("403"));
    // Repeated reads preserve the actual failure and never re-poll a completed future.
    assert_eq!(stream.read(&mut [0]).await.unwrap_err().to_string(), error.to_string());
}

#[tokio::test]
async fn trailers_only_error_preserves_status_and_message() {
    let mut response = grpc_response();
    response.headers_mut().insert("grpc-status", HeaderValue::from_static("7"));
    response.headers_mut().insert("grpc-message", HeaderValue::from_static("access%20denied"));
    let (mut stream, _server) = response_stream(response, vec![], None, true).await;
    let error = stream.read(&mut [0]).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("access denied"));
}

#[tokio::test]
async fn trailers_only_success_is_eof() {
    let mut response = grpc_response();
    response.headers_mut().insert("grpc-status", HeaderValue::from_static("0"));
    let (mut stream, _server) = response_stream(response, vec![], None, true).await;
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn trailer_error_is_reported_after_payload() {
    let mut trailers = ok_trailers();
    trailers.insert("grpc-status", HeaderValue::from_static("13"));
    let (mut stream, _server) = response_stream(
        grpc_response(), vec![encode_frame(b"payload")], Some(trailers), true,
    ).await;
    let mut received = Vec::new();
    let error = stream.read_to_end(&mut received).await.unwrap_err();
    assert_eq!(received, b"payload");
    assert!(error.to_string().contains("gRPC status 13"));
}

#[tokio::test]
async fn missing_or_invalid_status_is_rejected() {
    for status in [None, Some("bogus"), Some("17")] {
        let mut trailers = HeaderMap::new();
        if let Some(status) = status {
            trailers.insert("grpc-status", HeaderValue::from_static(status));
        }
        let (mut stream, _server) = response_stream(
            grpc_response(), vec![], Some(trailers), true,
        ).await;
        assert_eq!(stream.read(&mut [0]).await.unwrap_err().kind(), ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn invalid_content_type_is_rejected() {
    let response = Response::builder().header("content-type", "text/html").body(()).unwrap();
    let (mut stream, _server) = response_stream(response, vec![], None, true).await;
    assert_eq!(stream.read(&mut [0]).await.unwrap_err().kind(), ErrorKind::InvalidData);
}

#[tokio::test]
async fn empty_messages_and_fragmented_headers_preserve_payload() {
    let mut wire = Vec::new();
    wire.extend_from_slice(&[0; 5]); // proto3 may omit the empty data field.
    wire.extend_from_slice(&encode_frame(b""));
    wire.extend_from_slice(&encode_frame(&[b'x'; 130]));
    wire.extend_from_slice(&[0; 5]);
    wire.extend_from_slice(&encode_frame(b"tail"));
    let chunks = wire.into_iter().map(|byte| Bytes::from(vec![byte])).collect();
    let (mut stream, _server) = response_stream(
        grpc_response(), chunks, Some(ok_trailers()), true,
    ).await;
    let mut received = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut received)).await.unwrap().unwrap();
    assert_eq!(&received[..130], &[b'x'; 130]);
    assert_eq!(&received[130..], b"tail");
}

#[tokio::test]
async fn malformed_and_truncated_frames_are_rejected() {
    let cases: &[(&[u8], ErrorKind)] = &[
        (&[1, 0, 0, 0, 0], ErrorKind::InvalidData),
        (&[0, 0, 0, 0, 1, 0x0a], ErrorKind::InvalidData),
        (&[0, 0, 0, 0, 2, 0x0a, 0x80], ErrorKind::InvalidData),
        (&[0, 0, 0, 0, 3, 0x0a, 0], ErrorKind::InvalidData),
        (&[0, 0], ErrorKind::UnexpectedEof),
        (&[0, 0, 0, 0, 3, 0x0a, 1], ErrorKind::UnexpectedEof),
    ];
    for &(frame, kind) in cases {
        let (mut stream, _server) = response_stream(
            grpc_response(), vec![Bytes::copy_from_slice(frame)], Some(ok_trailers()), true,
        ).await;
        assert_eq!(stream.read(&mut [0]).await.unwrap_err().kind(), kind);
    }
}

#[tokio::test]
async fn prefilled_read_buffer_still_receives_data() {
    let (mut stream, _server) = response_stream(
        grpc_response(), vec![encode_frame(b"x")], Some(ok_trailers()), true,
    ).await;
    let mut storage = [0; 2];
    let mut buf = ReadBuf::new(&mut storage);
    buf.put_slice(b"p");
    poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut buf)).await.unwrap();
    assert_eq!(buf.filled(), b"px");
}
