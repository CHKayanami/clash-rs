use std::{future::{Future, poll_fn}, io, pin::Pin, task::{Context, Poll}};
use bytes::Bytes;
use h2::{Reason, RecvStream, SendStream, client::SendRequest};
use http::{HeaderValue, Method, Request, Response, header::CONTENT_LENGTH};
use http_body_util::BodyExt;
use hyper::body::Body;
use tokio::{spawn, task::JoinHandle};

use crate::proxy::transport::h2_common::{release_receive_capacity, send_bytes};
use super::{ResponseFuture, response_body::IncomingBody};
use super::super::body::RequestBody;

/// Cancellation resets only this request, preserving the pooled connection.
struct SendGuard {
    stream: SendStream<Bytes>,
    finished: bool,
}
impl Drop for SendGuard {
    fn drop(&mut self) {
        if !self.finished { self.stream.send_reset(Reason::CANCEL); }
    }
}

pub(super) struct UploadTask(JoinHandle<io::Result<()>>);
impl UploadTask {
    pub(super) fn poll_result(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll(cx).map(|result| result.map_err(io::Error::other).and_then(|result| result))
    }

    pub(super) async fn result(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_result(cx)).await
    }
}
impl Drop for UploadTask {
    fn drop(&mut self) { self.0.abort(); }
}

pub(super) fn send(
    sender: &mut SendRequest<Bytes>, request: Request<RequestBody>,
) -> io::Result<(ResponseFuture, Option<UploadTask>)> {
    let (mut parts, body) = request.into_parts();
    if let Some(length) = body.size_hint().exact()
        && (length != 0 || matches!(parts.method, Method::POST | Method::PUT | Method::PATCH)) {
        parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(length));
    }
    let empty = body.is_end_stream();
    let (response, stream) = sender.send_request(Request::from_parts(parts, ()), empty)
        .map_err(io::Error::other)?;
    let upload = if empty { None } else {
        Some(UploadTask(spawn(send_body(body, SendGuard { stream, finished: false }))))
    };
    let response = Box::pin(async move {
        let response = response.await.map_err(io::Error::other)?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(parts, IncomingBody::Http2(body)))
    });
    Ok((response, upload))
}

async fn send_body(body: RequestBody, mut guard: SendGuard) -> io::Result<()> {
    match body {
        RequestBody::Full(mut body) => {
            while let Some(frame) = body.frame().await {
                let frame = match frame { Ok(frame) => frame, Err(never) => match never {} };
                if let Ok(data) = frame.into_data() { send_bytes(&mut guard.stream, data, false).await?; }
            }
        }
        RequestBody::Stream(mut receiver) => {
            while let Some(chunk) = receiver.recv().await {
                send_bytes(&mut guard.stream, chunk.data, false).await?;
                let _ = chunk.consumed.send(());
            }
        }
    }
    guard.stream.send_data(Bytes::new(), true).map_err(io::Error::other)?;
    guard.finished = true;
    Ok(())
}

pub(super) fn poll_data(
    body: &mut RecvStream, cx: &mut Context<'_>,
) -> Poll<Option<io::Result<Bytes>>> {
    match Pin::new(&mut *body).poll_data(cx) {
        Poll::Ready(Some(Ok(data))) => {
            if let Err(error) = release_receive_capacity(body, data.len()) {
                return Poll::Ready(Some(Err(error)));
            }
            Poll::Ready(Some(Ok(data)))
        }
        Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(io::Error::other(error)))),
        Poll::Ready(None) => Poll::Ready(None),
        Poll::Pending => Poll::Pending,
    }
}
