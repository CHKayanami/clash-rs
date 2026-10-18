//! Reuse frame storage across batches; references to it live only during a poll.
use std::{io::{self, IoSlice}, pin::Pin, task::{Context, Poll}};
use bytes::{Bytes, BytesMut};
use futures::ready;
use tokio::io::AsyncWrite;
use super::batch::{BatchResult, PacketBatch, MAX_BATCH_PACKETS};
use super::UdpPacket;

#[derive(Default)]
pub(crate) struct FramedBatch {
    headers: BytesMut,
    header_ends: [usize; MAX_BATCH_PACKETS + 1],
    payloads: Vec<Bytes>,
    coalesced: BytesMut,
    coalesced_ready: bool,
    index: usize,
    offset: usize,
    count: usize,
    error: Option<io::Error>,
    terminated: bool,
}

impl FramedBatch {
    pub fn is_active(&self) -> bool { self.count != 0 || self.error.is_some() || self.terminated }

    pub fn prepare(&mut self, batch: &PacketBatch,
        mut encode_header: impl FnMut(&UdpPacket, &mut BytesMut) -> io::Result<()>) {
        debug_assert!(!self.is_active());
        self.headers.clear();
        self.payloads.clear();
        self.header_ends[0] = 0;
        for packet in batch.packets() {
            let start = self.headers.len();
            match encode_header(packet, &mut self.headers) {
                Ok(()) => {
                    self.payloads.push(packet.data.clone());
                    self.count += 1;
                    self.header_ends[self.count] = self.headers.len();
                }
                Err(error) => { self.headers.truncate(start); self.error = Some(error); break; }
            }
        }
    }

    fn slice_count(&self) -> usize {
        if self.coalesced_ready { 1 } else { self.count * 2 }
    }

    fn slice(&self, index: usize) -> &[u8] {
        if self.coalesced_ready { return &self.coalesced; }
        let packet = index / 2;
        if index % 2 == 0 { &self.headers[self.header_ends[packet]..self.header_ends[packet + 1]] }
        else { &self.payloads[packet] }
    }

    pub fn poll_write<W: AsyncWrite + Unpin>(&mut self, writer: &mut W,
        cx: &mut Context<'_>) -> Poll<BatchResult> {
        if self.terminated {
            return Poll::Ready(BatchResult::terminated(io::Error::new(io::ErrorKind::BrokenPipe, "datagram stream has failed")));
        }
        if !writer.is_write_vectored() && !self.coalesced_ready && self.count != 0 {
            self.coalesced.clear();
            let size = self.headers.len() + self.payloads.iter().map(Bytes::len).sum::<usize>();
            self.coalesced.reserve(size);
            for i in 0..self.count {
                self.coalesced.extend_from_slice(&self.headers[self.header_ends[i]..self.header_ends[i + 1]]);
                self.coalesced.extend_from_slice(&self.payloads[i]);
            }
            self.coalesced_ready = true;
        }
        while self.index < self.slice_count() {
            if self.offset == self.slice(self.index).len() {
                self.index += 1;
                self.offset = 0;
                continue;
            }
            let n = if writer.is_write_vectored() {
                let mut slices = [IoSlice::new(&[]); MAX_BATCH_PACKETS * 2];
                let count = (self.slice_count() - self.index).min(slices.len());
                for (i, slice) in slices[..count].iter_mut().enumerate() {
                    let start = if i == 0 { self.offset } else { 0 };
                    *slice = IoSlice::new(&self.slice(self.index + i)[start..]);
                }
                ready!(Pin::new(&mut *writer).poll_write_vectored(cx, &slices[..count]))
            } else {
                ready!(Pin::new(&mut *writer).poll_write(cx, &self.slice(self.index)[self.offset..]))
            };
            match n {
                Ok(0) => return self.fail(io::Error::new(io::ErrorKind::WriteZero, "failed to write datagram batch")),
                Ok(mut n) => {
                    while n != 0 {
                        let consumed = n.min(self.slice(self.index).len() - self.offset);
                        n -= consumed;
                        self.offset += consumed;
                        if self.offset == self.slice(self.index).len() {
                            self.index += 1;
                            self.offset = 0;
                        }
                    }
                }
                Err(error) => return self.fail(error),
            }
        }
        if self.count != 0 {
            if let Err(error) = ready!(Pin::new(writer).poll_flush(cx)) { return self.fail(error); }
        }
        let result = BatchResult { sent: self.count, error: self.error.take(), fatal: false };
        self.clear();
        Poll::Ready(result)
    }

    fn clear(&mut self) {
        self.headers.clear(); self.payloads.clear(); self.coalesced.clear();
        self.coalesced_ready = false; self.index = 0; self.offset = 0; self.count = 0;
    }

    fn fail(&mut self, error: io::Error) -> Poll<BatchResult> {
        // A partially written frame cannot be skipped or retried on this stream.
        self.clear(); self.error = None; self.terminated = true;
        Poll::Ready(BatchResult::terminated(error))
    }
}

#[cfg(test)]
#[path = "framed_tests.rs"]
mod tests;
