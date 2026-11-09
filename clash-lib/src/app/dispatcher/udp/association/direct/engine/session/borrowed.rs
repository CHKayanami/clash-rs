//! Synchronous sends borrow immutable ingress owners. Only an unsent suffix is
//! copied into the ordinary queue, before the device may recycle those owners.
use std::{net::SocketAddr, sync::Arc};
use super::*;
use crate::{app::dispatcher::udp::association::{direct::Upload, flow::FlowState},
    proxy::{direct::native::SendWorkspace, datagram::batch::MAX_BATCH_BYTES, utils::udp_batch::DatagramSlice}, session::SocksAddr};

struct Batch<'a> {
    slices: [DatagramSlice<'a>; MAX_DIRECT_BATCH_PACKETS],
    uploads: [Option<&'a Upload>; MAX_DIRECT_BATCH_PACKETS],
    owners: [Option<Arc<FlowState>>; MAX_DIRECT_BATCH_PACKETS],
    owner_index: [usize; MAX_DIRECT_BATCH_PACKETS],
    count: usize,
    owner_count: usize,
    bytes: usize,
}
impl<'a> Batch<'a> {
    fn new() -> Self {
        Self { slices: std::array::from_fn(|_| DatagramSlice { header: &[], payload: &[],
            destination: SocketAddr::from(([0, 0, 0, 0], 0)) }), uploads: [None; MAX_DIRECT_BATCH_PACKETS],
            owners: std::array::from_fn(|_| None), owner_index: [0; MAX_DIRECT_BATCH_PACKETS],
            count: 0, owner_count: 0, bytes: 0 }
    }
    fn collect(&mut self, state: &mut AssociationState, uploads: &[&'a Upload], cursor: &mut usize, now: Instant) {
        while let Some(upload) = uploads.get(*cursor) {
            if upload.segmentation.is_some() || self.count == MAX_DIRECT_BATCH_PACKETS { break; }
            let length = upload.data().len();
            if self.count > 0 && self.bytes + length > MAX_BATCH_BYTES { break; }
            let owner = self.owners[..self.owner_count].iter().position(|flow|
                flow.as_ref().is_some_and(|flow| flow.id == upload.id));
            let index = if let Some(index) = owner {
                // Cached owners can be closed concurrently by another worker.
                if self.owners[index].as_ref().unwrap().is_closed() { *cursor += 1; continue; }
                index
            } else {
                let Some(flow) = state.direct_flow(upload.id, now) else { *cursor += 1; continue; };
                self.owners[self.owner_count] = Some(flow);
                self.owner_count += 1; self.owner_count - 1
            };
            let flow = self.owners[index].as_ref().unwrap();
            let SocksAddr::Ip(destination) = flow.target else { break; };
            self.slices[self.count] = DatagramSlice { header: &[], payload: upload.data(), destination };
            self.uploads[self.count] = Some(upload);
            self.owner_index[self.count] = index;
            self.count += 1; self.bytes += length; *cursor += 1;
        }
    }
    fn complete(&self, state: &mut AssociationState, count: usize, now: Instant) {
        let mut index = 0;
        while index < count {
            let owner = self.owner_index[index];
            let mut bytes = 0;
            while index < count && self.owner_index[index] == owner {
                bytes += self.slices[index].payload.len(); index += 1;
            }
            state.sent_direct(self.owners[owner].as_ref().unwrap(), bytes, now);
        }
    }
    fn retain(&self, session: &mut Session, from: usize, now: Instant) {
        for index in from..self.count {
            let flow = self.owners[self.owner_index[index]].as_ref().unwrap();
            session.retain_admitted(self.uploads[index].unwrap(), flow, 0, None, now);
        }
    }
}

impl Session {
    pub(in crate::app::dispatcher::udp::association::direct::engine) fn upload_borrowed(&mut self, cx: &mut Context<'_>, uploads: &[&Upload], checked: bool, now: Instant, workspace: &mut SendWorkspace) -> Work {
        if !checked && !self.poll_control(cx) { return Work { close: true, ..Work::default() }; }
        let mut work = if self.has_upload() { self.poll_send(cx, now) } else { Work::default() };
        let mut cursor = 0;
        while cursor < uploads.len() && !work.close {
            if self.has_upload() || self.datagram.native_udp().is_none() {
                self.upload_owned(cx, uploads[cursor], now, &mut work); cursor += 1; continue;
            }
            if uploads[cursor].segmentation.is_some() {
                self.upload_segmented(cx, uploads[cursor], now, &mut work, workspace); cursor += 1; continue;
            }
            let mut batch = Batch::new();
            batch.collect(&mut self.state, uploads, &mut cursor, now);
            if batch.count == 0 {
                if cursor < uploads.len() {
                    // Unsupported physical addresses retain ordinary validation
                    // and per-datagram error handling without reordering a prefix.
                    self.upload_owned(cx, uploads[cursor], now, &mut work); cursor += 1;
                }
                continue;
            }
            let result = self.datagram.native_udp().unwrap().poll_send_slices_with(cx, &batch.slices[..batch.count], workspace);
            match result {
                Poll::Pending => batch.retain(self, 0, now),
                Poll::Ready(result) => {
                    assert!(result.sent > 0 || result.error.is_some(), "borrowed UDP send made no progress");
                    batch.complete(&mut self.state, result.sent, now);
                    work.frames += result.sent;
                    work.bytes += batch.slices[..result.sent].iter().map(|slice| slice.payload.len()).sum::<usize>();
                    work.progress = true;
                    let mut retained = result.sent;
                    if let Some(error) = result.error {
                        retained += 1; work.frames += 1;
                        work.close = !self.state.send_error(error) || result.fatal;
                    }
                    if !work.close {
                        batch.retain(self, retained, now);
                        work.again |= retained < batch.count;
                    }
                },
            }
        }
        work
    }

    fn retain_admitted(&mut self, upload: &Upload, flow: &Arc<FlowState>, offset: usize,
        segmentation: Option<u16>, now: Instant) {
        // These bytes precede anything enqueued into cold after admission.
        // Retention is transport completion, not a second policy decision.
        let mut packet = upload.retain_from(offset).packet;
        packet.dst_addr = flow.target.clone();
        assert!(self.aggregate.is_none() && self.deferred.is_none(), "borrowed UDP suffix has an earlier owner");
        if let Some(size) = segmentation.and_then(NonZeroU16::new) {
            assert!(self.sending.is_empty(), "borrowed UDP segments overtake queued data");
            self.aggregate = Some((DatagramSegments { packet, size: Some(size) }, 0));
        } else {
            // collect() uses the same byte/packet bounds as this owned queue.
            self.sending.push(packet).expect("borrowed UDP suffix exceeds its queue");
        }
        self.state.retain_direct(flow, now);
    }

    fn upload_owned(&mut self, cx: &mut Context<'_>, upload: &Upload, now: Instant, work: &mut Work) {
        if upload.segmentation.is_some() || self.has_aggregate() { work.merge(self.poll_send(cx, now)); }
        if work.close { return; }
        if !self.can_upload(upload.segmentation) {
            tracing::trace!("DIRECT UDP send batch full, dropping packet"); return;
        }
        if self.upload(upload.retain(), upload.segmentation, now) {
            if upload.segmentation.is_some() || self.upload_full() { work.merge(self.poll_send(cx, now)); }
        } else { tracing::trace!("DIRECT UDP send batch full, dropping packet"); }
    }

    fn upload_segmented(&mut self, cx: &mut Context<'_>, upload: &Upload, now: Instant, work: &mut Work, workspace: &mut SendWorkspace) {
        let Some(flow) = self.state.direct_flow(upload.id, now) else { return; };
        let SocksAddr::Ip(destination) = flow.target else {
            self.upload_owned(cx, upload, now, work); return;
        };
        let size = usize::from(upload.segmentation.unwrap());
        let result = self.datagram.native_udp().unwrap().poll_send_segments_with(cx, upload.data(), destination, size, workspace);
        let mut offset = 0;
        match result {
            Poll::Pending => {},
            Poll::Ready(result) => {
                assert!(result.bytes > 0 || result.error.is_some(), "borrowed UDP segments made no progress");
                offset += result.bytes; work.bytes += result.bytes; work.frames += 1; work.progress = true;
                if result.bytes > 0 { self.state.sent_direct(&flow, result.bytes, now); }
                if let Some(error) = result.error {
                    offset += result.failed;
                    work.close = !self.state.send_error(error) || result.fatal;
                }
                work.again |= !work.close && offset < upload.data().len();
            },
        }
        if !work.close && offset < upload.data().len() {
            self.retain_admitted(upload, &flow, offset, upload.segmentation, now);
        }
    }
}

#[cfg(test)]
mod tests;
