//! Retain pending device operations without blocking protocol processing.
use std::{io, mem, pin::Pin, sync::Arc, task::{Context, Poll}};
use bytes::BytesMut;
use clash_netstack::Packet;
use futures::Future;
use tokio_util::sync::ReusableBoxFuture;
use tun_rs::AsyncDevice;
use super::{Reader, Writer};
use tokio::task::unconstrained;
use tokio::sync::OwnedSemaphorePermit;
use super::super::device_loop::PacketIo;

type ReceiveCompletion = (Reader, Vec<Packet>, Vec<BytesMut>, io::Result<usize>);

pub(crate) struct DeviceIo {
    device: Arc<AsyncDevice>,
    reader: Option<Reader>,
    receiving: Option<ReusableBoxFuture<'static, ReceiveCompletion>>,
    reading: bool,
    writer: Option<Writer>,
    sending: Option<ReusableBoxFuture<'static, SendCompletion>>,
    scratch: Vec<BytesMut>,
    native_tcp: bool,
}

type SendCompletion = (Writer, Vec<Packet>, Vec<OwnedSemaphorePermit>, io::Result<()>);

impl DeviceIo {
    pub(in crate::proxy::tun) fn new(device: Arc<AsyncDevice>, reader: Reader, writer: Writer, native_tcp: bool) -> Self {
        Self { device, reader: Some(reader), receiving: None, reading: false,
            writer: Some(writer), sending: None, scratch: Vec::new(), native_tcp }
    }
}

impl PacketIo for DeviceIo {
    fn try_send_tcp(&mut self, header: &[u8], payload: &[u8], size: Option<u16>) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        if self.native_tcp {
            return super::linux::try_send_tcp(&self.device, header, payload, size);
        }
        let _ = (header, payload, size);
        Ok(false)
    }

    fn poll_receive(&mut self, cx: &mut Context<'_>, packets: &mut Vec<Packet>) -> Poll<io::Result<usize>> {
        if !self.reading {
            let mut reader = self.reader.take().expect("device read owner");
            let device = self.device.clone();
            let mut batch = mem::take(packets);
            let mut scratch = mem::take(&mut self.scratch);
            let native_tcp = self.native_tcp;
            let receive = async move {
                let result = reader.recv_frames(&device, &mut batch, &mut scratch, native_tcp).await;
                (reader, batch, scratch, result)
            };
            match &mut self.receiving {
                Some(pending) => pending.set(receive),
                None => self.receiving = Some(ReusableBoxFuture::new(receive)),
            }
            self.reading = true;
        }
        match Pin::new(self.receiving.as_mut().unwrap()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((reader, batch, scratch, result)) => {
                *packets = batch;
                self.reader = Some(reader);
                self.scratch = scratch;
                self.reading = false;
                result.into()
            }
        }
    }

    fn poll_send(&mut self, cx: &mut Context<'_>, packets: &mut Vec<Packet>,
        credits: &mut Vec<OwnedSemaphorePermit>) -> Poll<io::Result<()>> {
        if let Some(mut owner) = self.writer.take() {
            let device = self.device.clone();
            let mut batch = mem::take(packets);
            let budget = mem::take(credits);
            let send = async move {
                let result = unconstrained(owner.send(&device, &mut batch)).await;
                (owner, batch, budget, result)
            };
            match &mut self.sending {
                Some(pending) => pending.set(send),
                None => self.sending = Some(ReusableBoxFuture::new(send)),
            }
        }
        // Keep the future across Pending: restarting a partially written
        // batch would replay its successful prefix. Credits stay owned
        // by this operation until the actual write completes or cancels.
        match Pin::new(self.sending.as_mut().expect("device write owner")).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((owner, batch, budget, result)) => {
                self.writer = Some(owner);
                *packets = batch;
                *credits = budget;
                Poll::Ready(result)
            },
        }
    }
}
