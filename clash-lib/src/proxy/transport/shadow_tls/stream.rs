use std::{
    pin::Pin,
    task::{Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{prelude::*, utils::*};
use crate::common::io::{ReadExactSlideBase, ReadExactSlideExt, SlideBuffer};

#[derive(Default, Debug)]
pub enum ReadState {
    #[default]
    WaitingHeader,
    WaitingData(usize, [u8; TLS_HEADER_SIZE]),
    FlushingData,
}

#[derive(Default, Debug)]
pub enum WriteState {
    #[default]
    Idle,
    Flushing(usize),
}

#[derive(Debug)]
pub struct VerifiedStream<S> {
    pub raw: S,
    client_cert: Hmac,
    server_cert: Hmac,
    nop_cert: Option<Hmac>,

    pub read_buf: SlideBuffer,
    pub read_state: ReadState,

    pub write_buf: SlideBuffer,
    pub write_state: WriteState,
}

impl<S: crate::proxy::ProxyStream> crate::proxy::ProxyStream for VerifiedStream<S> {}

impl<S> VerifiedStream<S> {
    pub(crate) fn new(
        raw: S,
        client_cert: Hmac,
        server_cert: Hmac,
        nop_cert: Option<Hmac>,
    ) -> Self {
        Self {
            raw,
            client_cert,
            server_cert,
            nop_cert,
            read_buf: SlideBuffer::new(COPY_BUF_SIZE * 4),
            read_state: Default::default(),
            write_buf: SlideBuffer::new(COPY_BUF_SIZE * 4),
            write_state: Default::default(),
        }
    }
}

impl<S: AsyncRead + Unpin> ReadExactSlideBase for VerifiedStream<S> {
    type I = S;

    fn decompose(&mut self) -> (&mut Self::I, &mut SlideBuffer) {
        (&mut self.raw, &mut self.read_buf)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VerifiedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.read_state {
                ReadState::WaitingHeader => {
                    if this.read_buf.is_empty() {
                        if this.read_buf.remaining_capacity() < TLS_HEADER_SIZE {
                            this.read_buf.compact();
                        }
                        let mut read_buf_obj = tokio::io::ReadBuf::new(
                            &mut this.read_buf.write_slice()[..TLS_HEADER_SIZE],
                        );
                        ready!(Pin::new(&mut this.raw)
                            .poll_read(cx, &mut read_buf_obj))?;
                        let n = read_buf_obj.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        this.read_buf.advance_write(n);
                    }

                    if this.read_buf.len() < TLS_HEADER_SIZE {
                        ready!(this.poll_read_exact(cx, TLS_HEADER_SIZE))?;
                    }

                    let header_slice = &this.read_buf.as_slice()[..TLS_HEADER_SIZE];
                    let data_size = u16::from_be_bytes([
                        header_slice[3],
                        header_slice[4],
                    ]) as usize;

                    let mut header = [0u8; TLS_HEADER_SIZE];
                    header.copy_from_slice(header_slice);

                    this.read_buf.consume(TLS_HEADER_SIZE);
                    this.read_state = ReadState::WaitingData(data_size, header);
                }
                ReadState::WaitingData(size, header) => {
                    ready!(this.poll_read_exact(cx, size))?;

                    if header[0] == APPLICATION_DATA {
                        // ignore handshake application data
                        if let Some(ref mut nop_cert) = this.nop_cert {
                            if verify_appdata(
                                &header,
                                &mut this.read_buf.as_mut_slice()[..size],
                                nop_cert,
                                false,
                            ) {
                                this.read_buf.consume(size);
                                this.read_state = ReadState::WaitingHeader;
                                continue;
                            } else {
                                this.nop_cert.take();
                            }
                        }

                        // application data from data server: verify and strip 4-byte HMAC
                        if verify_appdata(
                            &header,
                            &mut this.read_buf.as_mut_slice()[..size],
                            &mut this.server_cert,
                            true,
                        ) {
                            this.read_buf.consume(HMAC_SIZE);
                            this.read_state = ReadState::FlushingData;
                        } else {
                            tracing::error!("shadowtls appdata verify failed");
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "appdata verify failed",
                            )));
                        }
                    } else {
                        this.read_buf.consume(size);
                        this.read_state = ReadState::WaitingHeader;
                    }
                }
                ReadState::FlushingData => {
                    let available = this.read_buf.len();
                    let to_read = std::cmp::min(buf.remaining(), available);
                    buf.put_slice(&this.read_buf.as_slice()[..to_read]);
                    this.read_buf.consume(to_read);

                    if this.read_buf.is_empty() {
                        this.read_state = ReadState::WaitingHeader;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VerifiedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();

        loop {
            match this.write_state {
                WriteState::Idle => {
                    const DEFAULT_HEADER_HMAC: [u8; TLS_HMAC_HEADER_SIZE] =
                        [APPLICATION_DATA, TLS_MAJOR, TLS_MINOR.0, 0, 0, 0, 0, 0, 0];

                    let total_frame_len = TLS_HMAC_HEADER_SIZE + buf.len();
                    this.write_buf.reserve(total_frame_len);

                    let start_pos = this.write_buf.len();
                    this.write_buf.extend_from_slice(&DEFAULT_HEADER_HMAC);

                    let len_bytes = ((buf.len() + HMAC_SIZE) as u16).to_be_bytes();
                    this.write_buf.as_mut_slice()[start_pos + 3..start_pos + 5]
                        .copy_from_slice(&len_bytes);
                    this.write_buf.extend_from_slice(buf);

                    this.client_cert.update(buf);
                    let hmac_val = this.client_cert.finalize();
                    this.client_cert.update(&hmac_val);
                    this.write_buf.as_mut_slice()[start_pos + TLS_HEADER_SIZE
                        ..start_pos + TLS_HMAC_HEADER_SIZE]
                        .copy_from_slice(&hmac_val);

                    this.write_state = WriteState::Flushing(buf.len());
                }
                WriteState::Flushing(consumed) => {
                    while !this.write_buf.is_empty() {
                        let nw = ready!(Pin::new(&mut this.raw)
                            .poll_write(cx, this.write_buf.as_slice()))?;
                        if nw == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "failed to write whole data",
                            )));
                        }
                        this.write_buf.consume(nw);
                    }
                    this.write_state = WriteState::Idle;
                    return Poll::Ready(Ok(consumed));
                }
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            let nw = ready!(Pin::new(&mut this.raw)
                .poll_write(cx, this.write_buf.as_slice()))?;
            if nw == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to flush data",
                )));
            }
            this.write_buf.consume(nw);
        }
        this.write_state = WriteState::Idle;
        Pin::new(&mut this.raw).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            let nw = ready!(Pin::new(&mut this.raw)
                .poll_write(cx, this.write_buf.as_slice()))?;
            if nw == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to flush data on shutdown",
                )));
            }
            this.write_buf.consume(nw);
        }
        this.write_state = WriteState::Idle;
        Pin::new(&mut this.raw).poll_shutdown(cx)
    }
}

fn verify_appdata(
    header: &[u8; TLS_HEADER_SIZE],
    data: &mut [u8],
    hmac: &mut Hmac,
    sep: bool,
) -> bool {
    if header[1] != TLS_MAJOR || header[2] != TLS_MINOR.0 || data.len() < HMAC_SIZE {
        return false;
    }
    hmac.update(&data[HMAC_SIZE..]);
    let hmac_real = hmac.finalize();
    if sep {
        hmac.update(&hmac_real);
    }
    data[0..HMAC_SIZE] == hmac_real
}
