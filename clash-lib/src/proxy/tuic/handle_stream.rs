use super::types::TuicConnection;
use crate::proxy::tuic::types::UdpRelayMode;
use bytes::Bytes;
use std::sync::Arc;

impl TuicConnection {
    pub async fn accept_uni_stream(&self) -> anyhow::Result<quinn::RecvStream> {
        let recv = self.conn.accept_uni().await?;
        Ok(recv)
    }

    pub async fn accept_bi_stream(
        &self,
    ) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
        let (send, recv) = self.conn.accept_bi().await?;
        Ok((send, recv))
    }

    pub async fn accept_datagram(&self) -> anyhow::Result<Bytes> {
        Ok(self.conn.read_datagram().await?)
    }

    pub async fn handle_uni_stream(self: Arc<Self>, mut recv: quinn::RecvStream) {
        tracing::debug!("[relay] incoming unidirectional stream");

        if self.udp_relay_mode != UdpRelayMode::Quic {
            tracing::warn!("[relay] received uni stream in non-quic relay mode");
            return;
        }

        match recv.read_to_end(super::proto::MAX_PACKET_FRAME_SIZE).await {
            Ok(data) => {
                let bytes = Bytes::from(data);
                match super::proto::decode_packet_frame(bytes) {
                    Ok(parsed) => {
                        self.dispatch_packet(parsed, "quic").await;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "[relay] incoming uni stream decode error: {err}"
                        );
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    "[relay] incoming unidirectional stream read error: {err}"
                );
            }
        }
    }

    pub async fn handle_bi_stream(
        self: Arc<Self>,
        _send: quinn::SendStream,
        _recv: quinn::RecvStream,
    ) {
        tracing::warn!(
            "[relay] incoming bidirectional stream: a client shouldn't receive bi stream"
        );
    }

    pub async fn handle_datagram(&self, dg: Bytes) {
        tracing::debug!("[relay] incoming datagram");

        if self.udp_relay_mode != UdpRelayMode::Native {
            tracing::warn!("[relay] received datagram in non-native relay mode");
            return;
        }

        match super::proto::decode_packet_frame(dg) {
            Ok(parsed) => {
                self.dispatch_packet(parsed, "native").await;
            }
            Err(err) => {
                tracing::warn!("[relay] incoming datagram decode error: {err}");
            }
        }
    }
}
