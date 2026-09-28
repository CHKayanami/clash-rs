use crate::{proxy::datagram::UdpPacket, session::SocksAddr as ClashSocksAddr};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use std::{sync::Arc, time::Duration};

use super::{
    proto::{
        Address, ParsedPacket, encode_auth, encode_connect_prefix,
        encode_dissociate, encode_heartbeat, encode_single_packet, packet_fragments,
    },
    stream::TuicStream,
    types::{TuicConnection, UdpRelayMode},
};

impl TuicConnection {
    pub async fn tuic_auth(
        self: Arc<Self>,
        zero_rtt_accepted: Option<quinn::ZeroRttAccepted>,
    ) {
        if let Some(zero_rtt_accepted) = zero_rtt_accepted {
            tracing::debug!("[auth] waiting for connection to be fully established");
            zero_rtt_accepted.await;
        }

        tracing::debug!("[auth] generating authentication token via TLS exporter");
        let mut token = [0u8; 32];
        if let Err(err) = self.conn.export_keying_material(
            &mut token,
            self.uuid.as_bytes(),
            &self.password,
        ) {
            tracing::warn!("[auth] export_keying_material failed: {err:?}");
            return;
        }

        let auth_buf = encode_auth(self.uuid, token);
        match self.conn.open_uni().await {
            Ok(mut send) => {
                if let Err(err) = send.write_all(&auth_buf).await {
                    tracing::warn!("[auth] authentication sending error: {err}");
                    return;
                }
                if let Err(err) = send.finish() {
                    tracing::warn!("[auth] failed to finish authentication stream: {err}");
                    return;
                }
                match send.stopped().await {
                    Ok(None) => tracing::info!(
                        "[auth] authentication frame acknowledged for {uuid}",
                        uuid = self.uuid
                    ),
                    Ok(Some(code)) => tracing::warn!(
                        "[auth] authentication stream stopped by peer with code {code}"
                    ),
                    Err(err) => tracing::warn!(
                        "[auth] authentication stream acknowledgement failed: {err}"
                    ),
                }
            }
            Err(err) => {
                tracing::warn!("[auth] open_uni error: {err}");
            }
        }
    }

    pub async fn connect_tcp(&self, addr: Address) -> Result<TuicStream> {
        let addr_display = addr.to_string();
        tracing::info!("[tcp] {addr_display}");

        let (mut send, recv) = self.conn.open_bi().await.map_err(|e| {
            tracing::warn!("[tcp] failed open_bi stream to {addr_display}: {e}");
            anyhow!(e)
        })?;

        let prefix = encode_connect_prefix(&addr);
        send.write_all(&prefix).await.map_err(|e| {
            tracing::warn!(
                "[tcp] failed writing connect prefix to {addr_display}: {e}"
            );
            anyhow!(e)
        })?;

        Ok(TuicStream::new(send, recv))
    }

    pub async fn outgoing_udp(
        &self,
        pkt: Bytes,
        addr: Address,
        assoc_id: u16,
    ) -> Result<()> {
        let pkt_id = self.get_next_pkt_id();
        match self.udp_relay_mode {
            UdpRelayMode::Native => {
                tracing::debug!("[udp] [{assoc_id:#06x}] [to-native] to {addr}");
                let max_size = self.conn.max_datagram_size().ok_or_else(|| {
                    anyhow!("peer does not support QUIC datagrams")
                })?;
                let frames =
                    packet_fragments(assoc_id, pkt_id, &addr, &pkt, max_size)?;
                for frame in frames {
                    let frame = frame?;
                    self.conn.send_datagram(frame).map_err(|err| {
                        tracing::warn!(
                            "[udp] [{assoc_id:#06x}] [to-native] to {addr}: {err}"
                        );
                        anyhow!(err)
                    })?;
                }
                Ok(())
            }
            UdpRelayMode::Quic => {
                tracing::debug!("[udp] [{assoc_id:#06x}] [to-quic] {addr}");
                let wire_pkt = encode_single_packet(assoc_id, pkt_id, &addr, &pkt)?;
                let mut send = self.conn.open_uni().await.map_err(|err| {
                    tracing::warn!(
                        "[udp] [{assoc_id:#06x}] [to-quic] to {addr}: {err}"
                    );
                    anyhow!(err)
                })?;
                send.write_all(&wire_pkt)
                    .await
                    .map_err(|err| anyhow!(err))?;
                let _ = send.finish();
                Ok(())
            }
        }
    }

    pub async fn dispatch_packet(&self, parsed: ParsedPacket, mode: &str) {
        let assoc_id = parsed.assoc_id;
        let pkt_id = parsed.pkt_id;

        tracing::debug!(
            "[udp] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] from {addr}",
            addr = parsed.addr
        );

        let (session, local_addr) = match self.udp_sessions.read().get(&assoc_id) {
            Some(v) => (v.incoming.clone(), v.local_addr.clone()),
            None => {
                tracing::debug!(
                    "[udp] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] no active session"
                );
                return;
            }
        };

        let complete = if parsed.frag_total == 1 {
            (parsed.frag_id == 0 && parsed.addr != Address::None)
                .then_some((parsed.addr, parsed.payload))
        } else {
            self.fragments.lock().accept(parsed)
        };
        let Some((address, payload)) = complete else {
            return;
        };
        let remote_addr = match ClashSocksAddr::try_from(address) {
            Ok(addr) => addr,
            Err(e) => {
                tracing::warn!("[udp] failed converting address: {e}");
                return;
            }
        };

        let packet = UdpPacket::new(payload, remote_addr, local_addr);
        match self.udp_relay_mode {
            UdpRelayMode::Native => {
                if let Err(err) = session.try_send(packet) {
                    tracing::debug!(
                        "[udp] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] dropping packet: {err}"
                    );
                }
            }
            UdpRelayMode::Quic => {
                if let Err(err) = session.send(packet).await {
                    tracing::warn!(
                        "[udp] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] failed sending packet: {err}"
                    );
                }
            }
        }
    }

    pub async fn dissociate(&self, assoc_id: u16) -> Result<()> {
        tracing::info!("[udp] [dissociate] [{assoc_id:#06x}]");
        self.fragments.lock().remove_association(assoc_id);
        let buf = encode_dissociate(assoc_id);
        let mut send = self.conn.open_uni().await?;
        send.write_all(&buf).await?;
        let _ = send.finish();
        Ok(())
    }

    async fn heartbeat(&self) -> Result<()> {
        self.check_open()?;
        let buf = encode_heartbeat();
        let _ = self.conn.send_datagram(buf);
        tracing::debug!("[tuic heartbeat] - {}", self.conn.remote_address());
        Ok(())
    }

    /// Periodic heartbeat task
    pub async fn cyclical_tasks(
        self: Arc<Self>,
        heartbeat_interval: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) -> anyhow::Error {
        let mut interval = tokio::time::interval(heartbeat_interval);
        let mut gc = tokio::time::interval(gc_interval);
        // Consume immediate first tick to avoid racing authentication
        interval.tick().await;
        gc.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(err) = self.heartbeat().await {
                        return err;
                    }
                }
                _ = gc.tick() => self.fragments.lock().expire(gc_lifetime),
            }
        }
    }
}
