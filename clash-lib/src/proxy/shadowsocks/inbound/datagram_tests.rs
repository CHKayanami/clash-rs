use super::*;
use bytes::BytesMut;
use futures::{StreamExt, future::poll_fn};
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context as SsContext,
    crypto::CipherKind,
    relay::udprelay::{crypto_io::encrypt_client_payload, proxy_socket::UdpSocketType},
};
use tokio::{net::UdpSocket, time::{sleep, timeout}};

async fn fixture(
    allow_lan: bool,
    bind: &str,
) -> io::Result<(InboundShadowsocksDatagram, SocketAddr)> {
    let socket = UdpSocket::bind(bind).await?;
    let address = socket.local_addr()?;
    let config = ServerConfig::new(
        address, "AAAAAAAAAAAAAAAAAAAAAA==",
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
    ).map_err(new_io_error)?;
    let socket = ProxySocket::from_socket(
        UdpSocketType::Server, SsContext::new_shared(ServerType::Server),
        &config, socket.into(),
    );
    Ok((InboundShadowsocksDatagram::new(socket, allow_lan)?, address))
}

fn packet(session: u64, id: u64) -> BytesMut {
    let context = SsContext::new(ServerType::Local);
    let mut control = UdpSocketControlData::default();
    control.client_session_id = session;
    control.packet_id = id;
    let mut packet = BytesMut::new();
    encrypt_client_payload(
        &context, CipherKind::AEAD2022_BLAKE3_AES_128_GCM, &[0; 16],
        &Address::SocketAddress("1.1.1.1:53".parse().unwrap()),
        &control, &[], b"request", &mut packet,
    );
    packet
}

#[tokio::test]
async fn replay_from_another_address_preserves_destination_and_expiry()
-> io::Result<()> {
    let (mut inbound, address) = fixture(true, "127.0.0.1:0").await?;
    let first = UdpSocket::bind("127.0.0.1:0").await?;
    let other = UdpSocket::bind("127.0.0.1:0").await?;
    let encrypted = packet(101, 7);
    first.send_to(&encrypted, address).await?;
    timeout(Duration::from_secs(1), inbound.next())
        .await.unwrap().unwrap();
    let key = ClientSessionKey::Aead2022 { client_session_id: 101, user_hash: None };
    let expiry = inbound.expirations.deadline(&inbound.client_controls[&key].expiry);
    // The following accepted session is a barrier: receiving it proves the
    // earlier replay from the same physical socket has been processed.
    other.send_to(&encrypted, address).await?;
    other.send_to(&packet(202, 0), address).await?;
    timeout(Duration::from_secs(1), inbound.next())
        .await.unwrap().unwrap();
    let client = &inbound.client_controls[&key];
    assert_eq!(client.client_addr, first.local_addr()?);
    assert_eq!(inbound.expirations.deadline(&client.expiry), expiry);
    Ok(())
}

#[tokio::test]
async fn local_only_udp_gate_drops_disallowed_sources_before_session_creation()
-> io::Result<()> {
    let (mut inbound, address) = fixture(false, "127.0.0.1:0").await?;
    let allowed = inbound.allowed_sources.as_ref().unwrap();
    assert!(allowed.contains(&"127.0.0.1".parse().unwrap()));
    assert!(!allowed.contains(&"192.0.2.1".parse().unwrap()));
    // Exclude the test socket's physical source to exercise the receive gate.
    inbound.allowed_sources.as_mut().unwrap().clear();
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&packet(101, 0), address).await?;
    assert!(timeout(Duration::from_millis(20), inbound.next()).await.is_err());
    assert!(inbound.client_controls.is_empty());
    inbound.allowed_sources.as_mut().unwrap().insert(client.local_addr()?.ip());
    client.send_to(&packet(101, 1), address).await?;
    assert!(timeout(Duration::from_secs(1), inbound.next())
        .await.unwrap().is_some());
    Ok(())
}

#[tokio::test]
async fn idle_expiration_is_bounded_and_removes_all_session_indexes()
-> io::Result<()> {
    let (mut inbound, _) = fixture(true, "127.0.0.1:0").await?;
    for id in 0..130_u64 {
        let key = ClientSessionKey::Aead2022 { client_session_id: id, user_hash: None };
        let address = SocketAddr::new("127.0.0.1".parse().unwrap(), 1000 + id as u16);
        let mut ctrl = UdpSocketControlData::default();
        ctrl.server_session_id = id;
        let expiry = inbound.expirations.insert(key, Duration::ZERO);
        inbound.client_controls.insert(key, ClientControl {
            inbound_user: None, ctrl, logical_addr: address, client_addr: address,
            expiry, window: PacketWindow::new(),
        });
        inbound.address_sessions.insert(address, key);
        inbound.server_session_ids.insert(id);
    }
    sleep(Duration::from_millis(10)).await;
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(inbound.poll_next_unpin(&mut cx).is_pending());
    // Tokio's cooperative budget may yield before our own 128-entry budget.
    let remaining = inbound.client_controls.len();
    assert!((2..130).contains(&remaining));
    timeout(Duration::from_secs(1), poll_fn(|cx| {
        let _ = inbound.poll_next_unpin(cx);
        if inbound.client_controls.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })).await.unwrap();
    assert!(inbound.address_sessions.is_empty());
    assert!(inbound.server_session_ids.is_empty());
    assert!(inbound.expirations.is_empty());
    Ok(())
}

#[tokio::test]
async fn wildcard_local_only_udp_accepts_loopback() -> io::Result<()> {
    let (mut inbound, address) = fixture(false, "0.0.0.0:0").await?;
    assert!(!inbound.allowed_sources.as_ref().unwrap()
        .contains(&"192.0.2.1".parse().unwrap()));
    let target = SocketAddr::new("127.0.0.1".parse().unwrap(), address.port());
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(&packet(101, 0), target).await?;
    assert!(timeout(Duration::from_secs(1), inbound.next())
        .await.unwrap().is_some());
    Ok(())
}
