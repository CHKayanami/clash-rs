//! Handshake execution and handler-scoped session resumption.

use std::{io, sync::Arc, time::{Duration, Instant}};
use anyhow::Context as _;
use boring::mlkem::{Algorithm as MlKemAlgorithm, MlKemPrivateKey};
use parking_lot::RwLock;
use rand::{Rng, RngExt as _, rng};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::{Instant as TokioInstant, timeout_at}};

use crate::proxy::AnyStream;
use super::{IV_LEN, MAX_NONCE, MLKEM_CIPHERTEXT_LEN, PFS_CLIENT_KEY_LEN,
    PFS_SERVER_KEY_LEN, SHARED_SECRET_LEN, TAG_LEN, TICKET_LEN, X25519_KEY_LEN};
use super::crypto::{AesCtr, StreamAead, aes_gcm_hardware_available,
    encode_length, x25519, x25519_keypair};
use super::options::{AuthKey, EncryptionOptions, PaddingSpec, XorMode};
use super::stream::{EncryptionStream, SessionKeys, StreamInit};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct SessionTicket {
    pfs_key: [u8; 64],
    ticket: [u8; TICKET_LEN],
    expires_at: Instant,
}

pub(crate) struct EncryptionClient {
    options: Arc<EncryptionOptions>,
    ticket: RwLock<Option<SessionTicket>>,
}

impl EncryptionClient {
    pub(crate) fn new(options: Arc<EncryptionOptions>) -> Arc<Self> {
        Arc::new(Self { options, ticket: RwLock::new(None) })
    }

    /// Apply one deadline to all handshake I/O and padding waits.
    pub(crate) async fn handshake(
        self: &Arc<Self>, stream: AnyStream,
    ) -> io::Result<EncryptionStream> {
        self.handshake_until(stream, HANDSHAKE_TIMEOUT).await
    }

    async fn handshake_until(
        self: &Arc<Self>, stream: AnyStream, timeout: Duration,
    ) -> io::Result<EncryptionStream> {
        let deadline = TokioInstant::now() + timeout;
        timeout_at(deadline, self.handshake_inner(stream, timeout)).await
            .map_err(|_| io::Error::new(
                io::ErrorKind::TimedOut, "VLESS Encryption handshake timed out",
            ))?
            .map_err(|error| match error.downcast::<io::Error>() {
                Ok(error) => error,
                Err(error) => io::Error::new(io::ErrorKind::InvalidData, error),
            })
    }

    #[cfg(test)]
    pub(super) async fn handshake_with_timeout(
        self: &Arc<Self>, stream: AnyStream, timeout: Duration,
    ) -> io::Result<EncryptionStream> {
        self.handshake_until(stream, timeout).await
    }

    #[cfg(test)]
    pub(in crate::proxy::vless) fn cached_ticket(&self) -> Option<[u8; TICKET_LEN]> {
        self.ticket.read().as_ref().map(|ticket| ticket.ticket)
    }

    async fn handshake_inner(
        self: &Arc<Self>, mut stream: AnyStream, timeout: Duration,
    ) -> anyhow::Result<EncryptionStream> {
        let use_aes = aes_gcm_hardware_available();
        let mut iv = [0u8; IV_LEN];
        rng().fill_bytes(&mut iv);
        let (relays, nfs_key) = self.build_relays(&iv)?;
        let mut nfs_aead = StreamAead::new(&iv, &nfs_key, use_aes)?;
        let prior_ticket = if self.options.allow_0rtt {
            self.ticket
                .read()
                .as_ref()
                .filter(|ticket| ticket.expires_at > Instant::now())
                .cloned()
        } else {
            None
        };

        if let Some(ticket) = prior_ticket {
            let mut prewrite = Vec::with_capacity(IV_LEN + relays.len() + 18 + 32);
            prewrite.extend_from_slice(&iv);
            prewrite.extend_from_slice(&relays);
            nfs_aead.seal(&encode_length(32), b"", &mut prewrite)?;
            let ticket_context_start = prewrite.len();
            nfs_aead.seal(&ticket.ticket, b"", &mut prewrite)?;
            let ticket_context = &prewrite[ticket_context_start..];
            let united_key = combine_keys(&ticket.pfs_key, &nfs_key);
            let send = StreamAead::new(ticket_context, &united_key, use_aes)?;
            let send_xor = (self.options.mode == XorMode::Random).then(|| AesCtr::new(&united_key, &iv));
            return Ok(EncryptionStream::new(
                stream,
                SessionKeys { material: united_key, use_aes },
                StreamInit::resumed(
                    send, send_xor, prewrite,
                    TicketUse::new(self.clone(), ticket.pfs_key), timeout,
                ),
            ));
        }

        let (padding_len, mut padding_lengths, padding_gaps) = self.make_padding();
        let (mlkem_public, mlkem_private) = MlKemPrivateKey::generate(MlKemAlgorithm::MlKem768)?;
        let (x_public, x_private) = x25519_keypair();
        let mut pfs_public = Vec::with_capacity(PFS_CLIENT_KEY_LEN);
        pfs_public.extend_from_slice(mlkem_public.as_bytes());
        pfs_public.extend_from_slice(&x_public);

        let mut hello = Vec::with_capacity(IV_LEN + relays.len() + 1250 + padding_len);
        hello.extend_from_slice(&iv);
        hello.extend_from_slice(&relays);
        nfs_aead.seal(
            &encode_length(PFS_CLIENT_KEY_LEN + TAG_LEN),
            b"",
            &mut hello,
        )?;
        nfs_aead.seal(&pfs_public, b"", &mut hello)?;
        anyhow::ensure!(padding_len >= 35, "VLESS Encryption padding is too short");
        nfs_aead.seal(&encode_length(padding_len - 18), b"", &mut hello)?;
        let padding_plaintext = vec![0; padding_len - 34];
        nfs_aead.seal(&padding_plaintext, b"", &mut hello)?;

        padding_lengths[0] += IV_LEN + relays.len() + 18 + PFS_CLIENT_KEY_LEN + TAG_LEN;
        let mut offset = 0;
        for (index, length) in padding_lengths.into_iter().enumerate() {
            if length > 0 {
                stream.write_all(&hello[offset..offset + length]).await?;
                offset += length;
            }
            if let Some(gap) = padding_gaps.get(index).copied() {
                tokio::time::sleep(gap.min(timeout)).await;
            }
        }
        anyhow::ensure!(
            offset == hello.len(),
            "VLESS Encryption padding layout mismatch"
        );
        stream.flush().await?;

        let mut encrypted_server_key = vec![0u8; PFS_SERVER_KEY_LEN + TAG_LEN];
        stream.read_exact(&mut encrypted_server_key).await?;
        let server_key_len =
            nfs_aead.open_with_nonce(&MAX_NONCE, &mut encrypted_server_key, b"")?;
        anyhow::ensure!(
            server_key_len == PFS_SERVER_KEY_LEN,
            "invalid VLESS Encryption server key length"
        );
        let server_key = &encrypted_server_key[..server_key_len];
        let mlkem_shared = mlkem_private
            .decapsulate(&server_key[..MLKEM_CIPHERTEXT_LEN])
            .context("invalid VLESS Encryption server ML-KEM ciphertext")?;
        let server_x25519: &[u8; X25519_KEY_LEN] = server_key[MLKEM_CIPHERTEXT_LEN..]
            .try_into()
            .expect("checked server X25519 key length");
        let x_shared = x25519(&x_private, server_x25519)?;
        let mut pfs_key = [0u8; 64];
        pfs_key[..32].copy_from_slice(&mlkem_shared);
        pfs_key[32..].copy_from_slice(&x_shared);
        let united_key = combine_keys(&pfs_key, &nfs_key);
        let send = StreamAead::new(&pfs_public, &united_key, use_aes)?;
        let mut recv = StreamAead::new(server_key, &united_key, use_aes)?;

        let mut encrypted_ticket = vec![0u8; TICKET_LEN + TAG_LEN];
        stream.read_exact(&mut encrypted_ticket).await?;
        let ticket_len = recv.open(&mut encrypted_ticket, b"")?;
        anyhow::ensure!(
            ticket_len == TICKET_LEN,
            "invalid VLESS Encryption ticket length"
        );
        let ticket: [u8; TICKET_LEN] = encrypted_ticket[..ticket_len]
            .try_into()
            .expect("checked ticket length");
        let ticket_seconds = u16::from_be_bytes([ticket[0], ticket[1]]);

        let mut encrypted_padding_len = vec![0u8; 18];
        stream.read_exact(&mut encrypted_padding_len).await?;
        let padding_len_plain = recv.open(&mut encrypted_padding_len, b"")?;
        anyhow::ensure!(
            padding_len_plain == 2,
            "invalid VLESS Encryption padding length"
        );
        let peer_padding_len =
            u16::from_be_bytes([encrypted_padding_len[0], encrypted_padding_len[1]]) as usize;
        anyhow::ensure!(
            (TAG_LEN..=u16::MAX as usize).contains(&peer_padding_len),
            "invalid VLESS Encryption peer padding length"
        );
        let mut peer_padding = vec![0; peer_padding_len];
        stream.read_exact(&mut peer_padding).await?;
        recv.open(&mut peer_padding, b"")
            .context("invalid VLESS Encryption peer padding")?;
        if self.options.allow_0rtt && ticket_seconds > 0 {
            *self.ticket.write() = Some(SessionTicket {
                pfs_key,
                ticket,
                expires_at: Instant::now() + Duration::from_secs(u64::from(ticket_seconds)),
            });
        }

        let send_xor = (self.options.mode == XorMode::Random).then(|| AesCtr::new(&united_key, &iv));
        let recv_xor = (self.options.mode == XorMode::Random).then(|| AesCtr::new(&united_key, &ticket));

        Ok(EncryptionStream::new(
            stream,
            SessionKeys { material: united_key, use_aes },
            StreamInit::established(
                send,
                recv,
                send_xor, recv_xor,
            ),
        ))
    }

    fn build_relays(&self, iv: &[u8; IV_LEN]) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
        let mut relays = Vec::with_capacity(self.options.relays_len);
        let mut previous = None::<AesCtr>;
        let mut final_key = [0u8; 32];
        for (index, key) in self.options.auth_keys.iter().enumerate() {
            let (mut ciphertext, shared) = encapsulate(key)?;
            if self.options.mode != XorMode::Native {
                AesCtr::new(key.public_bytes(), iv).apply(&mut ciphertext);
            }
            if let Some(previous) = previous.as_mut() {
                previous.apply(&mut ciphertext[..32]);
            }
            relays.extend_from_slice(&ciphertext);
            final_key = shared;
            if index + 1 < self.options.auth_keys.len() {
                let mut chain = AesCtr::new(&shared, iv);
                let mut next_hash = *self.options.auth_keys[index + 1].hash();
                chain.apply(&mut next_hash);
                relays.extend_from_slice(&next_hash);
                previous = Some(chain);
            }
        }
        anyhow::ensure!(
            relays.len() == self.options.relays_len,
            "VLESS Encryption relay size mismatch"
        );
        Ok((relays, final_key))
    }

    fn make_padding(&self) -> (usize, Vec<usize>, Vec<Duration>) {
        let default_lengths = [
            PaddingSpec {
                probability: 100,
                min: 111,
                max: 1111,
            },
            PaddingSpec {
                probability: 50,
                min: 0,
                max: 3333,
            },
        ];
        let default_gaps = [PaddingSpec {
            probability: 75,
            min: 0,
            max: 111,
        }];
        let lengths = if self.options.padding_lengths.is_empty() {
            &default_lengths[..]
        } else {
            &self.options.padding_lengths
        };
        let gaps = if self.options.padding_lengths.is_empty() {
            &default_gaps[..]
        } else {
            &self.options.padding_gaps
        };
        let mut rng = rng();
        let selected_lengths: Vec<_> = lengths
            .iter()
            .map(|spec| select_padding(&mut rng, *spec))
            .collect();
        let selected_gaps = gaps
            .iter()
            .map(|spec| Duration::from_millis(select_padding(&mut rng, *spec) as u64))
            .collect();
        (
            selected_lengths.iter().sum(),
            selected_lengths,
            selected_gaps,
        )
    }
}

fn combine_keys(pfs_key: &[u8; 64], nfs_key: &[u8; 32]) -> [u8; 96] {
    let mut key = [0; 96];
    key[..64].copy_from_slice(pfs_key);
    key[64..].copy_from_slice(nfs_key);
    key
}

fn select_padding(rng: &mut impl Rng, spec: PaddingSpec) -> usize {
    if rng.random_range(0u8..100) < spec.probability {
        rng.random_range(spec.min..=spec.max)
    } else {
        0
    }
}

fn encapsulate(key: &AuthKey) -> anyhow::Result<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    match key {
        AuthKey::X25519 { public, .. } => {
            let (ephemeral_public, ephemeral_private) = x25519_keypair();
            let shared = x25519(&ephemeral_private, public)?;
            Ok((ephemeral_public.to_vec(), shared))
        }
        AuthKey::MlKem { public, .. } => {
            let (ciphertext, shared) = public.encapsulate()?;
            Ok((ciphertext, shared))
        }
    }
}

pub(super) struct TicketUse {
    client: Arc<EncryptionClient>,
    pfs_key: [u8; 64],
}

impl TicketUse {
    pub(super) fn new(client: Arc<EncryptionClient>, pfs_key: [u8; 64]) -> Self {
        Self { client, pfs_key }
    }

    pub(super) fn invalidate(&self) {
        let mut ticket = self.client.ticket.write();
        if ticket
            .as_ref()
            .is_some_and(|current| current.pfs_key == self.pfs_key)
        {
            *ticket = None;
        }
    }
}
