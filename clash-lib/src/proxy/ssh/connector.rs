use russh::{
    client,
    keys::{PublicKeyOrCertificate, ssh_key},
};

pub struct Client {
    pub server_public_key: Option<Vec<ssh_key::PublicKey>>,
}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        match (&self.server_public_key, server_public_key) {
            (None, _) => Ok(true),
            (Some(keys), PublicKeyOrCertificate::PublicKey { key, .. })
                if keys.iter().any(|k| k == key) =>
            {
                Ok(true)
            }
            _ => Err(russh::Error::UnknownKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use russh::{
        Error,
        client::Handler,
        keys::{Algorithm, PrivateKey},
    };

    use super::Client;

    #[tokio::test]
    async fn server_host_key_pinning_is_preserved() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let trusted = PrivateKey::random(&mut rng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone();
        let untrusted = PrivateKey::random(&mut rng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone();
        let mut client = Client {
            server_public_key: Some(vec![trusted.clone()]),
        };
        assert!(client.check_server_key(&trusted.into()).await.unwrap());
        assert!(matches!(
            client.check_server_key(&untrusted.clone().into()).await,
            Err(Error::UnknownKey)
        ));

        client.server_public_key = None;
        assert!(client.check_server_key(&untrusted.into()).await.unwrap());
    }
}
