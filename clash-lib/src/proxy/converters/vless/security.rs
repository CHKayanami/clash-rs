use crate::{
    Error,
    config::internal::proxy::OutboundVless,
    proxy::transport::{RealityClient, TlsClient, TransportLayer},
};
use super::super::utils::{decode_base64_public_key, decode_short_id, xhttp_alpn};

pub(super) fn build_security(s: &OutboundVless, fingerprint: Option<&str>) -> Result<Option<TransportLayer>, Error> {
    let tls = if let Some(ref reality_opts) = s.reality_opts
    {
        // vless with reality

        // reality public-key bytes
        let pk_bytes =
            decode_base64_public_key(&reality_opts.public_key)?;

        // reality short id bytes
        let short_id = decode_short_id(
            reality_opts.short_id.as_deref().unwrap_or_default(),
        )?;

        // SNI
        let sni = s
            .server_name
            .clone()
            .unwrap_or_else(|| s.common_opts.server.clone());

        let chrome = match s.client_fingerprint.as_deref() {
            Some(fp) => {
                let fp_lower = fp.trim().to_ascii_lowercase();
                fp_lower != "none"
            }
            None => true,
        };

        Some(TransportLayer::Reality(RealityClient::new(
            sni, pk_bytes, short_id, chrome,
            if s.network.as_deref() == Some("xhttp") {
                Some(xhttp_alpn(s.xhttp_opts.as_deref(), s.alpn.as_ref(), true)?)
            } else { s.alpn.clone() },
        )?))
    } else {
        // vless without reality
        match s.tls.unwrap_or_default() {
            true => {
                let client = TlsClient::new_advanced(
                    s.skip_cert_verify.unwrap_or_default(),
                    s.server_name.as_ref().map(|x| x.to_owned()).unwrap_or(
                        s.ws_opts
                            .as_ref()
                            .and_then(|x| {
                                x.headers.clone().and_then(|x| {
                                    let h = x.get("Host");
                                    h.cloned()
                                })
                            })
                            .unwrap_or(s.common_opts.server.to_owned()),
                    ),
                    if s.network.as_deref() == Some("xhttp") {
                        Some(xhttp_alpn(s.xhttp_opts.as_deref(), s.alpn.as_ref(), false)?)
                    } else { match &s.alpn {
                        Some(alpn) => Some(alpn.clone()),
                        None => s
                            .network
                            .as_ref()
                            .map(|x| match x.as_str() {
                                "tcp" | "raw" => Ok(vec![]),
                                "ws" | "http" => Ok(vec!["http/1.1".to_owned()]),
                                "h2" | "grpc" => Ok(vec!["h2".to_owned()]),
                                _ => Err(Error::InvalidConfig(format!(
                                    "unsupported network: {x}"
                                ))),
                            })
                            .transpose()?,
                    } },
                    None,
                    fingerprint,
                    s.client_fingerprint.as_deref(),
                    s.tls_cert.as_deref(),
                    s.tls_key.as_deref(),
                )?;
                Some(TransportLayer::Tls(client))
            }
            false => None,
        }
    };

    Ok(tls)
}
