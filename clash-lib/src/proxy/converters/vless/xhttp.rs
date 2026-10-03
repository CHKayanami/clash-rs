use std::collections::HashMap;
use crate::{
    Error,
    config::internal::proxy::{OutboundVless, XHttpDownloadSettings, XHttpOpt},
    proxy::transport::{TransportSecurity, XHttpClient},
};
use super::{security::build_security, super::utils::xhttp_client};

fn download_options(opts: &XHttpOpt, settings: &XHttpDownloadSettings, host: &str) -> XHttpOpt {
    let header_host = |headers: &Option<HashMap<String, String>>| {
        headers.as_ref().and_then(|headers| headers.iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host")).map(|(_, value)| value.clone()))
    };
    let mut download = opts.clone();
    download.download_settings = None;
    // GET-only endpoint: reuse packet-up metadata rules without stream-one validation.
    download.mode = Some("packet-up".into());
    download.path = settings.path.clone().or_else(|| opts.path.clone());
    download.headers = settings.headers.clone().or_else(|| opts.headers.clone());
    download.host = settings.host.clone().or_else(|| header_host(&settings.headers))
        .or_else(|| opts.host.clone()).or_else(|| header_host(&download.headers))
        .or_else(|| Some(host.to_owned()));
    download.reuse_settings = settings.reuse_settings.clone().or_else(|| opts.reuse_settings.clone());
    download
}

pub(super) fn build_xhttp(s: &OutboundVless) -> Result<XHttpClient, Error> {
    let empty = XHttpOpt::default();
    let opts = s.xhttp_opts.as_deref().unwrap_or(&empty);
    let mut client = xhttp_client(Some(opts), s.server_name.as_deref().unwrap_or(&s.common_opts.server),
        s.tls.unwrap_or_default() || s.reality_opts.is_some(), s.reality_opts.is_some(), s.alpn.as_deref())?;
    if let Some(settings) = &opts.download_settings {
        let mut download = s.clone();
        download.common_opts.server = settings.server.clone().unwrap_or_else(|| s.common_opts.server.clone());
        download.common_opts.port = settings.port.unwrap_or(s.common_opts.port);
        download.server_name = settings.server_name.clone().or_else(|| s.server_name.clone());
        download.alpn = settings.alpn.clone().or_else(|| s.alpn.clone());
        download.reality_opts = settings.reality_opts.clone().or_else(|| s.reality_opts.clone());
        download.tls = settings.tls.or(s.tls);
        if settings.tls == Some(false) && download.reality_opts.is_some() {
            return Err(Error::InvalidConfig("XHTTP download Reality requires TLS".into()));
        }
        download.skip_cert_verify = settings.skip_cert_verify.or(s.skip_cert_verify);
        download.client_fingerprint = settings.client_fingerprint.clone().or_else(|| s.client_fingerprint.clone());
        download.tls_cert = settings.certificate.clone().or_else(|| s.tls_cert.clone());
        download.tls_key = settings.private_key.clone().or_else(|| s.tls_key.clone());
        let download_opts = download_options(opts, settings,
            download.server_name.as_deref().unwrap_or(&download.common_opts.server));
        download.xhttp_opts = Some(Box::new(download_opts.clone()));
        let security = build_security(&download, settings.fingerprint.as_deref())?;
        let security = TransportSecurity::from_layer(security.as_ref()).map_err(|error| Error::InvalidConfig(error.to_string()))?;
        client.configure_download(&download_opts, download.common_opts.server, download.common_opts.port,
            security, download.alpn.as_deref()).map_err(|error| Error::InvalidConfig(error.to_string()))?;
    }
    Ok(client)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use super::{XHttpDownloadSettings, XHttpOpt, download_options};

    #[test]
    fn xhttp_download_host_respects_explicit_and_inherited_headers() {
        let mut parent = XHttpOpt {
            headers: Some(HashMap::from([("Host".into(), "upload.example".into())])),
            ..Default::default()
        };
        let mut settings = XHttpDownloadSettings::default();
        assert_eq!(download_options(&parent, &settings, "fallback.example").host.as_deref(), Some("upload.example"));
        parent.host = Some("explicit-upload.example".into());
        settings.headers = Some(HashMap::from([("hOsT".into(), "download.example".into())]));
        assert_eq!(download_options(&parent, &settings, "fallback.example").host.as_deref(), Some("download.example"));
        settings.host = Some("explicit-download.example".into());
        assert_eq!(download_options(&parent, &settings, "fallback.example").host.as_deref(), Some("explicit-download.example"));
        assert_eq!(download_options(&XHttpOpt::default(), &XHttpDownloadSettings::default(), "fallback.example")
            .host.as_deref(), Some("fallback.example"));
    }
}
