use super::{ProviderVehicle, ProviderVehicleType};
use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::{
        errors::map_io_error,
        http::{ClashHTTPClientExt, HttpClient, DEFAULT_USER_AGENT, new_http_client},
    },
    proxy::utils::OutboundHandlerRegistry,
};

use async_trait::async_trait;

use http::{
    Request,
    header::{HeaderName, HeaderValue, LOCATION, USER_AGENT},
};
use http_body_util::BodyExt;
use hyper::Uri;
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
};
use tracing::{debug, warn};

pub struct Vehicle {
    pub url: Uri,
    pub path: PathBuf,
    pub outbound: Option<String>,
    pub headers: Option<HashMap<String, Vec<String>>>,
    http_client: HttpClient,
}

impl Vehicle {
    pub fn new<T: Into<Uri>, P: AsRef<Path>>(
        url: T,
        path: P,
        cwd: Option<P>,
        dns_resolver: ThreadSafeDNSResolver,
        outbound: Option<String>,
        outbounds: Option<OutboundHandlerRegistry>,
        headers: Option<HashMap<String, Vec<String>>>,
    ) -> Self {
        let client = new_http_client(dns_resolver, outbounds)
            .expect("failed to create http client");
        let uri = url.into();
        let path_ref = path.as_ref();
        let path_buf = if path_ref.as_os_str().is_empty() {
            let md5 = crate::common::utils::md5_str(uri.to_string().as_bytes());
            PathBuf::from(format!("cache/{md5}"))
        } else {
            path_ref.to_path_buf()
        };
        Self {
            url: uri,
            path: match cwd {
                Some(cwd) => cwd.as_ref().join(path_buf),
                None => path_buf,
            },
            outbound,
            headers,
            http_client: client,
        }
    }
}

#[async_trait]
impl ProviderVehicle for Vehicle {
    async fn read(&self) -> std::io::Result<Vec<u8>> {
        let mut current_uri = self.url.clone();
        let mut max_redirects = 10;

        loop {
            let mut req = Request::default();
            let mut has_user_agent = false;
            if let Some(headers) = &self.headers {
                for (key, values) in headers {
                    match HeaderName::from_bytes(key.as_bytes()) {
                        Ok(header_name) => {
                            if header_name == USER_AGENT {
                                has_user_agent = true;
                            }
                            for val in values {
                                match HeaderValue::from_str(val) {
                                    Ok(header_val) => {
                                        req.headers_mut().append(header_name.clone(), header_val);
                                    }
                                    Err(e) => {
                                        warn!(
                                            "invalid header value for {key}: {val}, error: {e}"
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("invalid header name: {key}, error: {e}");
                        }
                    }
                }
            }
            if !has_user_agent {
                req.headers_mut().insert(
                    USER_AGENT,
                    DEFAULT_USER_AGENT.parse().expect("must parse user agent"),
                );
            }
            if let Some(outbound) = &self.outbound {
                req.extensions_mut().insert(ClashHTTPClientExt {
                    outbound: Some(outbound.clone()),
                });
            }
            *req.body_mut() = http_body_util::Empty::<bytes::Bytes>::new();
            *req.uri_mut() = current_uri.clone();

            let res = self
                .http_client
                .request(req)
                .await
                .map_err(|x| io::Error::other(x.to_string()))?;

            let status = res.status();
            if status.is_redirection() {
                if max_redirects == 0 {
                    return Err(io::Error::other("too many redirects"));
                }
                max_redirects -= 1;

                let location = res
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| {
                        io::Error::other(format!(
                            "redirect response ({status}) missing Location header"
                        ))
                    })?
                    .to_str()
                    .map_err(|e| io::Error::other(e.to_string()))?;

                let base_url = url::Url::parse(&current_uri.to_string())
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let redirected_url = base_url
                    .join(location)
                    .map_err(|e| io::Error::other(e.to_string()))?;

                current_uri = redirected_url
                    .as_str()
                    .parse::<Uri>()
                    .map_err(|e| io::Error::other(e.to_string()))?;

                debug!("HttpVehicle redirecting to {}", current_uri);
                continue;
            }

            if !status.is_success() {
                return Err(io::Error::other(format!(
                    "HTTP request failed with status: {}",
                    status
                )));
            }

            return res
                .into_body()
                .collect()
                .await
                .map(|x| x.to_bytes().to_vec())
                .map_err(map_io_error);
        }
    }

    fn path(&self) -> &str {
        self.path.to_str().unwrap()
    }

    fn typ(&self) -> ProviderVehicleType {
        ProviderVehicleType::Http
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderVehicle;
    use crate::{
        app::dns::{EnhancedResolver, ThreadSafeDNSResolver},
        tests::initialize,
    };
    use httpmock::{Method::GET, MockServer};
    use hyper::Uri;
    use std::{str, sync::Arc};

    #[tokio::test]
    async fn test_http_vehicle() {
        initialize();
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/test_http_vehicle");
            then.status(200)
                .header("content-type", "text/html; charset=UTF-8")
                .body("HTTPBIN is awesome");
        });
        let u = server.url("/test_http_vehicle").parse::<Uri>().unwrap();
        let p = std::env::temp_dir().join("test_http_vehicle");
        let r = Arc::new(EnhancedResolver::new_default().await);
        let v = super::Vehicle::new(
            u,
            p,
            None,
            r.clone() as ThreadSafeDNSResolver,
            None,
            None,
            None,
        );

        let data = v.read().await.unwrap();
        mock.assert();
        assert_eq!(str::from_utf8(&data).unwrap(), "HTTPBIN is awesome");
    }

    #[tokio::test]
    async fn test_http_vehicle_redirect() {
        initialize();
        let server = MockServer::start();
        let mock_redirect = server.mock(|when, then| {
            when.method(GET).path("/redirect");
            then.status(302).header("location", "/target");
        });
        let mock_target = server.mock(|when, then| {
            when.method(GET).path("/target");
            then.status(200).body("redirect success");
        });

        let u = server.url("/redirect").parse::<Uri>().unwrap();
        let p = std::env::temp_dir().join("test_http_vehicle_redirect");
        let r = Arc::new(EnhancedResolver::new_default().await);
        let v = super::Vehicle::new(
            u,
            p,
            None,
            r.clone() as ThreadSafeDNSResolver,
            None,
            None,
            None,
        );

        let data = v.read().await.unwrap();
        mock_redirect.assert();
        mock_target.assert();
        assert_eq!(str::from_utf8(&data).unwrap(), "redirect success");
    }

    #[tokio::test]
    async fn test_http_vehicle_empty_path() {
        initialize();
        let u = "http://example.com/test".parse::<Uri>().unwrap();
        let r = Arc::new(EnhancedResolver::new_default().await);
        let v = super::Vehicle::new(
            u.clone(),
            "",
            None,
            r.clone() as ThreadSafeDNSResolver,
            None,
            None,
            None,
        );
        let expected_md5 = crate::common::utils::md5_str(u.to_string().as_bytes());
        assert_eq!(v.path(), format!("cache/{expected_md5}"));
    }

    #[tokio::test]
    async fn test_http_vehicle_with_proxy() {
        initialize();
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/test_proxy_vehicle");
            then.status(200).body("proxied success");
        });

        let u = server.url("/test_proxy_vehicle").parse::<Uri>().unwrap();
        let p = std::env::temp_dir().join("test_proxy_vehicle");
        let r = Arc::new(EnhancedResolver::new_default().await);

        let mut registry_map = std::collections::HashMap::new();
        let direct_handler = Arc::new(crate::proxy::direct::Handler::new("my-proxy"))
            as crate::proxy::AnyOutboundHandler;
        registry_map.insert("my-proxy".to_string(), direct_handler);
        let registry = Arc::new(parking_lot::RwLock::new(registry_map));

        let v = super::Vehicle::new(
            u,
            p,
            None,
            r.clone() as ThreadSafeDNSResolver,
            Some("my-proxy".to_string()),
            Some(registry),
            None,
        );

        let data = v.read().await.unwrap();
        mock.assert();
        assert_eq!(str::from_utf8(&data).unwrap(), "proxied success");
    }

    #[tokio::test]
    async fn test_http_vehicle_custom_headers() {
        initialize();
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/test_headers")
                .header("authorization", "Bearer token123")
                .header("x-custom-key", "custom-val")
                .header("user-agent", crate::common::http::DEFAULT_USER_AGENT);
            then.status(200).body("headers ok");
        });

        let u = server.url("/test_headers").parse::<Uri>().unwrap();
        let p = std::env::temp_dir().join("test_headers");
        let r = Arc::new(EnhancedResolver::new_default().await);

        let mut headers = std::collections::HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            vec!["Bearer token123".to_string()],
        );
        headers.insert(
            "X-Custom-Key".to_string(),
            vec!["custom-val".to_string()],
        );

        let v = super::Vehicle::new(
            u,
            p,
            None,
            r.clone() as ThreadSafeDNSResolver,
            None,
            None,
            Some(headers),
        );

        let data = v.read().await.unwrap();
        mock.assert();
        assert_eq!(str::from_utf8(&data).unwrap(), "headers ok");
    }

    #[tokio::test]
    async fn test_http_vehicle_custom_user_agent() {
        initialize();
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/test_custom_ua")
                .header("user-agent", "MyCustomAgent/1.0");
            then.status(200).body("ua ok");
        });

        let u = server.url("/test_custom_ua").parse::<Uri>().unwrap();
        let p = std::env::temp_dir().join("test_custom_ua");
        let r = Arc::new(EnhancedResolver::new_default().await);

        let mut headers = std::collections::HashMap::new();
        headers.insert(
            "User-Agent".to_string(),
            vec!["MyCustomAgent/1.0".to_string()],
        );

        let v = super::Vehicle::new(
            u,
            p,
            None,
            r.clone() as ThreadSafeDNSResolver,
            None,
            None,
            Some(headers),
        );

        let data = v.read().await.unwrap();
        mock.assert();
        assert_eq!(str::from_utf8(&data).unwrap(), "ua ok");
    }
}

