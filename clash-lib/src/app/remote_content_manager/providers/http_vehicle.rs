use super::{ProviderVehicle, ProviderVehicleType};
use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::{
        errors::map_io_error,
        http::{HttpClient, new_http_client},
    },
};

use async_trait::async_trait;

use http_body_util::BodyExt;
use hyper::Uri;
use tracing::debug;

use std::io;

use crate::common::http::DEFAULT_USER_AGENT;
use http::Request;
use std::path::{Path, PathBuf};

pub struct Vehicle {
    pub url: Uri,
    pub path: PathBuf,
    http_client: HttpClient,
}

impl Vehicle {
    pub fn new<T: Into<Uri>, P: AsRef<Path>>(
        url: T,
        path: P,
        cwd: Option<P>,
        dns_resolver: ThreadSafeDNSResolver,
    ) -> Self {
        // TODO(dev0): support remote content manager via proxy
        let client = new_http_client(dns_resolver, None)
            .expect("failed to create http client");
        Self {
            url: url.into(),
            path: match cwd {
                Some(cwd) => cwd.as_ref().join(path),
                None => path.as_ref().to_path_buf(),
            },
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
            req.headers_mut().insert(
                http::header::USER_AGENT,
                DEFAULT_USER_AGENT.parse().expect("must parse user agent"),
            );
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
                    .get(http::header::LOCATION)
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
        let v = super::Vehicle::new(u, p, None, r.clone() as ThreadSafeDNSResolver);

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
        let v = super::Vehicle::new(u, p, None, r.clone() as ThreadSafeDNSResolver);

        let data = v.read().await.unwrap();
        mock_redirect.assert();
        mock_target.assert();
        assert_eq!(str::from_utf8(&data).unwrap(), "redirect success");
    }
}
