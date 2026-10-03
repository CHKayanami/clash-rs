use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::uri::InvalidUri;

use crate::{
    Error,
    config::proxy::{CommonConfigOptions, GrpcOpt, H2Opt, HttpOpt, WsOpt},
    proxy::transport::{self, GrpcClient, H2Client, HttpClient, WsClient},
};

impl TryFrom<(&WsOpt, &CommonConfigOptions)> for WsClient {
    type Error = std::io::Error;

    fn try_from(pair: (&WsOpt, &CommonConfigOptions)) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        let path = x.path.as_ref().map(|x| x.to_owned()).unwrap_or_default();
        let headers = x.headers.as_ref().map(|x| x.to_owned()).unwrap_or_default();
        let max_early_data = x.max_early_data.unwrap_or_default() as usize;
        let early_data_header_name = x
            .early_data_header_name
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or_default();

        let client = transport::WsClient::new(
            common.server.to_owned(),
            common.port,
            path,
            headers,
            None,
            max_early_data,
            early_data_header_name,
        );
        Ok(client)
    }
}

impl TryFrom<(Option<String>, &GrpcOpt, &CommonConfigOptions)> for GrpcClient {
    type Error = InvalidUri;

    fn try_from(
        opt: (Option<String>, &GrpcOpt, &CommonConfigOptions),
    ) -> Result<Self, Self::Error> {
        let (sni, x, common) = opt;
        let client = transport::GrpcClient::new(
            sni.as_ref().unwrap_or(&common.server).to_owned(),
            format!("/{}", x.grpc_service_name.as_deref().unwrap_or_default())
                .try_into()?,
        );
        Ok(client)
    }
}

impl TryFrom<(&H2Opt, &CommonConfigOptions)> for H2Client {
    type Error = InvalidUri;

    fn try_from(pair: (&H2Opt, &CommonConfigOptions)) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        let host = x
            .host
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or(vec![common.server.to_owned()]);
        let path = x
            .path
            .as_deref()
            .filter(|p| !p.is_empty())
            .unwrap_or("/");

        Ok(H2Client::new(
            host,
            std::collections::HashMap::new(),
            http::Method::GET,
            path.try_into()?,
        ))
    }
}

impl TryFrom<(&HttpOpt, &CommonConfigOptions)> for HttpClient {
    type Error = std::convert::Infallible;

    fn try_from(pair: (&HttpOpt, &CommonConfigOptions)) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        let host = x
            .headers
            .as_ref()
            .and_then(|h| h.get("Host").or_else(|| h.get("host")))
            .and_then(|hosts| hosts.first())
            .cloned()
            .unwrap_or_else(|| common.server.clone());

        let method = x
            .method
            .clone()
            .unwrap_or_else(|| "GET".to_string());

        let path = x
            .path
            .clone()
            .unwrap_or_else(|| vec!["/".to_string()]);

        let headers = x.headers.clone().unwrap_or_default();

        Ok(HttpClient::new(
            host,
            common.port,
            method,
            path,
            headers,
        ))
    }
}

pub fn decode_base64_public_key(base64_public_key: &str) -> Result<[u8; 32], Error> {
    URL_SAFE_NO_PAD
        .decode(base64_public_key)
        .map_err(|e| {
            Error::InvalidConfig(format!("reality public-key base64: {e}"))
        })?
        .try_into()
        .map_err(|_| {
            Error::InvalidConfig("reality public-key must decode to 32 bytes".into())
        })
}

pub fn decode_short_id(hex_short_id: &str) -> Result<[u8; 8], Error> {
    if hex_short_id.len() > 16 {
        return Err(Error::InvalidConfig(
            "reality short-id must contain at most 8 bytes".into(),
        ));
    }
    let mut short_id = [0; 8];
    hex::decode_to_slice(hex_short_id, &mut short_id[..hex_short_id.len() / 2])
        .map_err(|e| Error::InvalidConfig(format!("reality short-id hex: {e}")))?;
    Ok(short_id)
}

#[cfg(test)]
mod reality_tests {
    use super::{decode_base64_public_key, decode_short_id};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn reality_short_id_validates_length_and_pads_with_zeroes() {
        assert_eq!(decode_short_id("").unwrap(), [0; 8]);
        assert_eq!(decode_short_id("01020304").unwrap(), [1, 2, 3, 4, 0, 0, 0, 0]);
        assert_eq!(decode_short_id("0102030405060708").unwrap(), [1, 2, 3, 4, 5, 6, 7, 8]);
        for invalid in ["123", "gg", "010203040506070809", "é"] {
            assert!(decode_short_id(invalid).is_err());
        }
    }

    #[test]
    fn reality_public_key_requires_32_decoded_bytes() {
        assert_eq!(decode_base64_public_key(&URL_SAFE_NO_PAD.encode([42; 32])).unwrap(), [42; 32]);
        for invalid in ["invalid".to_owned(), URL_SAFE_NO_PAD.encode([42; 31]),
            URL_SAFE_NO_PAD.encode([42; 33])] {
            assert!(decode_base64_public_key(&invalid).is_err());
        }
    }
}
