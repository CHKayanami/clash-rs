use quinn_jls::{RecvStream, SendStream};
use tokio::io::Join;

use crate::proxy::ProxyStream;

pub type ShadowQuicStream = Join<RecvStream, SendStream>;

impl ProxyStream for ShadowQuicStream {}
