use base64::{Engine, engine::general_purpose::STANDARD};
use clash_shadowsocks::config::ServerUser;

#[test]
fn user_debug_redacts_authentication_key() {
    let key = vec![7_u8; 32];
    let user = ServerUser::new("synthetic-user", key.clone());
    let output = format!("{user:?}");
    assert!(output.contains("synthetic-user"));
    assert!(!output.contains(&STANDARD.encode(&key)));
    assert!(!output.contains(&format!("{key:?}")));
}
