// Unix restart uses exec() in-place (preserving the child PID and handle);
// Windows spawns a replacement process and exits the parent, so same-PID
// assertions and single-handle cleanup only apply on Unix.
#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "clash-rs-e2e-{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config_yaml(api_port: u16, socks_port: u16, allow_lan: bool) -> String {
    format!(
        "bind-address: 127.0.0.1\nsocks-port: {socks_port}\nexternal-controller: 127.0.0.1:{api_port}\nsecret: test-secret\nmode: direct\nallow-lan: {allow_lan}\ntun:\n  enable: false\n"
    )
}

fn http_request(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let payload = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer test-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let (head, resp_body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp_body.to_string())
}

fn wait_for_configs(port: u16, expected_substring: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let req = format!(
                "GET /configs HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n"
            );
            if stream.write_all(req.as_bytes()).is_ok() {
                let mut raw = String::new();
                if stream.read_to_string(&mut raw).is_ok()
                    && let Some((_, body)) = raw.split_once("\r\n\r\n")
                    && body.contains(expected_substring)
                {
                    return body.to_string();
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for GET /configs on port {port} containing {expected_substring:?}");
}

fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = body.find(&needle)? + needle.len();
    let end = body[start..].find('"')?;
    Some(body[start..start + end].to_string())
}

#[test]
fn put_configs_returns_501_and_post_restart_reloads_edited_file() {
    let work = TempDir::new("restart");
    let conf_dir = work.path().join("conf");
    fs::create_dir_all(&conf_dir).unwrap();

    let api_port = free_port();
    let socks_port = free_port();
    let config_file = conf_dir.join("config.yaml");
    fs::write(&config_file, config_yaml(api_port, socks_port, true)).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_clash-rs"))
        .current_dir(work.path())
        .args(["-d", "conf", "-c", "config.yaml", "--log-file=-review.log"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut guard = ChildGuard(child);

    wait_for_configs(api_port, "\"allow-lan\":true", Duration::from_secs(10));
    let (status, ver_before) = http_request(api_port, "GET", "/version", None);
    assert_eq!(status, 200, "GET /version failed: {ver_before}");
    let old_instance_id = extract_json_string(&ver_before, "instance_id")
        .expect("GET /version should include instance_id");

    let (status, body) = http_request(api_port, "PUT", "/configs", Some(r#"{"path":""}"#));
    assert_eq!(status, 501, "PUT /configs should return 501: {body}");

    // Edit config on disk, then trigger graceful process restart via POST /restart.
    fs::write(&config_file, config_yaml(api_port, socks_port, false)).unwrap();
    let (status, body) = http_request(api_port, "POST", "/restart", None);
    assert_eq!(status, 200, "POST /restart failed: {body}");
    assert_eq!(
        extract_json_string(&body, "instance_id").as_deref(),
        Some(old_instance_id.as_str()),
        "POST /restart should report the retiring instance_id: {body}"
    );

    wait_for_configs(api_port, "\"allow-lan\":false", Duration::from_secs(10));
    let (status, ver_after) = http_request(api_port, "GET", "/version", None);
    assert_eq!(status, 200, "GET /version after restart failed: {ver_after}");
    let new_instance_id = extract_json_string(&ver_after, "instance_id")
        .expect("GET /version after restart should include instance_id");
    assert_ne!(
        new_instance_id, old_instance_id,
        "restarted instance should generate a fresh instance_id"
    );
    assert!(
        conf_dir.join("-review.log").exists(),
        "log file passed via --log-file=-review.log should be preserved across restart"
    );
    assert!(
        guard.0.try_wait().unwrap().is_none(),
        "restarted process should remain alive"
    );
}

#[test]
fn sigterm_during_log_drain_cancels_restart() {
    let work = TempDir::new("restart-sigterm");
    let api_port = free_port();
    fs::write(
        work.path().join("config.yaml"),
        format!(
            "external-controller: 127.0.0.1:{api_port}\nsecret: test-secret\nmode: direct\n"
        ),
    )
    .unwrap();

    // Leave stdout unread so the log worker is still draining after the API closes.
    let child = Command::new(env!("CARGO_BIN_EXE_clash-rs"))
        .arg("-d")
        .arg(work.path())
        .env("RUST_LOG", "info,tower_http=trace")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut guard = ChildGuard(child);
    wait_for_configs(api_port, "\"mode\":\"direct\"", Duration::from_secs(10));
    for _ in 0..250 {
        assert_eq!(http_request(api_port, "GET", "/version", None).0, 200);
    }
    assert_eq!(http_request(api_port, "POST", "/restart", None).0, 200);

    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", api_port)).is_ok() {
        assert!(Instant::now() < deadline, "old API did not close");
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(50));
    assert!(guard.0.try_wait().unwrap().is_none());
    assert!(Command::new("kill")
        .arg("-TERM")
        .arg(guard.0.id().to_string())
        .status()
        .unwrap()
        .success());

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = guard.0.try_wait().unwrap() {
            assert!(status.success(), "process should exit cleanly: {status}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "process did not stop after SIGTERM during restart"
        );
        thread::sleep(Duration::from_millis(20));
    }
}
