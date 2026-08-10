use axum::response::IntoResponse;
use serde_json::json;

const VERSION: &str = env!("CLASH_VERSION_OVERRIDE");
const TARGET_TRIPLE: &str = env!("CLASH_TARGET_TRIPLE");
const TARGET_OS: &str = env!("CLASH_TARGET_OS");
const TARGET_ARCH: &str = env!("CLASH_TARGET_ARCH");
const FORK_AUTHOR: &str = env!("CLASH_FORK_AUTHOR");
const FEATURES: Option<&str> = option_env!("CLASH_FEATURES");

pub async fn handle() -> impl IntoResponse {
    let os = match TARGET_OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = match TARGET_ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" | "i686" => "386",
        other => other,
    };

    let features: Vec<&str> = match FEATURES {
        Some(f) if !f.is_empty() => f.split(", ").collect(),
        _ => Vec::new(),
    };

    axum::Json(json!({
        "version": VERSION,
        "author": FORK_AUTHOR,
        "meta": false,
        "os": os,
        "arch": arch,
        "target": TARGET_TRIPLE,
        "features": features,
    }))
}
