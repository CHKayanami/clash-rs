fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Watch both CLASH_* and GitHub-provided env vars so rebuilds trigger correctly
    let vars = ["CLASH_GIT_REF", "CLASH_GIT_SHA", "GITHUB_REF", "GITHUB_SHA"];
    for var in vars {
        println!("cargo:rerun-if-env-changed={var}");
    }

    // Prefer explicit CLASH_* vars; fall back to GITHUB_* which are set by GitHub
    // Actions. Use std::env::var_os to read at runtime, not option_env! at compile
    // time.
    let git_ref = std::env::var_os("CLASH_GIT_REF")
        .or_else(|| std::env::var_os("GITHUB_REF"))
        .and_then(|v| v.into_string().ok());
    let git_sha = std::env::var_os("CLASH_GIT_SHA")
        .or_else(|| std::env::var_os("GITHUB_SHA"))
        .and_then(|v| v.into_string().ok());

    let version = match (git_ref.as_deref(), git_sha.as_deref()) {
        (Some("refs/heads/master"), Some(sha)) => {
            let short_sha = &sha[..7.min(sha.len())];
            // Nightly release below
            format!("{}-alpha+sha.{short_sha}", env!("CARGO_PKG_VERSION"))
        }
        _ => env!("CARGO_PKG_VERSION").into(),
    };
    println!("cargo:rustc-env=CLASH_VERSION_OVERRIDE={version}");

    let target = std::env::var("TARGET").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    println!("cargo:rustc-env=CLASH_TARGET_TRIPLE={target}");
    println!("cargo:rustc-env=CLASH_TARGET_OS={target_os}");
    println!("cargo:rustc-env=CLASH_TARGET_ARCH={target_arch}");
    println!("cargo:rustc-env=CLASH_FORK_AUTHOR=ala");

    let features = std::env::var("CARGO_CFG_FEATURE").unwrap_or_default();
    let mut feature_list: Vec<&str> = features.split(',').filter(|s| !s.is_empty()).collect();
    feature_list.sort();
    let features_str = feature_list.join(", ");
    println!("cargo:rustc-env=CLASH_FEATURES={features_str}");
}

