use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_crate = manifest_dir.join("../clash-ebpf-bpf");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("clash-ebpf.o");

    println!("cargo:rerun-if-changed={}", ebpf_crate.join("src").display());
    println!("cargo:rerun-if-changed={}", ebpf_crate.join("Cargo.toml").display());
    println!("cargo:rerun-if-changed={}", manifest_dir.join("../clash-ebpf-common").display());

    let profile = std::env::var("PROFILE").expect("Cargo did not set PROFILE");
    let bpf_target = manifest_dir.join("../target/bpfel-unknown-none");
    let mut candidates = vec![bpf_target.join(&profile).join("clash-ebpf-bpf")];
    if profile != "release" {
        candidates.push(bpf_target.join("release/clash-ebpf-bpf"));
    }
    for candidate in &candidates {
        println!("cargo:rerun-if-changed={}", candidate.display());
    }

    let target_obj = candidates.iter().find(|path| {
        path.metadata().is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
    }).unwrap_or_else(|| {
        let searched = candidates.iter().map(|path| path.display().to_string())
            .collect::<Vec<_>>().join("\n  ");
        panic!(
            "eBPF binary not found or empty. Searched:\n  {searched}\n\
             Build it first: cd clash-ebpf-bpf && cargo +nightly build --release \
             -Zbuild-std=core --target bpfel-unknown-none"
        );
    });
    let size = target_obj.metadata().expect("Failed to stat eBPF binary").len();
    std::fs::copy(target_obj, &dest).expect("Failed to copy built eBPF binary");
    println!(
        "cargo:warning=Successfully embedded eBPF object from {} ({} bytes)",
        target_obj.display(),
        size
    );

    println!("cargo:rustc-env=CLASH_EBPF_OBJECT={}", dest.display());
}
