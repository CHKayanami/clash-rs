use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_crate = manifest_dir.join("../clash-ebpf-bpf");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("clash-ebpf.o");

    println!("cargo:rerun-if-changed={}", ebpf_crate.join("src").display());
    println!("cargo:rerun-if-changed={}", ebpf_crate.join("Cargo.toml").display());
    println!("cargo:rerun-if-changed={}", manifest_dir.join("../clash-ebpf-common").display());

    let candidates = [
        ebpf_crate.join("target/bpfel-unknown-none/release/clash-ebpf-bpf"),
        manifest_dir.join("../target/bpfel-unknown-none/release/clash-ebpf-bpf"),
    ];

    let found = candidates.iter().find(|p| p.exists() && p.metadata().map(|m| m.len()).unwrap_or(0) > 0);

    if let Some(target_obj) = found {
        let size = target_obj.metadata().map(|m| m.len()).unwrap_or(0);
        std::fs::copy(target_obj, &dest).expect("Failed to copy built eBPF binary");
        println!(
            "cargo:warning=Successfully embedded eBPF object from {} ({} bytes)",
            target_obj.display(),
            size
        );
    } else {
        panic!(
            "cargo:error=eBPF binary not found! Please build it first: cd clash-ebpf-bpf && cargo +nightly build --release -Zbuild-std=core --target bpfel-unknown-none"
        );
    }

    println!("cargo:rustc-env=CLASH_EBPF_OBJECT={}", dest.display());
}
