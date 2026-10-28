#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an Android NDK installation}"
command -v cargo-ndk >/dev/null || { echo "Install cargo-ndk: cargo install cargo-ndk --version 4.1.2 --locked" >&2; exit 1; }
if [ "$#" -eq 0 ]; then set -- arm64-v8a; fi
args=()
for abi in "$@"; do
    case "$abi" in
        arm64-v8a) rustup target add aarch64-linux-android ;;
        x86_64) rustup target add x86_64-linux-android ;;
        *) echo "Unsupported Android ABI: $abi" >&2; exit 1 ;;
    esac
    args+=(-t "$abi")
done
cargo ndk "${args[@]}" --platform 26 --link-libcxx-shared -o target/android/jniLibs build \
    -p clash-ffi --release --locked --features clash-lib/standard,clash-lib/tun
