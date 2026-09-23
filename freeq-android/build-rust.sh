#!/bin/bash
set -euo pipefail

# Build the Rust SDK for Android targets and generate Kotlin bindings.
# Run from the repo root: ./freeq-android/build-rust.sh
#
# Prerequisites:
#   - Android NDK installed (set ANDROID_NDK_HOME or use default path)
#   - cargo-ndk: cargo install cargo-ndk
#   - Rust Android targets: rustup target add aarch64-linux-android x86_64-linux-android

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Prefer rustup-managed cargo/rustc over Homebrew (which lacks Android targets)
export PATH="$HOME/.cargo/bin:$PATH"
# If Homebrew rustc still wins, force rustup's rustc
if rustc --print sysroot 2>/dev/null | grep -q Cellar; then
    for tc in "$HOME/.rustup"/toolchains/stable-*; do
        if [ -x "$tc/bin/rustc" ]; then
            export RUSTC="$tc/bin/rustc"
            echo "==> Overriding Homebrew rustc with: $RUSTC"
            break
        fi
    done
fi

# Auto-detect NDK if not set
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    NDK_DIR="$HOME/Library/Android/sdk/ndk"
    if [ -d "$NDK_DIR" ]; then
        ANDROID_NDK_HOME="$(ls -d "$NDK_DIR"/*/ 2>/dev/null | sort -V | tail -1)"
        ANDROID_NDK_HOME="${ANDROID_NDK_HOME%/}"
        export ANDROID_NDK_HOME
        echo "==> Auto-detected NDK: $ANDROID_NDK_HOME"
    else
        echo "ERROR: Android NDK not found. Install via Android Studio SDK Manager."
        exit 1
    fi
fi

JNILIBS_DIR="freeq-android/freeq/src/main/jniLibs"
FFI_DIR="freeq-android/freeq/src/main/java/com/freeq/ffi"
GEN_DIR="freeq-android/Generated"

echo "==> Building for Android targets (arm64-v8a, x86_64)..."
cargo ndk \
    -t arm64-v8a \
    -t x86_64 \
    -o "$JNILIBS_DIR" \
    build -p freeq-sdk-ffi --lib --release --features logcat-trace

echo "==> Building host binary for bindgen..."
cargo build -p freeq-sdk-ffi --lib --release
cargo build -p freeq-sdk-ffi --bin uniffi-bindgen

echo "==> Generating Kotlin bindings..."
cargo run -p freeq-sdk-ffi --bin uniffi-bindgen -- generate \
    freeq-sdk-ffi/src/freeq.udl \
    --language kotlin \
    --config freeq-sdk-ffi/uniffi.toml \
    --out-dir "$GEN_DIR"

echo "==> Installing generated bindings..."
# Remove old stub files
rm -f "$FFI_DIR/FreeqClient.kt" "$FFI_DIR/FreeqTypes.kt" "$FFI_DIR/EventHandler.kt"

# Copy generated binding (UniFFI outputs to package path under out-dir)
mkdir -p "$FFI_DIR"
find "$GEN_DIR" -name "*.kt" -exec cp {} "$FFI_DIR/" \;

echo "==> Done!"
echo "    Native libs: $JNILIBS_DIR/{arm64-v8a,x86_64}/libfreeq_sdk_ffi.so"
echo "    Kotlin binding: $FFI_DIR/freeq.kt"
