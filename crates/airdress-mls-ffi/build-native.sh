#!/usr/bin/env bash
set -euo pipefail

# Build airdress-mls-ffi native libraries for Flutter platforms.
#
# Usage:
#   ./build-native.sh                    # build for host only
#   ./build-native.sh linux              # Linux x86_64
#   ./build-native.sh android            # all Android ABIs
#   ./build-native.sh ios                # iOS arm64 + simulator
#   ./build-native.sh all                # everything
#
# Output goes to ./build/<platform>/ with the library files ready
# to copy into the Flutter project's platform-specific native dirs.
#
# Each cross target is added to the pinned toolchain (rust-toolchain.toml)
# with `rustup target add` before it is built.
#
# Android needs the NDK: set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT, or
# ANDROID_NDK_LATEST_HOME as GitHub's runners do). The linker is the NDK's
# clang wrapper for ANDROID_API_LEVEL (default 21, the lowest API level the
# Rust Android targets support).
#
# iOS uses the static library, built with `cargo rustc --crate-type
# staticlib` so that no Apple linker is needed: it builds on Linux too.
# Linking it into the app happens in Xcode.

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CRATE_DIR/../.."  # workspace root: rustup resolves the pinned toolchain here

TARGETS="${1:-host}"
BUILD_DIR="$CRATE_DIR/build"
mkdir -p "$BUILD_DIR"

# The library file a target produces: the static library on iOS, the
# dynamic one everywhere else.
library_name() {
  case "$1" in
    *-apple-ios*)   echo "libairdress_mls_ffi.a" ;;
    *-apple-*)      echo "libairdress_mls_ffi.dylib" ;;
    *-windows-*)    echo "airdress_mls_ffi.dll" ;;
    *)              echo "libairdress_mls_ffi.so" ;;
  esac
}

host_triple() {
  rustc -vV | sed -n 's/^host: //p'
}

ndk_home() {
  local ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${ANDROID_NDK_LATEST_HOME:-}}}"
  if [[ -z "$ndk" || ! -d "$ndk" ]]; then
    echo "error: the Android NDK was not found." >&2
    echo "  Set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) to an NDK directory," >&2
    echo "  e.g. \$ANDROID_HOME/ndk/<version>." >&2
    exit 1
  fi
  echo "$ndk"
}

# Point cargo at the NDK's clang wrapper for one Android target.
configure_android_linker() {
  local target="$1"
  local ndk api host_tag clang_prefix
  ndk="$(ndk_home)"
  api="${ANDROID_API_LEVEL:-21}"
  case "$(uname -s)" in
    Linux)  host_tag="linux-x86_64" ;;
    Darwin) host_tag="darwin-x86_64" ;;  # the NDK ships x86_64-named on Apple Silicon too
    *)      echo "error: no Android NDK host tag for $(uname -s)" >&2; exit 1 ;;
  esac
  # The NDK names the 32-bit ARM wrapper armv7a, not armv7.
  case "$target" in
    armv7-linux-androideabi) clang_prefix="armv7a-linux-androideabi" ;;
    *)                       clang_prefix="$target" ;;
  esac

  local linker="$ndk/toolchains/llvm/prebuilt/$host_tag/bin/${clang_prefix}${api}-clang"
  if [[ ! -x "$linker" ]]; then
    echo "error: no NDK clang wrapper at $linker" >&2
    echo "  Check ANDROID_NDK_HOME and ANDROID_API_LEVEL ($api)." >&2
    exit 1
  fi

  local env_target
  env_target="$(echo "$target" | tr '[:lower:]-' '[:upper:]_')"
  export "CARGO_TARGET_${env_target}_LINKER=$linker"
  export "CC_${target//-/_}=$linker"
  export "AR_${target//-/_}=$ndk/toolchains/llvm/prebuilt/$host_tag/bin/llvm-ar"
}

build_target() {
  local target="$1"
  local output_dir="$2"
  echo "=== Building for $target ==="
  rustup target add "$target"

  case "$target" in
    *-android*) configure_android_linker "$target" ;;
  esac

  case "$target" in
    *-apple-ios*)
      cargo rustc -p airdress-mls-ffi --lib --release --locked \
        --target "$target" --crate-type staticlib
      ;;
    *)
      cargo build -p airdress-mls-ffi --release --locked --target "$target"
      ;;
  esac

  local src
  src="target/$target/release/$(library_name "$target")"
  if [[ ! -f "$src" ]]; then
    echo "error: the build for $target produced no $src" >&2
    exit 1
  fi
  mkdir -p "$output_dir"
  cp "$src" "$output_dir/"
  echo "  → $output_dir/$(basename "$src") ($(du -h "$src" | cut -f1))"
}

build_host() {
  build_target "$(host_triple)" "$BUILD_DIR/host"
}

build_linux() {
  build_target "x86_64-unknown-linux-gnu" "$BUILD_DIR/linux/x86_64"
}

build_android() {
  for target in \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android; do

    local abi
    case "$target" in
      aarch64-*)  abi="arm64-v8a" ;;
      armv7-*)    abi="armeabi-v7a" ;;
      x86_64-*)   abi="x86_64" ;;
      i686-*)     abi="x86" ;;
    esac

    build_target "$target" "$BUILD_DIR/android/jniLibs/$abi"
  done
}

build_ios() {
  build_target "aarch64-apple-ios" "$BUILD_DIR/ios/arm64"
  # Simulator (Apple Silicon)
  build_target "aarch64-apple-ios-sim" "$BUILD_DIR/ios/sim-arm64"
}

case "$TARGETS" in
  host)    build_host ;;
  linux)   build_linux ;;
  android) build_android ;;
  ios)     build_ios ;;
  all)     build_linux; build_android; build_ios ;;
  *)       echo "Usage: $0 {host|linux|android|ios|all}"; exit 1 ;;
esac

echo ""
echo "Build artifacts in $BUILD_DIR/"
ls -R "$BUILD_DIR/"
