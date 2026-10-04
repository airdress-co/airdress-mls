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

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CRATE_DIR/../.."  # workspace root (this repository)

TARGETS="${1:-host}"
BUILD_DIR="$CRATE_DIR/build"
mkdir -p "$BUILD_DIR"

build_target() {
  local target="$1"
  local output_dir="$2"
  echo "=== Building for $target ==="
  cargo build -p airdress-mls-ffi --release --target "$target"
  mkdir -p "$output_dir"

  local ext
  case "$target" in
    *-linux-*)   ext="so" ;;
    *-apple-*)   ext="dylib" ;;
    *-windows-*) ext="dll" ;;
    *-android-*) ext="so" ;;
    *)           ext="so" ;;
  esac

  local src="target/$target/release/libairdress_mls_ffi.$ext"
  if [ ! -f "$src" ]; then
    src="target/$target/release/airdress_mls_ffi.$ext"
  fi
  cp "$src" "$output_dir/"
  echo "  → $output_dir/$(basename "$src") ($(du -h "$src" | cut -f1))"
}

build_host() {
  echo "=== Building for host ==="
  cargo build -p airdress-mls-ffi --release
  mkdir -p "$BUILD_DIR/host"
  cp target/release/libairdress_mls_ffi.* "$BUILD_DIR/host/" 2>/dev/null || true
  echo "  → $BUILD_DIR/host/"
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
  if rustup target list --installed | grep -q aarch64-apple-ios-sim; then
    build_target "aarch64-apple-ios-sim" "$BUILD_DIR/ios/sim-arm64"
  fi
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
