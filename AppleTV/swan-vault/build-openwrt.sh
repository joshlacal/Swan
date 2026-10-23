#!/bin/sh
# Cross-build swan-vault as a static musl binary for an OpenWrt router.
# Needs: rustup target (added on first run), zig (brew install zig).
# Usage: ./build-openwrt.sh [aarch64|armv7|mipsel]   (default aarch64)
set -eu
cd "$(dirname "$0")"
arch="${1:-aarch64}"
case "$arch" in
  aarch64) target=aarch64-unknown-linux-musl;   zigtarget=aarch64-linux-musl ;;
  armv7)   target=armv7-unknown-linux-musleabihf; zigtarget=arm-linux-musleabihf ;;
  mipsel)  target=mipsel-unknown-linux-musl;    zigtarget=mipsel-linux-musl ;;
  *) echo "unknown arch $arch" >&2; exit 64 ;;
esac
rustup target add "$target" >/dev/null
wrapper="$(mktemp -d)/cc"
printf '#!/bin/sh\nexec zig cc -target %s "$@"\n' "$zigtarget" > "$wrapper"
chmod +x "$wrapper"
envname="CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')"
# zig ships its own CRT; Rust's self-contained musl CRT would define _start twice.
env "${envname}_LINKER=$wrapper" \
    "${envname}_RUSTFLAGS=-C link-self-contained=no -C target-feature=+crt-static" \
    cargo build --release --target "$target"
ls -la "target/$target/release/swan-vault"
