#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
output="${1:-/tmp/frp-encrypted-build}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
for assets in web/frpc/dist/index.html web/frps/dist/index.html; do
  if [[ ! -f "$assets" ]]; then
    echo "Missing dashboard assets: build both web workspaces first" >&2
    exit 1
  fi
done
revision="$(git rev-parse --short=12 HEAD)"
build_version="0.72.0+encrypted.1.${revision}"
dirty=false
if [[ -n "$(git status --porcelain)" ]]; then
  dirty=true
  build_version="${build_version}.dirty"
fi
for target in linux/amd64 darwin/arm64; do
  os="${target%/*}"
  arch="${target#*/}"
  package="frp-encrypted_${os}_${arch}"
  mkdir -p "$output/$package"
  for program in frps frpc; do
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build \
      -tags "$program" \
      -ldflags "-X github.com/fatedier/frp/pkg/util/version.version=$build_version" \
      -o "$output/$package/$program" "./cmd/$program"
  done
  cp LICENSE "$output/$package/LICENSE"
  cp doc/encrypted-config.md "$output/$package/README.md"
  printf 'version=%s\nsource=%s\ndirty=%s\n' "$build_version" "$(git rev-parse HEAD)" "$dirty" > "$output/$package/BUILD.txt"
  tar -czf "$output/$package.tar.gz" -C "$output" "$package"
done
cd "$output"
shasum -a 256 frp-encrypted_linux_amd64.tar.gz frp-encrypted_darwin_arm64.tar.gz > SHA256SUMS
echo "Built packages in $output"
