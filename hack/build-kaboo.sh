#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
output="${1:-/tmp/kaboo-build}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
revision="$(git rev-parse --short=12 HEAD)"
version="0.1.0+${revision}"
dirty=false
if [[ -n "$(git status --porcelain)" ]]; then dirty=true; version="${version}.dirty"; fi
for target in linux/amd64 darwin/arm64; do
  target_os="${target%/*}"
  target_arch="${target#*/}"
  package="kaboo_${target_os}_${target_arch}"
  mkdir -p "$output/$package"
  for role in server cli; do
    tag=frps
    if [[ "$role" == cli ]]; then tag=frpc; fi
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build \
      -tags "$tag,noweb" \
      -ldflags "-X github.com/fatedier/frp/pkg/kaboo.BuildVersion=$version -X github.com/fatedier/frp/pkg/kaboo.BuildCommit=$(git rev-parse HEAD)" \
      -o "$output/$package/kaboo-$role" "./cmd/kaboo-$role"
  done
  cp LICENSE "$output/$package/LICENSE"
  cp doc/kaboo.md "$output/$package/README.md"
  cp doc/kaboo-third-party.md "$output/$package/THIRD-PARTY.md"
  printf 'version=%s\nsource=%s\ndirty=%s\nrepository=https://github.com/morefreefg/frp\n' "$version" "$(git rev-parse HEAD)" "$dirty" > "$output/$package/BUILD.txt"
  tar -czf "$output/$package.tar.gz" -C "$output" "$package"
done
cd "$output"
shasum -a 256 kaboo_linux_amd64.tar.gz kaboo_darwin_arm64.tar.gz > SHA256SUMS
echo "Built public Kaboo programs in $output (private deployment files are not packaged)"
