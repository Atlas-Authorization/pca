#!/usr/bin/env bash
# Reproducible build of wasm/less_cat1.wasm from the PATCHED LESS reference vendored in sdks/pca-less-c (Atlas-Authorization/LESS,
# branch atlas-verifier-hardening, commit 0b8b9a07: upstream less-sig/LESS 6383430 plus the three verifier fixes; see
# sdks/pca-less-c/README.md) and the randomness / flat-buffer seam scripts/less_wasm_glue.c.
#
#   packages/pca-less-wasm/scripts/build-wasm.sh [out_dir]      (default: <repo>/packages/pca-less-wasm/wasm)
#
# Toolchain: wasi-sdk 25.0 (clang 19.1.5-wasi-sdk), the release the loader was written for (a wasm32-wasi reactor whose only
# host import is wasi_snapshot_preview1.random_get). The release tarball for this host (x86_64 Linux or arm64 macOS) is
# downloaded once into $WASI_SDK_CACHE (default ~/.cache/pca-wasi-sdk) and checked against the SHA-256 pinned below before
# anything in it runs. The sources are checked against SOURCES_SHA256 (the vendored tree as built and recorded in
# wasm/BUILD.json), so a build from a modified tree is refused unless ALLOW_SOURCE_CHANGE=1 (then record the new digest).
# Output: <out_dir>/less_cat1.wasm and <out_dir>/BUILD.json (toolchain, source digest, wasm SHA-256). The same inputs give the
# same bytes on both hosts (checked: see wasm/BUILD.json `reproduced_on`).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
pkg="$(cd "$here/.." && pwd)"
repo="$(cd "$pkg/../.." && pwd)"
src="${LESS_SRC:-$repo/sdks/pca-less-c}"  # LESS_SRC: another tree with lib/ and include/ (only with ALLOW_SOURCE_CHANGE=1)
out="${1:-$pkg/wasm}"
mkdir -p "$out"; out="$(cd "$out" && pwd)"

WASI_SDK_VER=25
SOURCES_SHA256="2304832390bfb2688e14471a2b7089465f48473207deb2279a089288c7ba9b8e"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) tarball="wasi-sdk-25.0-x86_64-linux.tar.gz"; tar_sha="52640dde13599bf127a95499e61d6d640256119456d1af8897ab6725bcf3d89c" ;;
  Darwin-arm64) tarball="wasi-sdk-25.0-arm64-macos.tar.gz"; tar_sha="e1e529ea226b1db0b430327809deae9246b580fa3cae32d31c82dfe770233587" ;;
  *) echo "build-wasm: unsupported host $(uname -s)-$(uname -m) (x86_64 Linux or arm64 macOS)" >&2; exit 2 ;;
esac
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

# ---- toolchain (pinned, hash-checked)
cache="${WASI_SDK_CACHE:-$HOME/.cache/pca-wasi-sdk}"
mkdir -p "$cache"
sdk="$cache/${tarball%.tar.gz}"
if [ ! -x "$sdk/bin/clang" ]; then
  dl="$cache/dl-$$"; mkdir -p "$dl"
  curl -fsSL --retry 3 -o "$dl/$tarball" "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-$WASI_SDK_VER/$tarball"
  got="$(sha256 "$dl/$tarball" | cut -d' ' -f1)"
  [ "$got" = "$tar_sha" ] || { echo "build-wasm: $tarball sha256 $got != pinned $tar_sha" >&2; rm -rf "$dl"; exit 1; }
  tar -xzf "$dl/$tarball" -C "$dl"
  rm -rf "$sdk"; mv "$dl/${tarball%.tar.gz}" "$sdk"; rm -rf "$dl"
fi
cc="$sdk/bin/clang"
sysroot="$sdk/share/wasi-sysroot"

# ---- sources (vendored, digest-checked)
srcs=(codes fips202 keccakf1600 LESS monomial rng seedtree sign utils sort canonical transpose)
files=(); for f in "${srcs[@]}"; do files+=("lib/$f.c"); done
for h in "$src"/include/*.h; do files+=("include/$(basename "$h")"); done
digest="$( (cd "$src" && for f in "${files[@]}"; do sha256 "$f"; done; cd "$here" && sha256 less_wasm_glue.c) | sha256 | cut -d' ' -f1)"
if [ "$SOURCES_SHA256" != "$digest" ] && [ "${ALLOW_SOURCE_CHANGE:-0}" != 1 ]; then
  echo "build-wasm: source digest $digest != recorded $SOURCES_SHA256 (set ALLOW_SOURCE_CHANGE=1 for a deliberate change)" >&2
  exit 1
fi

# ---- compile + link (portable scalar C: no SIMD defines; 8 MiB stack for the on-stack matrices)
wasm="$out/less_cat1.wasm"
exports=(less_autoseed less_seed less_keypair less_sign less_open less_public_key_bytes less_secret_key_bytes
  less_signature_max_bytes less_seed_bytes malloc free)
ld=(-mexec-model=reactor -Wl,-z,stack-size=8388608)
for e in "${exports[@]}"; do ld+=("-Wl,--export=$e"); done
(cd "$src" && "$cc" --target=wasm32-wasi --sysroot="$sysroot" -O2 -std=c99 -fno-exceptions -DCATEGORY=252 -DTARGET=45 \
  -I include -Wno-unused-function -Wno-unused-parameter "${ld[@]}" "${files[@]:0:12}" "$here/less_wasm_glue.c" -o "$wasm")
wasm_sha="$(sha256 "$wasm" | cut -d' ' -f1)"
clang_ver="$("$cc" --version | head -1)"
cat > "$out/BUILD.json" <<JSON
{
 "artifact": "less_cat1.wasm",
 "wasm_sha256": "$wasm_sha",
 "wasm_bytes": $(wc -c < "$wasm" | tr -d ' '),
 "sources": "sdks/pca-less-c (Atlas-Authorization/LESS atlas-verifier-hardening 0b8b9a07ce029bd9af12d701f5093c5ca0d9418b) + packages/pca-less-wasm/scripts/less_wasm_glue.c",
 "sources_sha256": "$digest",
 "toolchain": "wasi-sdk $WASI_SDK_VER.0 ($clang_ver)",
 "toolchain_tarballs_sha256": {
  "wasi-sdk-25.0-x86_64-linux.tar.gz": "52640dde13599bf127a95499e61d6d640256119456d1af8897ab6725bcf3d89c",
  "wasi-sdk-25.0-arm64-macos.tar.gz": "e1e529ea226b1db0b430327809deae9246b580fa3cae32d31c82dfe770233587"
 },
 "built_on": "$(uname -s)-$(uname -m)"
}
JSON
echo "$wasm $wasm_sha"
