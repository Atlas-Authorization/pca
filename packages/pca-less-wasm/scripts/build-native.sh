#!/usr/bin/env bash
# Build the UNMODIFIED upstream LESS reference (pinned commit) natively into several variants
# for cross-checking the wasm artifact. Usage: build-native.sh <work_dir>
# Variants (same params as the wasm: CATEGORY=252 TARGET=45, portable scalar C, no AVX/NEON defines):
#   O2        apple clang -O2 (matches the wasm build's -O2)
#   O0asan    apple clang -O0 -fsanitize=address,undefined (+ -fno-sanitize-recover)
#   O3llvm    Homebrew LLVM clang (second compiler, different version) -O3 -fsanitize=undefined
set -euo pipefail
PIN=6383430b9123e69d2ef6a6224f930972e3225610
HERE="$(cd "$(dirname "$0")" && pwd)"
W="${1:?work dir}"; mkdir -p "$W"; W="$(cd "$W" && pwd)"
if [ ! -d "$W/LESS/.git" ]; then git clone https://github.com/less-sig/LESS "$W/LESS"; fi
git -C "$W/LESS" checkout -q "$PIN"
test "$(git -C "$W/LESS" rev-parse HEAD)" = "$PIN"
REF="$W/LESS/Reference_Implementation"; LIB="$REF/lib"
SRCS=(codes.c fips202.c keccakf1600.c LESS.c monomial.c rng.c seedtree.c sign.c utils.c sort.c canonical.c transpose.c)
FILES=(); for s in "${SRCS[@]}"; do FILES+=("$LIB/$s"); done
COMMON=(-std=c99 -DCATEGORY=252 -DTARGET=45 -I "$REF/include" -Wno-unused-function -Wno-unused-parameter -g)
mkdir -p "$W/bin"
cc "${COMMON[@]}" -O2 "${FILES[@]}" "$HERE/less_native_driver.c" -o "$W/bin/less_O2"
cc "${COMMON[@]}" -O0 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
   "${FILES[@]}" "$HERE/less_native_driver.c" -o "$W/bin/less_O0asan"
LLVMCC=/opt/homebrew/opt/llvm/bin/clang
if [ -x "$LLVMCC" ]; then
  "$LLVMCC" "${COMMON[@]}" -O3 -fsanitize=undefined -fno-sanitize-recover=all \
     "${FILES[@]}" "$HERE/less_native_driver.c" -o "$W/bin/less_O3llvm" \
     && "$LLVMCC" --version | head -1
fi
ls -l "$W/bin"
