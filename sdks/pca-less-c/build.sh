#!/usr/bin/env bash
# Builds the shared library libatlas_less (.dylib on macOS, .so elsewhere) into build/ (or $1): the patched LESS reference
# plus the verify-only wrapper, parameter set less-252-45. Used by the ctypes / FFI verifiers (Python finds build/ by
# default; elsewhere point ATLAS_PCA_LIBLESS at the result). Needs a C99 compiler ($CC, default cc).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/build}"
mkdir -p "$out"
# Windows builds with mingw-w64 gcc (CC=gcc), not MSVC: the reference uses GNU __attribute__((aligned)), variable-length arrays and
# pthreads (atlas_less.c), none of which MSVC supports. winpthread and libgcc are linked statically so atlas_less.dll needs no runtime DLLs.
case "$(uname -s)" in
  Darwin) lib="$out/libatlas_less.dylib"; opts=(-fPIC); libs=(-lpthread) ;;
  MINGW*|MSYS*|CYGWIN*) lib="$out/atlas_less.dll"; opts=(-static-libgcc); libs=(-Wl,-Bstatic -lpthread -Wl,-Bdynamic) ;;
  *) lib="$out/libatlas_less.so"; opts=(-fPIC); libs=(-lpthread) ;;
esac
"${CC:-cc}" -O2 -std=c99 "${opts[@]}" -shared -DCATEGORY=252 -DTARGET=45 -I"$here/include" -I"$here" \
  -o "$lib" "$here"/lib/*.c "$here/atlas_less.c" "${libs[@]}"
echo "$lib"
