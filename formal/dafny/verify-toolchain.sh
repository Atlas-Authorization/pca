#!/usr/bin/env bash
# verify-toolchain.sh [--install] [--dir DIR] [--zip FILE] [--runtimes]
#   (default)   check that the Dafny installation found (DIR, else $DAFNY_DIR, else `dirname $(command -v dafny)`,
#               else /work/tools/dafny) matches formal/dafny/TOOLCHAIN.lock: version string, z3 binaries, key assemblies, and
#               the hash of the whole file tree. Exit 1 on ANY mismatch (so a swapped z3 or a patched Dafny cannot go unnoticed).
#   --install   download the pinned ubuntu zip into DIR (default /work/tools/dafny), verify the ZIP hash BEFORE unpacking,
#               unpack, then run the checks above. (Replaces the unpinned `curl` in install-dafny.sh for reproducible proofs.)
#   --zip FILE  verify a zip you already have (hash only) and exit.
#   --runtimes  also report dotnet/node/go/java/python versions against the recorded ones (informational; major .NET enforced).
# Read-only with respect to build.sh / *.dfy. Needs: sha256sum (or shasum -a 256), unzip (for --install).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$HERE/TOOLCHAIN.lock"
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
fails=0; ok() { echo "ok    $1"; }; bad() { echo "FAIL  $1" >&2; fails=$((fails+1)); }
chk() { # name file expected
  if [ ! -f "$2" ]; then bad "$1: missing $2"; return; fi
  local g; g="$(sha "$2")"; [ "$g" = "$3" ] && ok "$1" || bad "$1: got $g want $3"; }

INSTALL=0; DIR=""; ZIP=""; RT=0
while [ $# -gt 0 ]; do case "$1" in --install) INSTALL=1;; --dir) DIR="$2"; shift;; --zip) ZIP="$2"; shift;; --runtimes) RT=1;; *) echo "unknown arg $1" >&2; exit 2;; esac; shift; done

if [ -n "$ZIP" ]; then chk "zip $(basename "$ZIP")" "$ZIP" "$DAFNY_ZIP_ubuntu_22_04_x64_SHA256"; exit $((fails>0)); fi

if [ -z "$DIR" ]; then
  if [ -n "${DAFNY_DIR:-}" ]; then DIR="$DAFNY_DIR"
  elif command -v dafny >/dev/null 2>&1; then DIR="$(cd "$(dirname "$(command -v dafny)")" && pwd)"
  else DIR=/work/tools/dafny; fi
fi

if [ "$INSTALL" = 1 ]; then
  W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
  curl -fsSL -o "$W/dafny.zip" "$DAFNY_RELEASE_URL_BASE/$DAFNY_ZIP_ubuntu_22_04_x64" || { echo "download failed" >&2; exit 1; }
  chk "downloaded zip" "$W/dafny.zip" "$DAFNY_ZIP_ubuntu_22_04_x64_SHA256"
  [ "$fails" = 0 ] || { echo "REFUSING to unpack an unverified archive" >&2; exit 1; }
  mkdir -p "$W/x" && unzip -q -o "$W/dafny.zip" -d "$W/x" && rm -rf "$DIR" && mkdir -p "$(dirname "$DIR")" && mv "$W/x/dafny" "$DIR"
  chmod +x "$DIR/dafny" "$DIR"/z3/bin/* 2>/dev/null || true
fi

[ -x "$DIR/dafny" ] || { echo "no dafny at $DIR" >&2; exit 1; }
echo "toolchain dir: $DIR"
ver="$("$DIR/dafny" --version 2>/dev/null | head -1)"
[ "$ver" = "$DAFNY_VERSION_STRING" ] && ok "dafny --version = $ver" || bad "dafny --version: got '$ver' want '$DAFNY_VERSION_STRING'"
chk "z3 4.12.1 binary" "$DIR/z3/bin/z3-4.12.1" "$Z3_4_12_1_SHA256"
chk "z3 4.14.1 binary" "$DIR/z3/bin/z3-4.14.1" "$Z3_4_14_1_SHA256"
zv="$("$DIR/z3/bin/z3-4.12.1" -version 2>/dev/null)"; case "$zv" in *"4.12.1"*) ok "z3 reports $zv";; *) bad "z3-4.12.1 reports '$zv'";; esac
chk Dafny.dll "$DIR/Dafny.dll" "$DLL_Dafny_SHA256"
chk DafnyDriver.dll "$DIR/DafnyDriver.dll" "$DLL_DafnyDriver_SHA256"
chk DafnyPipeline.dll "$DIR/DafnyPipeline.dll" "$DLL_DafnyPipeline_SHA256"
chk DafnyCore.dll "$DIR/DafnyCore.dll" "$DLL_DafnyCore_SHA256"
chk DafnyRuntime.dll "$DIR/DafnyRuntime.dll" "$DLL_DafnyRuntime_SHA256"
chk Boogie.Core.dll "$DIR/Boogie.Core.dll" "$DLL_BoogieCore_SHA256"
chk Boogie.ExecutionEngine.dll "$DIR/Boogie.ExecutionEngine.dll" "$DLL_BoogieExecutionEngine_SHA256"
chk Boogie.VCGeneration.dll "$DIR/Boogie.VCGeneration.dll" "$DLL_BoogieVCGeneration_SHA256"
chk Boogie.Provers.SMTLib.dll "$DIR/Boogie.Provers.SMTLib.dll" "$DLL_BoogieProversSMTLib_SHA256"
chk DafnyPrelude.bpl "$DIR/DafnyPrelude.bpl" "$FILE_DafnyPrelude_bpl_SHA256"
chk DafnyRuntime.jar "$DIR/DafnyRuntime.jar" "$FILE_DafnyRuntime_jar_SHA256"
if grep -q "\"Boogie.Core/$BOOGIE_VERSION\"" "$DIR/Dafny.deps.json" 2>/dev/null; then ok "Boogie $BOOGIE_VERSION (Dafny.deps.json)"; else bad "Boogie version in Dafny.deps.json is not $BOOGIE_VERSION"; fi
# whole-tree hash: catches any extra/modified/removed file (including the other targets' runtimes and .doo libraries)
{
  tree="$(cd "$DIR" && find . -type f | LC_ALL=C sort | while IFS= read -r f; do printf '%s  %s\n' "$(sha "$f")" "$f"; done | { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; } | cut -d' ' -f1)"
  n="$(cd "$DIR" && find . -type f | wc -l | tr -d ' ')"
  [ "$tree" = "$DAFNY_TREE_SHA256" ] && [ "$n" = "$DAFNY_TREE_FILES" ] && ok "tree hash ($n files)" || bad "tree hash: got $tree ($n files) want $DAFNY_TREE_SHA256 ($DAFNY_TREE_FILES)"
}
# the Dafny sources must stay free of assume/axiom/extern (same audit as build.sh, repeated so it is checked with the toolchain)
if grep -nE '^[^/]*(\bassume\b|\{:axiom\}|\{:extern|\bextern\b)' "$HERE"/[A-Z]*.dfy >/dev/null 2>&1; then bad "assume/axiom/extern present in formal/dafny/*.dfy"; else ok "no assume/axiom/extern in the Dafny sources"; fi

if [ "$RT" = 1 ]; then
  dn="$(dotnet --list-runtimes 2>/dev/null | grep -o 'Microsoft.NETCore.App [0-9]*' | head -1 | cut -d' ' -f2)"; echo "info  dotnet runtime major(s): $(dotnet --list-runtimes 2>/dev/null | grep -o 'NETCore.App [0-9.]*' | tr '\n' ' ') (recorded $DOTNET_RUNTIME_RECORDED)"
  dotnet --list-runtimes 2>/dev/null | grep -q "NETCore.App $DOTNET_RUNTIME_MAJOR\." && ok ".NET $DOTNET_RUNTIME_MAJOR runtime present" || bad ".NET $DOTNET_RUNTIME_MAJOR runtime missing"
  echo "info  node $(node --version 2>&1) (recorded $NODE_RECORDED); $(go version 2>&1) (recorded $GO_RECORDED); java $(java -version 2>&1 | head -1) (recorded $JAVA_RECORDED); $(python3 --version 2>&1) (recorded $PYTHON_RECORDED)"
fi
if [ "$fails" = 0 ]; then echo "TOOLCHAIN OK"; else echo "TOOLCHAIN MISMATCH ($fails)" >&2; exit 1; fi
