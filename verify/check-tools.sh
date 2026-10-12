#!/usr/bin/env bash
# check-tools.sh [tool ...]   Compare the tools found on PATH with TOOLCHAIN.lock. Informational per tool; exit 1 if any
# REQUESTED tool is missing or has a different version. No tools listed => report everything, never fail.
#   tools: dafny tamarin maude proverif cryptoverif tla easycrypt lean verus kani cbmc node pnpm
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/TOOLCHAIN.lock"
want=("$@"); fails=0
requested() { [ ${#want[@]} -eq 0 ] && return 1; local t; for t in "${want[@]}"; do [ "$t" = "$1" ] && return 0; done; return 1; }
report() { # tool want-version got-version(or empty)
  local st=ok
  if [ -z "$3" ]; then st=MISSING; elif [[ "$3" != *"$2"* ]]; then st=DIFFERENT; fi
  printf '%-11s want %-22s got %-34s %s\n' "$1" "$2" "${3:-none}" "$st"
  if [ "$st" != ok ] && requested "$1"; then fails=$((fails+1)); fi
}
have() { command -v "$1" >/dev/null 2>&1; }
DAFNY_BIN="$(command -v dafny || true)"; [ -z "$DAFNY_BIN" ] && [ -x "${DAFNY_DIR:-/nonexistent}/dafny" ] && DAFNY_BIN="$DAFNY_DIR/dafny"
report dafny "$DAFNY_VERSION"      "$([ -n "$DAFNY_BIN" ] && "$DAFNY_BIN" --version 2>/dev/null | head -1)"
report tamarin "$TAMARIN_VERSION"  "$(have tamarin-prover && tamarin-prover --version 2>&1 | grep -oE 'version [0-9.]+' | head -1)"
report maude "$MAUDE_VERSION"      "$(have maude && maude --version 2>&1 | head -1)"
report proverif "$PROVERIF_VERSION" "$(have proverif && proverif --help 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)"
report cryptoverif "$CRYPTOVERIF_VERSION" "$(have cryptoverif && cryptoverif -help 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)"
report tla "TLC (see lock)"        "$(for j in "${TLA_JAR:-}" ./tla2tools.jar "$HOME/tla2tools.jar"; do [ -f "$j" ] && { have java && java -cp "$j" tlc2.TLC 2>&1 | grep -m1 -oE 'Version [0-9.]+'; break; }; done)"
report easycrypt "$EASYCRYPT_VERSION" "$(have easycrypt && easycrypt -version 2>&1 | head -1)"
report lean "$LEAN_VERSION"        "$(have lean && lean --version 2>&1 | head -1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+')"
report verus "$VERUS_RELEASE"      "$({ have verus && verus --version 2>&1 | head -3 | tr '\n' ' '; } || true)"
report kani "$KANI_VERSION"        "$(have cargo-kani && cargo kani --version 2>&1 | head -1)"
report cbmc "$CBMC_VERSION"        "$(have cbmc && cbmc --version 2>&1 | head -1)"
report node "v$NODE_MIN_MAJOR"     "$(have node && node --version)"
report pnpm "$PNPM_VERSION"        "$(have pnpm && pnpm --version)"
echo
echo "Note: 'DIFFERENT' for node means 'recorded on v$NODE_RECORDED_MAJOR, minimum v$NODE_MIN_MAJOR'; check by eye. Dafny is hash-pinned: run formal/dafny/verify-toolchain.sh."
exit $((fails>0))
