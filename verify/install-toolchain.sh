#!/usr/bin/env bash
# install-toolchain.sh <component ...>     Fresh Ubuntu 22.04/24.04 x86_64 machine; uses sudo apt for system packages.
#   components: dafny tamarin proverif tla lean easycrypt verus all-cheap
#   dafny      hash-pinned download (formal/dafny/TOOLCHAIN.lock), verified BEFORE unpacking; installs to $DAFNY_DIR
#   tamarin    Tamarin 1.12.0 + Maude 3.5.1 release binaries into ~/tools   (via tools/pca-formal/box-setup.sh)
#   proverif   ProVerif 2.05 + CryptoVerif 2.13 via opam (OCaml 4.14.2)      (same script, opam switch "pv")
#   lean       elan (toolchain per lean-toolchain files)                     (same script)
#   tla        tla2tools.jar from the TLA+ tools release into ~/tla2tools.jar (+ a JRE via apt)
#   easycrypt  EasyCrypt at the pinned commit + Why3 1.8.2 + Alt-Ergo 2.6.4 + Z3 + CVC5 via opam (slow: 30-60 min build)
#   verus      Verus release + Rust 1.98.1 (tools/pca-implverif/install-tools.sh installs the rest of the implementation lane)
#   all-cheap  dafny + tamarin + tla
# Nothing here is run automatically by `make verify-*`; the Makefile only tells you what is missing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT/TOOLCHAIN.lock"
DAFNY_DIR="${DAFNY_DIR:-$HOME/.pca-tools/dafny}"
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo "WARNING: pinned binaries are Linux x86_64; this host is $(uname -sm)." >&2; }
c_dafny()   { sudo apt-get update -qq; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl unzip libicu-dev >/dev/null
              bash "$ROOT/formal/dafny/verify-toolchain.sh" --install --dir "$DAFNY_DIR" --runtimes
              echo "export PATH=\"$DAFNY_DIR:\$PATH\"   # add to your shell profile"; }
c_tamarin() { bash "$ROOT/tools/pca-formal/box-setup.sh" tamarin; }
c_proverif(){ bash "$ROOT/tools/pca-formal/box-setup.sh" opam; }
c_lean()    { bash "$ROOT/tools/pca-formal/box-setup.sh" lean; }
c_tla()     { sudo apt-get update -qq; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl default-jre-headless >/dev/null
              [ -f "$HOME/tla2tools.jar" ] || curl -fsSL -o "$HOME/tla2tools.jar" https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
              echo "installed ~/tla2tools.jar (the recorded run used TLC nightly $TLC_RECORDED_BUILD; a release jar is a valid re-check)"; }
c_easycrypt(){
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq opam build-essential m4 pkg-config libgmp-dev zlib1g-dev git curl unzip >/dev/null
  [ -d "$HOME/.opam" ] || opam init -y --disable-sandboxing --bare >/dev/null
  opam switch list 2>/dev/null | grep -q '\bec\b' || opam switch create ec "$OCAML_VERSION" -y
  eval "$(opam env --switch=ec)"
  opam pin add -yn easycrypt "git+https://github.com/EasyCrypt/easycrypt.git#$EASYCRYPT_GIT"
  opam install -y "why3.$WHY3_VERSION" "alt-ergo.$ALTERGO_VERSION" easycrypt
  # SMT solvers EasyCrypt calls: Z3 and CVC5 must be on PATH at the pinned versions (apt's versions differ; use the upstream releases).
  echo "Install Z3 $Z3_EASYCRYPT_VERSION and CVC5 $CVC5_VERSION from their upstream release pages onto PATH, then run: easycrypt why3config"
  echo "Then: eval \$(opam env --switch=ec); verify/check-tools.sh easycrypt"; }
c_verus()   { bash "$ROOT/tools/pca-implverif/install-tools.sh"; }
[ $# -gt 0 ] || { sed -n 2,14p "$0"; exit 2; }
for c in "$@"; do case "$c" in
  dafny|tamarin|proverif|lean|tla|easycrypt|verus) "c_$c";;
  all-cheap) c_dafny; c_tamarin; c_tla;;
  *) echo "unknown component: $c" >&2; exit 2;; esac; done
