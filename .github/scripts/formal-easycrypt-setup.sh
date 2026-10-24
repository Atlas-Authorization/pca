#!/usr/bin/env bash
# formal-easycrypt-setup.sh : EasyCrypt at the pinned commit + Why3 + Alt-Ergo (opam switch "ec"), and the pinned Z3 / CVC5
# release binaries in ~/smt, all from TOOLCHAIN.lock; then `easycrypt why3config`. Idempotent (the opam root is cached).
set -euo pipefail
. ./TOOLCHAIN.lock
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq opam build-essential m4 pkg-config libgmp-dev zlib1g-dev unzip >/dev/null
mkdir -p "$HOME/smt"
if [ ! -x "$HOME/smt/z3" ]; then
  curl -fsSL -o /tmp/z3.zip "https://github.com/Z3Prover/z3/releases/download/z3-${Z3_EASYCRYPT_VERSION}/z3-${Z3_EASYCRYPT_VERSION}-x64-glibc-2.31.zip"
  unzip -q -o /tmp/z3.zip -d /tmp/z3 && cp /tmp/z3/*/bin/z3 "$HOME/smt/z3"
fi
if [ ! -x "$HOME/smt/cvc5" ]; then
  curl -fsSL -o "$HOME/smt/cvc5" "https://github.com/cvc5/cvc5/releases/download/cvc5-${CVC5_VERSION}/cvc5-Linux" \
    || { curl -fsSL -o /tmp/cvc5.zip "https://github.com/cvc5/cvc5/releases/download/cvc5-${CVC5_VERSION}/cvc5-Linux-static.zip" \
         && unzip -q -o /tmp/cvc5.zip -d /tmp/cvc5 && cp /tmp/cvc5/*/bin/cvc5 "$HOME/smt/cvc5"; }
  chmod +x "$HOME/smt/cvc5"
fi
export PATH="$HOME/smt:$PATH"; z3 --version; cvc5 --version | head -1
export OPAMYES=1 OPAMCONFIRMLEVEL=unsafe-yes   # non-interactive, incl. depext installs
[ -d "$HOME/.opam" ] || opam init -y --disable-sandboxing --bare >/dev/null
opam switch list 2>/dev/null | grep -qw ec || opam switch create ec "$OCAML_VERSION" -y
eval "$(opam env --switch=ec)"
command -v easycrypt >/dev/null || {
  opam pin add -yn easycrypt "git+https://github.com/EasyCrypt/easycrypt.git#$EASYCRYPT_GIT"
  opam install -y "why3.$WHY3_VERSION" "alt-ergo.$ALTERGO_VERSION" easycrypt
}
easycrypt why3config
easycrypt config 2>&1 | head -20 || true
