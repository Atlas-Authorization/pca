#!/usr/bin/env bash
# Idempotent: installs the symbolic-verification toolchain on an Ubuntu 24.04 x86_64 box (run ON the box).
#   Tamarin 1.12.0 (GitHub release), Maude 3.5.1 (GitHub release; apt's 3.2 is rejected by Tamarin),
#   ProVerif + CryptoVerif via opam (tools=pv,cv), Lean via elan.   Usage: box-setup.sh [tamarin] [opam] [lean]
set -euo pipefail
what="${*:-tamarin}"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq graphviz build-essential m4 pkg-config unzip curl opam libgmp-dev zlib1g-dev >/dev/null
mkdir -p ~/tools
if [[ " $what " == *" tamarin "* ]]; then
  [ -x ~/tools/maude/maude ] || { mkdir -p ~/tools/maude; cd ~/tools/maude
    curl -sL -o m.zip https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip; unzip -oq m.zip; chmod +x maude; }
  [ -x ~/tools/tamarin/tamarin-prover ] || { mkdir -p ~/tools/tamarin; cd ~/tools/tamarin
    curl -sL -o t.tgz https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz; tar xzf t.tgz; }
fi
if [[ " $what " == *" opam "* ]]; then
  [ -d ~/.opam ] || opam init -y --disable-sandboxing --bare >/dev/null
  opam switch list 2>/dev/null | grep -q pv || opam switch create pv 4.14.2 -y >/dev/null
  eval "$(opam env --switch=pv)"
  opam install -y proverif 2>&1 | tail -3 || true
fi
if [[ " $what " == *" lean "* ]]; then
  [ -x ~/.elan/bin/lake ] || curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none >/dev/null
fi
cat > ~/pcaenv.sh <<'E2'
export PATH=$HOME/tools/maude:$HOME/tools/tamarin:$HOME/.elan/bin:$HOME/pcabin:$PATH
[ -d ~/.opam ] && eval "$(opam env --switch=pv 2>/dev/null)" || true
E2
echo setup-ok
