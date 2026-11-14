#!/usr/bin/env bash
# install-cv.sh: idempotent install of CryptoVerif (opam switch `cv`, OCaml 4.14.2) into the job user's home on a farm box.
# Never run on the Mac. Usage (farm): bash formal/cryptoverif/install-cv.sh ; then `source ~/cvenv.sh`.
set -uo pipefail
if [ -f ~/cvenv.sh ] && (source ~/cvenv.sh && command -v cryptoverif >/dev/null); then echo "cryptoverif already installed"; source ~/cvenv.sh; cryptoverif -help 2>&1 | head -1; exit 0; fi
echo "== host: $(hostname)  user: $(id -un)  cores: $(nproc)"
for t in gcc make m4 patch unzip bzip2 curl git pkg-config; do printf '%s: %s\n' "$t" "$(command -v $t || echo MISSING)"; done
if ! command -v opam >/dev/null; then
  if sudo -n true 2>/dev/null; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq opam m4 bubblewrap libgmp-dev >/dev/null 2>&1 || true
  fi
fi
if ! command -v opam >/dev/null; then
  mkdir -p ~/pcabin
  curl -sSL -o ~/pcabin/opam https://github.com/ocaml/opam/releases/download/2.3.0/opam-2.3.0-x86_64-linux && chmod +x ~/pcabin/opam
  export PATH=$HOME/pcabin:$PATH
fi
opam --version || { echo "no opam"; exit 2; }
[ -d ~/.opam ] || opam init -y --disable-sandboxing --bare -n >/dev/null 2>&1
opam switch list 2>/dev/null | grep -qw cv || opam switch create cv 4.14.2 -y 2>&1 | tail -5
eval "$(opam env --switch=cv --set-switch)"
opam install -y cryptoverif 2>&1 | tail -5
cat > ~/cvenv.sh <<'E2'
export PATH=$HOME/pcabin:$PATH
eval "$(opam env --switch=cv --set-switch 2>/dev/null)"
E2
source ~/cvenv.sh
command -v cryptoverif && cryptoverif -help 2>&1 | head -1
ls "$(opam var doc 2>/dev/null)/cryptoverif/" 2>/dev/null | head
