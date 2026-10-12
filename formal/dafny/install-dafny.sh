#!/usr/bin/env bash
# install-dafny.sh  -- install Dafny 4.11.0 (bundles z3 4.12.1) + .NET 8 runtime check into /work/tools/dafny on a cloud box.
# Run directly on the machine, or over ssh. Idempotent.
set -euo pipefail
V=4.11.0
mkdir -p /work/tools && cd /work/tools
if [ ! -x dafny/dafny ] || [ "$(dafny/dafny --version | cut -d+ -f1)" != "$V" ]; then
  curl -fsSL -o dafny.zip "https://github.com/dafny-lang/dafny/releases/download/v$V/dafny-$V-x64-ubuntu-22.04.zip"
  unzip -q -o dafny.zip
  chmod +x dafny/dafny dafny/z3/bin/*
fi
dotnet --version
dafny/dafny --version
