#!/usr/bin/env bash
# Install the verification toolchain on a cloud box (idempotent). Pinned versions are recorded in the doc.
set -x
export PATH=$HOME/.cargo/bin:$PATH
sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y valgrind cmake libssl-dev pkg-config unzip curl linux-tools-common
mkdir -p /work/dl && cd /work/dl
curl -sLO https://github.com/diffblue/cbmc/releases/download/cbmc-6.11.0/ubuntu-24.04-cbmc-6.11.0-Linux.deb && sudo dpkg -i ubuntu-24.04-cbmc-6.11.0-Linux.deb
curl -sLO https://github.com/verus-lang/verus/releases/download/release/0.2026.10.04.426d8b0/verus-0.2026.10.04.426d8b0-x86-linux.zip && mkdir -p ~/verus && unzip -oq verus-*.zip -d ~/verus
rustup install 1.98.1
rustup toolchain install nightly --component miri rust-src
cargo install --locked kani-verifier && cargo kani setup
cargo install --locked cargo-geiger cargo-audit
cbmc --version; valgrind --version; cargo kani --version; ~/verus/verus-x86-linux/verus --version
echo INSTALL-DONE
