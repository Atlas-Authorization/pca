#!/usr/bin/env bash
# push.sh <ip>  -- targeted push (no --delete on sdks): tools/pca-implverif, small fixtures, sdks/rust-pca/proofs
set -e; IP="$1"; R="$(cd "$(dirname "$0")/../.." && pwd)"
SO="ssh -i $HOME/.ssh/pca_tee_vm -o StrictHostKeyChecking=no -o UserKnownHostsFile=$HOME/.pca-vm-state/known_hosts -o LogLevel=ERROR"
rsync -az -e "$SO" --exclude target --exclude .lake --exclude out "$R/tools/pca-implverif/" pca@$IP:/work/iv/tools/pca-implverif/
rsync -az -e "$SO" "$R/sdks/rust-pca/proofs/" pca@$IP:/work/iv/sdks/rust-pca/proofs/
for c in stark-pca stark-pca-plonky3 folding-pca; do rsync -az -e "$SO" "$R/sdks/$c/fixtures/" pca@$IP:/work/iv/sdks/$c/fixtures/; done
rsync -az -e "$SO" --include 'decide_input.sample.json' --exclude '*' "$R/sdks/zkvm-pca/fixtures/" pca@$IP:/work/iv/sdks/zkvm-pca/fixtures/
rsync -az -e "$SO" "$R/sdks/zkvm-pca/core/tests/" pca@$IP:/work/iv/sdks/zkvm-pca/core/tests/
echo pushed
