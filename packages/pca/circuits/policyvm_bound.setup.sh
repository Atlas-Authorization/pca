#!/usr/bin/env bash
# DEV-ONLY single-party Groth16 setup (BN254) for the risk-bound Policy-VM circuit 'pca-policyvm-v2'.
# Nothing it produces is committed: the CI circuit job builds it, and every artifact lands in circuits/build/:
#   policyvm_bound_js/policyvm_bound.wasm, policyvm_bound.r1cs, policyvm_bound_final.zkey,
#   policyvm_bound_vkey.json, policyvm_bound_sample_proof.json (envelope {system, circuit, proof, publicSignals})
# Needs a 2^18 powers-of-tau (several GB of RAM). Usage: PCA_DEV_SETUP=1 bash circuits/policyvm_bound.setup.sh
set -euo pipefail
source "$(dirname "$0")/dev-only-guard.sh"

cd "$(dirname "$0")/.."                       # packages/pca
CIRCOM="${CIRCOM:-circom}"
SNARKJS="node node_modules/snarkjs/build/cli.cjs"
CIRCUITS=circuits
BUILD="$CIRCUITS/build"
PTAU="$(mktemp -d)/ptau"; mkdir -p "$PTAU"
POWER="${POWER:-18}"
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=12000}"

mkdir -p "$BUILD"
"$CIRCOM" "$CIRCUITS/policyvm_bound.circom" --r1cs --wasm --sym -o "$BUILD" -l node_modules/circomlib/circuits
$SNARKJS r1cs info "$BUILD/policyvm_bound.r1cs"

$SNARKJS powersoftau new bn128 "$POWER" "$PTAU/pot_0000.ptau"
$SNARKJS powersoftau contribute "$PTAU/pot_0000.ptau" "$PTAU/pot_0001.ptau" --name="pca-policyvm-bound-ph1" -e="pca policyvm bound phase1 $(date +%s%N)"
$SNARKJS powersoftau prepare phase2 "$PTAU/pot_0001.ptau" "$PTAU/pot_final.ptau"
$SNARKJS groth16 setup "$BUILD/policyvm_bound.r1cs" "$PTAU/pot_final.ptau" "$PTAU/policyvm_bound_0000.zkey"
$SNARKJS zkey contribute "$PTAU/policyvm_bound_0000.zkey" "$BUILD/policyvm_bound_final.zkey" --name="pca-policyvm-bound-ph2" -e="pca policyvm bound phase2 $(date +%s%N)"
$SNARKJS zkey export verificationkey "$BUILD/policyvm_bound_final.zkey" "$BUILD/policyvm_bound_vkey.json"

node "$BUILD/policyvm_bound_js/generate_witness.js" "$BUILD/policyvm_bound_js/policyvm_bound.wasm" "$CIRCUITS/policyvm_sample_input.json" "$BUILD/witness_bound.wtns"
$SNARKJS groth16 prove "$BUILD/policyvm_bound_final.zkey" "$BUILD/witness_bound.wtns" "$BUILD/policyvm_bound_proof.json" "$BUILD/policyvm_bound_public.json"
$SNARKJS groth16 verify "$BUILD/policyvm_bound_vkey.json" "$BUILD/policyvm_bound_public.json" "$BUILD/policyvm_bound_proof.json"
node -e '
  const fs = require("fs");
  const [p, s, o] = process.argv.slice(1);
  fs.writeFileSync(o, JSON.stringify({ system: "groth16-bn254", circuit: "pca-policyvm-v2", proof: JSON.parse(fs.readFileSync(p, "utf8")), publicSignals: JSON.parse(fs.readFileSync(s, "utf8")) }, null, 2) + "\n");
' "$BUILD/policyvm_bound_proof.json" "$BUILD/policyvm_bound_public.json" "$BUILD/policyvm_bound_sample_proof.json"
echo ">> done: $BUILD/policyvm_bound_vkey.json $BUILD/policyvm_bound_sample_proof.json"
