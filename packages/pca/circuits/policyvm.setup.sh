#!/usr/bin/env bash
# Reproducible trusted setup for the FULL Policy-VM §9B compliance circuit (Groth16 / BN254).
#
# This is the heavy successor to setup.sh (compliance.circom). The circuit has ~151,585 non-linear
# constraints (sha256-in-circuit over three fixed-layout structs + the fixed-point Policy VM), so it
# needs a 2^18 powers-of-tau — several GB of RAM and disk during `prepare phase2`. Run it on a box with
# the headroom (a laptop usually does not); the committed fixtures let everyone else VERIFY offline.
#
# Produces two COMMITTED fixtures (tracked, small):
#   circuits/policyvm_vkey.json          — Groth16 verifying key (loaded by createPolicyVmSnarkBackend)
#   circuits/policyvm_sample_proof.json  — a sample {proof, publicSignals} the offline test verifies
# and the large GITIGNORED prover artifacts under circuits/build/ (regenerate; never committed):
#   circuits/build/policyvm_js/policyvm.wasm   — witness calculator (provePolicyVmCompliance input)
#   circuits/build/policyvm_final.zkey         — Groth16 proving key
#
# A fresh run yields a cryptographically equivalent setup (ceremony entropy differs, so the exact
# vkey/zkey bytes change — but a proof made with the new proving key verifies under the new vkey, and a
# new sample proof is written alongside, so the committed pair stays self-consistent).
#
# Requirements: circom 2.x on PATH (or CIRCOM=/path/to/circom); snarkjs (optional dep of @atlasauth/pca).
# Usage:  bash circuits/policyvm.setup.sh
set -euo pipefail

cd "$(dirname "$0")/.."                       # packages/pca
CIRCOM="${CIRCOM:-circom}"
SNARKJS="node node_modules/snarkjs/build/cli.cjs"
CIRCUITS=circuits
BUILD="$CIRCUITS/build"
PTAU="$(mktemp -d)/ptau"; mkdir -p "$PTAU"
POWER="${POWER:-18}"                          # 2^18 = 262144 >= 151585 constraints
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=12000}"

echo ">> compiling full Policy-VM circuit"
mkdir -p "$BUILD"
"$CIRCOM" "$CIRCUITS/policyvm.circom" --r1cs --wasm --sym -o "$BUILD" -l node_modules/circomlib/circuits
$SNARKJS r1cs info "$BUILD/policyvm.r1cs"

echo ">> phase 1 (powers of tau, power=$POWER)"
$SNARKJS powersoftau new bn128 "$POWER" "$PTAU/pot_0000.ptau"
$SNARKJS powersoftau contribute "$PTAU/pot_0000.ptau" "$PTAU/pot_0001.ptau" --name="pca-policyvm-ph1" -e="pca policyvm phase1 $(date +%s%N)"
$SNARKJS powersoftau prepare phase2 "$PTAU/pot_0001.ptau" "$PTAU/pot_final.ptau"

echo ">> phase 2 (groth16 circuit-specific setup)"
$SNARKJS groth16 setup "$BUILD/policyvm.r1cs" "$PTAU/pot_final.ptau" "$PTAU/policyvm_0000.zkey"
$SNARKJS zkey contribute "$PTAU/policyvm_0000.zkey" "$BUILD/policyvm_final.zkey" --name="pca-policyvm-ph2" -e="pca policyvm phase2 $(date +%s%N)"
$SNARKJS zkey export verificationkey "$BUILD/policyvm_final.zkey" "$CIRCUITS/policyvm_vkey.json"

echo ">> generate + verify a sample proof (committed fixture)"
node "$BUILD/policyvm_js/generate_witness.js" "$BUILD/policyvm_js/policyvm.wasm" "$CIRCUITS/policyvm_sample_input.json" "$BUILD/witness.wtns"
$SNARKJS groth16 prove "$BUILD/policyvm_final.zkey" "$BUILD/witness.wtns" "$BUILD/policyvm_proof.json" "$BUILD/policyvm_public.json"
$SNARKJS groth16 verify "$CIRCUITS/policyvm_vkey.json" "$BUILD/policyvm_public.json" "$BUILD/policyvm_proof.json"

# Combine proof + publicSignals into the committed sample envelope the offline test loads.
node -e '
  const fs = require("fs");
  const proof = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const publicSignals = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const env = { system: "groth16-bn254", circuit: "pca-policyvm-v1", proof, publicSignals };
  fs.writeFileSync(process.argv[3], JSON.stringify(env, null, 2) + "\n");
' "$BUILD/policyvm_proof.json" "$BUILD/policyvm_public.json" "$CIRCUITS/policyvm_sample_proof.json"

echo ">> done. committed fixtures:"
ls -la "$CIRCUITS/policyvm_vkey.json" "$CIRCUITS/policyvm_sample_proof.json"
echo ">> gitignored prover artifacts:"
ls -la "$BUILD/policyvm_final.zkey" "$BUILD/policyvm_js/policyvm.wasm"
