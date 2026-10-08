#!/usr/bin/env bash
# Reproducible FRESH trusted setup for the FULL Policy-VM §9B circuit on the BLS12-381 curve
# (128-bit security — the end-game plan's P2 "BN254 -> BLS12-381" migration). This is the BLS12-381
# sibling of policyvm.setup.sh; it does NOT replace it — the BN254 fixtures stay committed alongside.
#
# The circuit is identical (circuits/policyvm.circom); only the proving field changes. On BLS12-381 it
# compiles to 151,585 non-linear constraints (same count — the constraint system is field-independent),
# so it still needs a 2^18 powers-of-tau. Group/field ops are larger than BN254, so phase 1 + prove are
# noticeably slower and want several GB of RAM — run it on a box with the headroom (this build was run
# on an Azure Standard_D4s_v4: 4 vCPU / 16 GB). The committed fixtures let everyone else VERIFY offline.
#
# Public powers-of-tau mirrors are BN254-only / gated, so this generates a FRESH bls12381 ptau locally
# (a one-person ceremony — fine for an engineering fixture; a real deployment runs a multi-party one).
#
# Produces two COMMITTED fixtures (tracked, small):
#   circuits/policyvm_bls12381_vkey.json          — Groth16 verifying key (BLS12-381)
#   circuits/policyvm_bls12381_sample_proof.json  — a sample {proof, publicSignals}, system tag
#                                                    "groth16-bls12-381", that the offline test verifies
# and the large GITIGNORED prover artifacts under circuits/build/ (regenerate; never committed):
#   circuits/build/policyvm_js/policyvm.wasm   — witness calculator
#   circuits/build/policyvm_final.zkey         — Groth16 proving key (BLS12-381)
#
# A fresh run yields a cryptographically equivalent setup (ceremony entropy differs, so the exact
# vkey/zkey/proof bytes change — but a proof made with the new proving key verifies under the new vkey,
# and a new sample proof is written alongside, so the committed pair stays self-consistent).
#
# Requirements: circom 2.x with BLS12-381 support (`circom --prime bls12381`; use >= 2.1.x) on PATH
# (or CIRCOM=/path/to/circom); snarkjs (optional dep of @atlasauth/pca).
# Usage:  bash circuits/policyvm.bls12381.setup.sh
set -euo pipefail

cd "$(dirname "$0")/.."                       # packages/pca
CIRCOM="${CIRCOM:-circom}"
SNARKJS="node node_modules/snarkjs/build/cli.cjs"
CIRCUITS=circuits
BUILD="$CIRCUITS/build"
PTAU="$(mktemp -d)/ptau"; mkdir -p "$PTAU"
POWER="${POWER:-18}"                          # 2^18 = 262144 >= 151585 constraints
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=13000}"

echo ">> compiling full Policy-VM circuit on BLS12-381"
mkdir -p "$BUILD"
"$CIRCOM" "$CIRCUITS/policyvm.circom" --r1cs --wasm --sym --prime bls12381 -o "$BUILD" -l node_modules/circomlib/circuits
$SNARKJS r1cs info "$BUILD/policyvm.r1cs"

echo ">> phase 1 (powers of tau, bls12381, power=$POWER)"
$SNARKJS powersoftau new bls12381 "$POWER" "$PTAU/pot_0000.ptau"
$SNARKJS powersoftau contribute "$PTAU/pot_0000.ptau" "$PTAU/pot_0001.ptau" --name="pca-policyvm-bls-ph1" -e="pca policyvm bls12381 phase1 $(date +%s%N)"
$SNARKJS powersoftau prepare phase2 "$PTAU/pot_0001.ptau" "$PTAU/pot_final.ptau"

echo ">> phase 2 (groth16 circuit-specific setup)"
$SNARKJS groth16 setup "$BUILD/policyvm.r1cs" "$PTAU/pot_final.ptau" "$PTAU/policyvm_0000.zkey"
$SNARKJS zkey contribute "$PTAU/policyvm_0000.zkey" "$BUILD/policyvm_final.zkey" --name="pca-policyvm-bls-ph2" -e="pca policyvm bls12381 phase2 $(date +%s%N)"
$SNARKJS zkey export verificationkey "$BUILD/policyvm_final.zkey" "$CIRCUITS/policyvm_bls12381_vkey.json"

echo ">> generate + verify a sample proof (committed fixture)"
node "$BUILD/policyvm_js/generate_witness.js" "$BUILD/policyvm_js/policyvm.wasm" "$CIRCUITS/policyvm_sample_input.json" "$BUILD/witness.wtns"
$SNARKJS groth16 prove "$BUILD/policyvm_final.zkey" "$BUILD/witness.wtns" "$BUILD/policyvm_proof.json" "$BUILD/policyvm_public.json"
$SNARKJS groth16 verify "$CIRCUITS/policyvm_bls12381_vkey.json" "$BUILD/policyvm_public.json" "$BUILD/policyvm_proof.json"

# Combine proof + publicSignals into the committed sample envelope the offline test loads.
node -e '
  const fs = require("fs");
  const proof = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const publicSignals = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const env = { system: "groth16-bls12-381", circuit: "pca-policyvm-v1", proof, publicSignals };
  fs.writeFileSync(process.argv[3], JSON.stringify(env, null, 2) + "\n");
' "$BUILD/policyvm_proof.json" "$BUILD/policyvm_public.json" "$CIRCUITS/policyvm_bls12381_sample_proof.json"

echo ">> done. committed fixtures:"
ls -la "$CIRCUITS/policyvm_bls12381_vkey.json" "$CIRCUITS/policyvm_bls12381_sample_proof.json"
echo ">> gitignored prover artifacts:"
ls -la "$BUILD/policyvm_final.zkey" "$BUILD/policyvm_js/policyvm.wasm"
