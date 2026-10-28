#!/usr/bin/env bash
# Reproducible local trusted setup for the PCA §9B compliance circuit (Groth16 / BN254).
#
# Regenerates the test fixtures in circuits/build/ :
#   compliance_js/compliance.wasm   — witness calculator (prover input)
#   compliance_final.zkey           — Groth16 proving key
#   verification_key.json           — Groth16 verifying key (loaded by createGroth16SnarkBackend)
#
# These fixtures make the tests deterministic and fully OFFLINE: once generated, no network or
# toolchain is needed to prove or verify. A fresh run produces a cryptographically equivalent setup
# (the ceremony entropy differs, so the exact zkey/vkey bytes change, but proofs made with the new
# proving key verify under the new verifying key).
#
# Requirements:
#   - circom 2.x on PATH (or set CIRCOM=/path/to/circom). Prebuilt binaries:
#       https://github.com/iden3/circom/releases  (e.g. circom-macos-amd64 runs on Apple Silicon via Rosetta)
#   - snarkjs (installed as an optional dependency of @atlasauth/pca)
#
# Usage:  PCA_DEV_SETUP=1 bash circuits/setup.sh   (DEV-ONLY single-party setup; see dev-only-guard.sh)
set -euo pipefail
source "$(dirname "$0")/dev-only-guard.sh"

cd "$(dirname "$0")/.."                     # packages/pca
CIRCOM="${CIRCOM:-circom}"
SNARKJS="node node_modules/snarkjs/build/cli.cjs"
CIRCUITS=circuits
BUILD="$CIRCUITS/build"
PTAU="$(mktemp -d)/ptau"; mkdir -p "$PTAU"
# PTAU_FILE=/path/to/powersOfTau28_hez_final_12.ptau : use an existing (pinned, public) phase-1 file instead of
# generating a throwaway local one. download it and verify its sha256 first.
POWER=12                                     # 2^12 = 4096 >= ~1.8k constraints

echo ">> compiling circuit"
mkdir -p "$BUILD"
"$CIRCOM" "$CIRCUITS/compliance.circom" --r1cs --wasm --sym -o "$BUILD" -l node_modules/circomlib/circuits

if [ -n "${PTAU_FILE:-}" ]; then
  echo ">> phase 1: using supplied $PTAU_FILE"
  cp "$PTAU_FILE" "$PTAU/pot_final.ptau"
else
echo ">> phase 1 (powers of tau)"
$SNARKJS powersoftau new bn128 "$POWER" "$PTAU/pot_0000.ptau"
$SNARKJS powersoftau contribute "$PTAU/pot_0000.ptau" "$PTAU/pot_0001.ptau" --name="pca-zk-ceremony-1" -e="pca zk compliance phase1 $(date +%s)"
$SNARKJS powersoftau prepare phase2 "$PTAU/pot_0001.ptau" "$PTAU/pot_final.ptau"
fi

echo ">> phase 2 (groth16 circuit-specific setup)"
$SNARKJS groth16 setup "$BUILD/compliance.r1cs" "$PTAU/pot_final.ptau" "$PTAU/compliance_0000.zkey"
$SNARKJS zkey contribute "$PTAU/compliance_0000.zkey" "$BUILD/compliance_final.zkey" --name="pca-zk-ceremony-2" -e="pca zk compliance phase2 $(date +%s)"
$SNARKJS zkey export verificationkey "$BUILD/compliance_final.zkey" "$BUILD/verification_key.json"

echo ">> done. fixtures:"
ls -la "$BUILD/compliance_final.zkey" "$BUILD/verification_key.json" "$BUILD/compliance_js/compliance.wasm"
