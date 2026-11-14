#!/usr/bin/env bash
# farm-check.sh: install CryptoVerif if needed, then run every model + negative control (run_all.sh).
# FARM ONLY:  PCAQ_OWNER=crypto-proofs cloud-box tooling/q submit --box sp4 --cores 2 --mem 12 --wall 14400 --prep none \
#               --pull formal/cryptoverif/results --wait -- bash formal/cryptoverif/farm-check.sh
set -uo pipefail
cd "$(dirname "$0")" || exit 1
bash ./install-cv.sh >/dev/null 2>&1 || true
source ~/cvenv.sh || { echo "CryptoVerif not installed"; exit 3; }
command -v cryptoverif >/dev/null || { echo "CryptoVerif not on PATH"; exit 3; }
echo "== host $(hostname), $(nproc) cores, $(date -u +%FT%TZ)"
bash ./run_all.sh
rc=$?
echo "== done rc=$rc"
exit $rc
