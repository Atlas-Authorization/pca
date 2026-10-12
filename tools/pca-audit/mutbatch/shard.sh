#!/usr/bin/env bash
# shard.sh <i>   prep the packages of tools/pca-audit/mutbatch/spec-full-<i>.json and run it (inside a queue job).
set -uo pipefail
S="tools/pca-audit/mutbatch/spec-full-$1.json"
PKGS=$(node -p "[...new Set(require('./$S').map(m=>m.pkg))].join(' ')")
bash tools/pca-audit/mutbatch/prep.sh $PKGS
node tools/pca-audit/mutbatch/run.mjs "$S" "${MB_PAR:-5}"
