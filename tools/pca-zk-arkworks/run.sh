#!/usr/bin/env bash
# run.sh build            build the verifier with the pinned lockfile
# run.sh verify <curve> <case.json>   print the verdict (exit 0 valid, 1 rejected)
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-build}" in
  build) cargo build --release --locked -q ;;
  verify) cargo run --release --locked -q -- verify "$2" "$3" ;;
  *) echo "usage: run.sh build | verify bn254|bls12-381 <case.json>" >&2; exit 2 ;;
esac
