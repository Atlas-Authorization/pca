#!/usr/bin/env bash
# Fetch the NIST ACVP-Server vectors used by run.mjs (the Wycheproof files are vendored under vectors/). Needs network; idempotent.
set -euo pipefail
OUT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vectors/acvp}"; mkdir -p "$OUT"
BASE=https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files
for d in SHA2-256-1.0 SHA2-384-1.0 SHA2-512-1.0 SHA3-256-2.0 SHA3-512-2.0 SHAKE-128-1.0 SHAKE-256-1.0 HMAC-SHA2-256-1.0 HMAC-SHA2-512-1.0 \
         ML-DSA-keyGen-FIPS204 ML-DSA-sigVer-FIPS204 SLH-DSA-keyGen-FIPS205 SLH-DSA-sigVer-FIPS205; do
  mkdir -p "$OUT/$d"
  for f in internalProjection.json; do [ -s "$OUT/$d/$f" ] || curl -sSfL -o "$OUT/$d/$f" "$BASE/$d/$f" || echo "WARN: $d/$f unavailable" >&2; done
done
du -sh "$OUT"
