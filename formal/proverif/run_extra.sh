#!/usr/bin/env bash
# run_extra.sh: self-judging ProVerif models in extra/ (no recorded results to compare; each case states its expected verdict).
#   oprf_verifiable.pv : BadAccept unreachable (true); with the proof check removed it is reachable (false); Accepted reachable (sanity)
# Needs `proverif` on PATH. Exit 1 on any mismatch.
cd "$(dirname "$0")/extra" || exit 1
mkdir -p out; rc=0
expect() { # name file query-index expected
  full=$(timeout "${PV_TIMEOUT:-1200}" proverif "$2" 2>&1)
  r=$(printf '%s\n' "$full" | grep -E '^RESULT' | sed -n "$3p")
  [ -n "$r" ] || printf '%s\n' "$full" | tail -15
  echo "$1: $r"
  case "$r" in *"$4"*) ;; *) echo "MISMATCH $1 (expected $4)"; rc=1;; esac
}
expect oprf_verifiable oprf_verifiable.pv 1 "is true"
expect oprf_sanity_accept oprf_verifiable.pv 2 "is false"
sed -e 's/if chk(pkof(k), b, z, p) = true then (\*CHK\*)/if true then/' oprf_verifiable.pv > out/oprf_no_check.pv
expect NEG_oprf_no_check out/oprf_no_check.pv 1 "is false"
exit $rc
