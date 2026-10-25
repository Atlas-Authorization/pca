#!/usr/bin/env bash
# verus-check.sh -- run Verus over every fragment in tools/pca-implverif/verus/ and judge the result.
#
#   <name>.rs           a proof: must report "verification results:: N verified, 0 errors".
#   <name>_controls.rs  NEGATIVE CONTROLS: every `fn control_*` is a mutated rule under the proved contract, so Verus
#                       must REJECT each one (at least one error located inside that function, and not a resource-limit
#                       error: an rlimit is "undecided", not "refuted"), and must report no error anywhere else in the
#                       file (the unmutated helpers verify). A control that verified would mean the contract does not
#                       pin the rule down.
#
# Usage: tools/pca-implverif/verus-check.sh [log-dir]     (verus on PATH; logs go to log-dir, default a temp dir)
# Exit 0 only if every proof verified and every control was rejected.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$(mktemp -d "${TMPDIR:-/tmp}/verus.XXXXXX")}"; mkdir -p "$OUT"
command -v verus >/dev/null || { echo "verus not on PATH" >&2; exit 3; }
verus --version 2>&1 | tee "$OUT/version.txt"
rc=0
for f in "$HERE"/verus/*.rs; do
  b="$(basename "$f" .rs)"; log="$OUT/$b.txt"
  echo "== verus $b.rs"
  verus --multiple-errors 20 "$f" >"$log" 2>&1; cat "$log"
  case "$b" in
    *_controls)
      # error locations -> enclosing control_* fn (by declaration line); any error outside a control fn fails
      verdict="$(awk -v src="$f" '
        BEGIN { n = 0
                while ((getline l < src) > 0) { ln++; if (l ~ /fn control_[A-Za-z0-9_]+/) { n++; s[n] = ln
                  match(l, /control_[A-Za-z0-9_]+/); name[n] = substr(l, RSTART, RLENGTH) } } }
        /^error/ { pend = ($0 ~ /aborting due to/) ? 0 : 1; rl = ($0 ~ /rlimit|Resource limit/); next }
        pend && /-->/ { pend = 0; split($NF, p, ":"); line = p[2] + 0; hit = 0
                for (i = n; i >= 1; i--) if (line >= s[i]) { hit = i; break }
                if (hit == 0) { printf "FAIL error outside any control_ fn at line %d\n", line; bad = 1 }
                else if (rl) { printf "FAIL %s: resource-limit error (undecided, not refuted)\n", name[hit]; bad = 1 }
                else rej[hit]++ }
        /verification results::/ { ran = 1 }
        END { if (!ran) { print "FAIL no verification results line (Verus did not run to completion)"; bad = 1 }
              if (n == 0) { print "FAIL no control_ functions found"; bad = 1 }
              for (i = 1; i <= n; i++) if (!rej[i]) { printf "FAIL %s VERIFIED (control not rejected)\n", name[i]; bad = 1 }
              if (!bad) printf "OK all %d controls rejected, no other errors\n", n }' "$log")"
      echo "$verdict" | tee -a "$log"
      case "$verdict" in OK*) ;; *) rc=1 ;; esac ;;
    *)
      grep -qE 'verification results:: [0-9]+ verified, 0 errors' "$log" || { echo "FAIL $b.rs did not verify"; rc=1; } ;;
  esac
done
exit $rc
