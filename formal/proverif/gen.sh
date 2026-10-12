#!/bin/sh
# gen.sh <base.pv> <VARIANT|""> [QUERY]   ->  generated .pv on stdout
#   line ending (*-X[,Y..]*)  : deleted in variant X (or Y..)
#   variants may be combined with '+' (e.g. NO_EXTRACT+REV_CTHREE)
#   line starting (*+X*)      : kept (marker stripped) only in variant X
#   line containing (*Q:name*): a query; only the one named QUERY is kept when QUERY is given (all when omitted)
base=$1; v=$2; q=$3
awk -v v="$v" -v q="$q" '
function inlist1(lst, x,   a, n, i) { n = split(lst, a, ","); for (i = 1; i <= n; i++) if (a[i] == x) return 1; return 0 }
function inlist(lst, vv,   b, k, j) { k = split(vv, b, "+"); for (j = 1; j <= k; j++) if (inlist1(lst, b[j])) return 1; return 0 }
{ line=$0 }
{
  if (match(line, /\(\*-[A-Z_,]+\*\)[ \t]*$/)) { m=substr(line,RSTART+3,RLENGTH-5); sub(/[ \t]*$/,"",m); if (v != "" && inlist(m, v)) next; sub(/[ \t]*\(\*-[A-Z_,]+\*\)[ \t]*$/,"",line) }
  if (match(line, /^[ \t]*\(\*\+[A-Z_]+\*\)/)) { m=substr(line,RSTART,RLENGTH); gsub(/[ \t]|\(|\)|\*|\+/,"",m); if (inlist(m, v)) { sub(/^[ \t]*\(\*\+[A-Z_]+\*\)/,"",line) } else next }
  if (match(line, /\(\*Q:[A-Za-z0-9_]+\*\)/)) { n=substr(line,RSTART+4,RLENGTH-6); if (q!="" && n!=q) next; sub(/\(\*Q:[A-Za-z0-9_]+\*\) ?/,"",line) }
  print line
}' "$base"
