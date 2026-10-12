#!/bin/sh
# Tamarin oracle: solve every goal EXCEPT the recursive Walk(...) premise first (signature / key-reveal /
# restriction goals close the branch long before the unbounded walk would have to be unrolled).
# stdin: lines "<num>:<goal text>"; stdout: goal numbers, best first.
awk -F: '
  { n=$1; line=$0 }
  line ~ /(^|[^A-Za-z])Walk\(/ { w[++nw]=n; next }
  { o[++no]=n }
  END { for(i=1;i<=no;i++) print o[i]; for(i=1;i<=nw;i++) print w[i] }'
