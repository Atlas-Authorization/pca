#!/bin/sh
# Tamarin oracle for EXISTS-TRACE (executability) lemmas: build the trace forward-ish -- action/rule goals
# of the verifier first, then linear premises, Fr, and K-derivation goals last.
awk -F: '
  { n=$1; l=$0; p=5
    if (l ~ /Accept\(|HopWalk\(|HonestDelegated\(|Granted\(/) p=0
    else if (l ~ /(^|[^A-Za-z])Walk\(/) p=1
    else if (l ~ /!Hop\(|!Ctx\(|!VCfg\(|!Ltk\(/) p=2
    else if (l ~ /Fr\(/) p=3
    else if (l ~ /!KU\(|KU\(|K\(/) p=6
    else if (l ~ /In\(/) p=4
    print p " " n }' | sort -n -s -k1,1 | awk '{print $2}'
