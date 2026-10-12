#!/bin/sh
# Oracle for the replay-store models: protocol-rule / linear-fact goals first, order-table premises next,
# adversary-knowledge (K/KU/In) and Fr goals last.
awk -F: '
  { n=$1; l=$0; p=3
    if (l ~ /AcceptCtr|AcceptNonce|COk\(|Ok\(|Ctr\(|Cell\(/) p=0
    else if (l ~ /!Lt\(|!Le\(/) p=1
    else if (l ~ /CtrCreated|CellCreated|CtrRead|NonceRead/) p=2
    else if (l ~ /Fr\(/) p=6
    else if (l ~ /!KU\(|KU\(|K\(/) p=7
    else if (l ~ /In\(/) p=5
    print p " " n }' | sort -n -s -k1,1 | awk '{print $2}'
