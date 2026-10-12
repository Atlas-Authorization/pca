#!/bin/sh
# Tamarin oracle for the PINNED budget attack witnesses (exists-trace): the lemma fixes every event, value and order,
# so solve the pinned actions first, then the finite tables and the root, then the snapshot/meter threads (whose values
# are now constants) and the spend tokens; tree-structure facts last (the pinned lemmas forbid allocations).
awk -F: '
  { n=$1; l=$0; p=6
    if (l ~ /DebitReadV\(|DebitWriteV\(|Spent\(|SpendBegin\(|RootNode\(|Debited\(|DebitRead\(/) p=0
    else if (l ~ /!Dec\(/) p=1
    else if (l ~ /!IsRoot\(/) p=2
    else if (l ~ /Snap\(/) p=3
    else if (l ~ /RCnt\(/) p=4
    else if (l ~ /Debit\(/) p=5
    else if (l ~ /Fr\(/) p=6
    else if (l ~ /!KU\(|KU\(|K\(|In\(/) p=7
    else if (l ~ /Cnt\(|!Lim\(|!Node\(|!Le\(|Alloc\(/) p=9
    print p " " n }' | sort -n -s -k1,1 | awk '{print $2}'
