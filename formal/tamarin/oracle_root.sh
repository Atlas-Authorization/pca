#!/bin/sh
# Tamarin oracle for the ROOT-meter lemmas of pca_budget_v4.spthy (root_bound incl. -DROOT3, spend_debits_root,
# spent_root_is_root_node, and the base-model refutations of the attack lemmas).  Same principle as
# oracle_nodebound.sh: the root meter thread (RCnt, finite through !Dec) and the root's identity (!IsRoot -> Root_Grant,
# unique by Fr) close every case; the tree structure (!Lim/!Node) and the recursive Debit tokens are never needed and
# are solved last, because solving them unfolds the tree without bound.
awk -F: '
  { n=$1; l=$0; p=6
    if (l ~ /!Dec\(/) p=0
    else if (l ~ /!IsRoot\(/) p=1
    else if (l ~ /RCnt\(|FCnt\(|Cnt\(/) p=2
    else if (l ~ /Spent\(|Debited\(|DebitFrom\(|RootNode\(|Alloc\(|SpendBegin\(|Focus\(/) p=3
    else if (l ~ /Fr\(/) p=4
    else if (l ~ /!Le\(/) p=5
    else if (l ~ /!KU\(|KU\(|K\(|In\(/) p=6
    else if (l ~ /Snap\(/) p=7
    else if (l ~ /!Lim\(|!Node\(/) p=8
    else if (l ~ /Debit\(/) p=9
    print p " " n }' | sort -n -s -k1,1 | awk '{print $2}'
