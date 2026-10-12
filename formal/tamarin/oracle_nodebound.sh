#!/bin/sh
# Tamarin oracle for node_bound (pca_budget_v5_focus.spthy and pca_budget_v4.spthy).
# Lesson from the runs that exhausted 12-100g: solving a !Lim(parent, .) premise of Alloc_Child_D unfolds the
# ANCESTOR chain upward without bound (every parent may itself be a child), and solving a Debit(...) token premise
# unfolds the DESCENDANT chain downward without bound.  node_bound needs neither: it is closed by the meter thread
# (FCnt/Cnt, finite because of the !Dec table) plus Fr uniqueness (a node is allocated once).  So: tables, meters,
# the lemma's actions and Fr first; the K/In/!Le premises after; tree-structure facts and Debit tokens never
# before everything else.
awk -F: '
  { n=$1; l=$0; p=6
    if (l ~ /!Dec\(/) p=0
    else if (l ~ /FCnt\(|RCnt\(|Cnt\(/) p=1
    else if (l ~ /Focus\(|FDebited\(|DebitFrom\(|Alloc\(|RootNode\(/) p=2
    else if (l ~ /Fr\(/) p=3
    else if (l ~ /Debited\(|Spent\(|SpendBegin\(/) p=4
    else if (l ~ /!Le\(/) p=5
    else if (l ~ /!KU\(|KU\(|K\(|In\(/) p=7
    else if (l ~ /!Lim\(|!Node\(|!IsRoot\(/) p=8
    else if (l ~ /Debit\(/) p=9
    print p " " n }' | sort -n -s -k1,1 | awk '{print $2}'
