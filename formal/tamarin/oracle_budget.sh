#!/bin/sh
# Tamarin oracle for the budget models: close the finite-table premises (!Dec/!Le) and the root/parent structure
# first, then the Cnt (meter) threads, then Debit tokens, then Fr/In/K goals last.
awk -F: '
  { n=$1; l=$0; p=5
    if (l ~ /!Dec\(|!Le\(/) p=0
    else if (l ~ /!Parent\(|!Lim\(|!RootOf\(/) p=1
    else if (l ~ /Spent\(|Debited\(|SpendBegin|Alloc\(|RootNode/) p=2
    else if (l ~ /Cnt\(|Snap\(/) p=3
    else if (l ~ /Debit\(/) p=4
    else if (l ~ /Fr\(/) p=7
    else if (l ~ /!KU\(|KU\(|K\(/) p=8
    else if (l ~ /In\(/) p=6
    print p " " n }' | sort -n -s -k1,1 | awk '{print $2}'
