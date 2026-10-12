#!/bin/sh
# Tamarin oracle for the explicit-clock models: solve the finite order-table premises (!Succ/!Le/!Lt) FIRST (this
# pins the timepoint variables to constants, so the backward Tick chain is bounded), then Clock-thread rules,
# then everything else; Fr/In/K last.
awk -F: '
  { n=$1; l=$0; p=5
    if (l ~ /!Succ\(|!Le\(|!Lt\(|!Nx\(/) p=0
    else if (l ~ /ClockPast|ClockRd|Accept\(|Validity/) p=1
    else if (l ~ /Clock\(/) p=2
    else if (l ~ /Fr\(/) p=7
    else if (l ~ /!KU\(|KU\(|K\(/) p=8
    else if (l ~ /In\(/) p=6
    print p " " n }' | sort -n -s -k1,1 | awk '{print $2}'
