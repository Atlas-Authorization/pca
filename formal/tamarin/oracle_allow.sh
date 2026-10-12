#!/bin/sh
# Tamarin oracle for the allowlist models: finite order/step tables first (they pin versions/steps to constants), then the
# lemma's action goals, then the verifier state thread, then publish/operator, Fr/In/K last.
awk -F: '
  { n=$1; l=$0; p=5
    if (l ~ /!Nx\(|!Le\(|!Allowed\(/) p=0
    else if (l ~ /AcceptMf|AttOk|Wiped/) p=1
    else if (l ~ /SeenR?\(/) p=2
    else if (l ~ /!Manifest\(|Anchor\(|!OldHead\(/) p=3
    else if (l ~ /OpState\(/) p=4
    else if (l ~ /Fr\(/) p=7
    else if (l ~ /!KU\(|KU\(|K\(/) p=8
    else if (l ~ /In\(/) p=6
    print p " " n }' | sort -n -s -k1,1 | awk '{print $2}'
