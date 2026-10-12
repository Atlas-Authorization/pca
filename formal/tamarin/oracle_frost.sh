#!/bin/sh
# oracle for FROST models: solve Nonce/Share/Setup (state) goals and Signed/Used actions first, adversary K(..) last.
awk -F: '
 { n=$1; l=$0; p=5
   if (l ~ /Setup\(|ShareOf\(|!Share\(|!GroupPub/) p=0
   else if (l ~ /Nonce\(|Committed\(|Used\(|Signed\(/) p=1
   else if (l ~ /RevealShare|Aggregated|Accepted/) p=2
   else if (l ~ /Fr\(/) p=3
   else if (l ~ /In\(/) p=6
   else if (l ~ /!KU\(zs|!KU\( *zs/) p=4
   else if (l ~ /!KU\(|KU\(|K\(/) p=7
   print p " " n }' | sort -n -s -k1,1 | awk '{print $2}'
