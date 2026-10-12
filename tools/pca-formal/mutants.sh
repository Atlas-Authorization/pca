#!/usr/bin/env bash
# Harness self-test: every deliberately broken MODEL mutant must be KILLED (disagree > 0 against the real code).
# A surviving mutant means either an equivalent mutant (explained in the doc) or a blind spot of the harness.
cd "$(dirname "$0")/conformance"
TSX=../../../packages/pca/node_modules/.bin/tsx
sum() { python3 -c "import sys,json;d=json.load(sys.stdin);print('killed' if d['disagree']>0 else 'SURVIVED','(disagree',d['disagree'],'of',d.get('n',d.get('sequences',d.get('cases'))),')')"; }
for mu in noParentLink noIssuerEq noHopSig noPrefix noAnchor expiryOffByOne noAud noGrefBound noLeafSig noRootPolicy noAncestorCaveat onlyLeafCaveat; do
  printf '%-18s run.ts  ' $mu; PCA_MODEL_MUTANT=$mu $TSX run.ts single-rand 1500 5 | sum; done
for mu in noNonceStore retentionStrict noCounter counterGE; do
  printf '%-18s seq.ts  ' $mu; PCA_MODEL_MUTANT=$mu $TSX seq.ts rand 150 5 | sum; done
for mu in thrNoDistinct thrUnbound thrNoSetDistinct; do
  printf '%-18s thr.ts  ' $mu; PCA_MODEL_MUTANT=$mu $TSX thr.ts rand 3000 5 | sum; done
