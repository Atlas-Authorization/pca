#!/usr/bin/env python3
"""formal-conformance-check.py <dir> <shard> <smoke|full> : the model-to-code conformance run is only a pass if every stage
of verify/run-conformance.sh wrote a result with at least one case and 0 disagreements, and the harness self-test killed
at least one mutant (an empty / crashed stage is a failure, never a silent 0)."""
import json, os, sys
d, s, mode = sys.argv[1], sys.argv[2], sys.argv[3]
stages = ['single-exh0', 'single-rand', 'seq-exh2', 'seq-rand', 'thr-exh', 'thr-rand', 'att-exh', 'att-rand']
if mode == 'full':
    stages.append('single-exh1')
bad = 0
for st in stages:
    p = os.path.join(d, f'{st}-{s}.json')
    txt = open(p).read().strip() if os.path.exists(p) else ''
    if not txt:
        print(f'FAIL {st}: no result (stage crashed; see stderr-{s}.txt)'); bad += 1; continue
    j = json.loads(txt.splitlines()[-1])
    n = j.get('n', j.get('sequences', j.get('cases', 0)))
    print(f'{"ok  " if n and not j["disagree"] else "FAIL"} {st}: {n} case(s), {j["disagree"]} disagreement(s), {j.get("seconds", "?")} s')
    bad += (not n) or bool(j['disagree'])
m = os.path.join(d, f'mutants-{s}.txt')
killed = sum('killed' in l for l in open(m)) if os.path.exists(m) else 0
print(f'{"ok  " if killed else "FAIL"} harness self-test: {killed} mutant(s) killed')
bad += not killed
sys.exit(1 if bad else 0)
