#!/usr/bin/env python3
"""Infection summary (php-infection-box.sh: infection-out/summary.json) -> survivors list for native-check-equivalents.mjs.
One record per survivor (escaped + not-covered): crate php-pca, file src/<File>, line = the trimmed SOURCE line at the mutant's
start line, occurrence = which copy of that text in the file (1-based; the site key), lineno = the start line (a hint),
mutant = '<Mutator>: <first replacement line as Infection prints it>'. Identical mutants at one site are listed once each and
are covered by one ledger entry with multiplicity N.   python3 php-survivors.py summary.json sdks/php-pca/src out.json"""
import json, sys
summ, srcdir, out = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(summ))
ms = sorted(d['escaped'] + d['uncovered'], key=lambda m: (m['file'], m['line'], m['mutator'], m['diff']))
res, srcs = [], {}
for m in ms:
    plus = [l[1:].strip() for l in m['diff'].split('\n') if l.startswith('+') and not l.startswith('+++')]
    src = srcs.setdefault(m['file'], open(f"{srcdir}/{m['file']}").read().split('\n'))
    line = src[m['line'] - 1].strip()
    occ = [i + 1 for i, l in enumerate(src) if l.strip() == line].index(m['line']) + 1
    mut = (m['mutator'] + ': ' + (plus[0] if plus else '(line removed)'))[:240]
    res.append({'crate': 'php-pca', 'file': 'src/' + m['file'], 'mutant': mut, 'line': line, 'occurrence': occ, 'lineno': m['line']})
json.dump(res, open(out, 'w'), indent=1)
print(f"{len(res)} survivors -> {out}")
