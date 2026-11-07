#!/usr/bin/env python3
"""Infection summary (php-infection-box.sh: infection-out/summary.json) -> survivors list for native-check-equivalents.mjs.
One record per survivor (escaped + not-covered): crate php-pca, file src/<File>, line = the trimmed SOURCE line at the mutant's
start line, occurrence = which copy of that text in the file (1-based; the site key), lineno = the start line (a hint),
mutant = '<Mutator>: <first replacement line as Infection prints it>'. Identical mutants at one site are listed once each and
are covered by one ledger entry with multiplicity N.   python3 php-survivors.py summary.json sdks/php-pca/src out.json [run-errors.json]
With a 4th argument, the ERRORED mutants (the test process died: fatal error, memory, signal; Infection counts them as
detected though no test decided them) go there in the same record shape plus `evidence` (the process output tail), for the
merge job's run-error ledger check (sdks/php-pca/mutation-run-errors.json)."""
import json, sys
summ, srcdir, out = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(summ))
srcs = {}
def records(ms):
    res = []
    for m in sorted(ms, key=lambda m: (m['file'], m['line'], m['mutator'], m['diff'])):
        plus = [l[1:].strip() for l in m['diff'].split('\n') if l.startswith('+') and not l.startswith('+++')]
        src = srcs.setdefault(m['file'], open(f"{srcdir}/{m['file']}").read().split('\n'))
        line = src[m['line'] - 1].strip()
        occ = [i + 1 for i, l in enumerate(src) if l.strip() == line].index(m['line']) + 1
        mut = (m['mutator'] + ': ' + (plus[0] if plus else '(line removed)'))[:240]
        res.append({'crate': 'php-pca', 'file': 'src/' + m['file'], 'mutant': mut, 'line': line, 'occurrence': occ, 'lineno': m['line']})
        if 'evidence' in m:
            res[-1]['evidence'] = m['evidence']
    return res
res = records(d['escaped'] + d['uncovered'])
json.dump(res, open(out, 'w'), indent=1)
if len(sys.argv) > 4:
    errs = records(d.get('errored') or [])
    json.dump(errs, open(sys.argv[4], 'w'), indent=1)
    print(f"{len(errs)} run errors -> {sys.argv[4]}")
print(f"{len(res)} survivors -> {out}")
