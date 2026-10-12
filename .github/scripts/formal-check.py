#!/usr/bin/env python3
"""Re-check helpers for the formal CI (.github/workflows/formal-*.yml): compare a fresh tool run with the result files
committed in this repository. A recorded proof (verified / true / Proved) must be reproduced exactly; a recorded attack
(falsified / false) must be found again. A timeout or a missing result where a verdict was recorded is a FAILURE (a
timeout is not a proof). Lemmas whose recorded outcome is itself a timeout / no-result are listed, not judged.

  formal-check.py tamarin-v1  <committed-dir> <new-dir>
  formal-check.py tamarin-v2-jobs <committed-v2-dir> <shard 1..n> <n>      -> "theory|variant|lemma|heuristic" lines
  formal-check.py tamarin-v2-check <committed-v2-dir> <parts-dir> <jobs-file>
  formal-check.py proverif    <committed-dir> <new-dir>
  formal-check.py exact       <committed-dir> <new-dir> [ignored-file ...]
"""
import os
import re
import sys

TAM = re.compile(r'^\s*(\S+) \((exists-trace|all-traces)\): (verified|falsified - found trace|falsified - no trace found)')


def fail_summary(bad, ok, extra=''):
    for b in bad:
        print('MISMATCH', b)
    print(f'{ok} verdict(s) reproduced, {len(bad)} mismatch(es){extra}')
    return 1 if bad or ok == 0 else 0


def tamarin_lines(path):
    out = {}
    for line in open(path, encoding='utf-8', errors='replace'):
        m = TAM.match(line)
        if m:
            out[m.group(1)] = m.group(3)
    return out


def tamarin_v1(committed, new):
    bad, ok = [], 0
    for f in sorted(os.listdir(committed)):
        p = os.path.join(committed, f)
        if not f.endswith('.txt') or not os.path.isfile(p):
            continue
        want = tamarin_lines(p)
        q = os.path.join(new, f)
        got = tamarin_lines(q) if os.path.exists(q) else {}
        for lemma, v in want.items():
            if got.get(lemma) == v:
                ok += 1
            else:
                bad.append(f'{f}: {lemma}: recorded "{v}", got "{got.get(lemma, "no result / timeout")}"')
    return fail_summary(bad, ok)


def v2_recorded(committed):
    """(theory, variant, lemma, heuristic, verdict) for every lemma with a recorded verdict."""
    jobs = []
    for f in sorted(os.listdir(committed)):
        if not f.endswith('.txt') or f.startswith('summary') or not f.startswith('pca_'):
            continue
        name = f[:-4]
        th, _, var = name.partition('__')
        lines = open(os.path.join(committed, f), encoding='utf-8', errors='replace').read().split('\n')
        for i, line in enumerate(lines):
            m = TAM.match(line)
            if not m:
                continue
            h = 's'
            if i + 1 < len(lines):
                hm = re.search(r'heuristic=(\S+)', lines[i + 1])
                if hm:
                    h = hm.group(1)
            jobs.append((th, var, m.group(1), h, m.group(3)))
    return jobs


def tamarin_v2_jobs(committed, k, n):
    for i, j in enumerate(v2_recorded(committed)):
        if i % n == k - 1:
            print('|'.join(j[:4]))
    return 0


def tamarin_v2_check(committed, parts, jobsfile):
    want = {(t, v, l): verdict for t, v, l, _, verdict in v2_recorded(committed)}
    bad, ok = [], 0
    for line in open(jobsfile):
        line = line.strip()
        if not line:
            continue
        t, v, l, _ = line.split('|')
        name = t + ('__' + v if v else '')
        p = os.path.join(parts, f'.{name}.{l}.part')
        got = None
        if os.path.exists(p):
            m = TAM.match(open(p, encoding='utf-8', errors='replace').readline())
            got = m.group(3) if m else None
        if got == want[(t, v, l)]:
            ok += 1
        else:
            bad.append(f'{name}: {l}: recorded "{want[(t, v, l)]}", got "{got or "no result / timeout"}"')
    return fail_summary(bad, ok)


def pv_lines(path):
    out = {}
    for line in open(path, encoding='utf-8', errors='replace'):
        parts = [x.strip() for x in line.split('|', 2)]
        if len(parts) == 3:
            out[parts[0]] = parts[2]
    return out


def proverif(committed, new):
    bad, ok, open_ = [], 0, 0
    for f in sorted(os.listdir(committed)):
        p = os.path.join(committed, f)
        if not f.endswith('.txt') or f == 'versions.txt' or not os.path.isfile(p):
            continue
        want = pv_lines(p)
        q = os.path.join(new, f)
        got = pv_lines(q) if os.path.exists(q) else {}
        for query, r in want.items():
            if not r.startswith('RESULT'):
                open_ += 1
                print(f'recorded without a verdict (not judged): {f}: {query}: {r[:80]}')
                continue
            if got.get(query) == r:
                ok += 1
            else:
                bad.append(f'{f}: {query}: recorded "{r[:160]}", got "{(got.get(query) or "missing")[:160]}"')
    return fail_summary(bad, ok, f', {open_} recorded without a verdict')


def exact(committed, new, ignored):
    bad, ok = [], 0
    for f in sorted(os.listdir(committed)):
        p = os.path.join(committed, f)
        if f in ignored or not f.endswith('.txt') or not os.path.isfile(p):
            continue
        q = os.path.join(new, f)
        a = open(p, encoding='utf-8', errors='replace').read().strip()
        b = open(q, encoding='utf-8', errors='replace').read().strip() if os.path.exists(q) else '<missing>'
        if a == b:
            ok += 1
        else:
            bad.append(f'{f}:\n--- recorded\n{a}\n--- got\n{b}')
    return fail_summary(bad, ok)


def main(a):
    cmd = a[0] if a else ''
    if cmd == 'tamarin-v1':
        return tamarin_v1(a[1], a[2])
    if cmd == 'tamarin-v2-jobs':
        return tamarin_v2_jobs(a[1], int(a[2]), int(a[3]))
    if cmd == 'tamarin-v2-check':
        return tamarin_v2_check(a[1], a[2], a[3])
    if cmd == 'proverif':
        return proverif(a[1], a[2])
    if cmd == 'exact':
        return exact(a[1], a[2], set(a[3:]))
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
