#!/usr/bin/env python3
"""Harness power test on the REAL code: apply one deliberate bug at a time to a COPY of packages/pca/src (never to
packages/), run the conformance harness against the copy; the harness must report disagreements (mutant killed).
Usage: code-mutants.py [N_SINGLE=1500]    (needs node_modules of the repo: run from the repo checkout)"""
import os, shutil, subprocess, sys, json, tempfile
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1500
MUT = [
 ('pcactn.ts', "now > p.exp", "now >= p.exp", 'expiry boundary off-by-one', 'run'),
 ('pcactn.ts', "typeof p.grant_ref === 'string' && p.grant_ref.length > 0 && typeof rootId === 'string' && p.grant_ref === rootId", "typeof p.grant_ref === 'string' && p.grant_ref.length > 0 && typeof rootId === 'string'", 'grant_ref not bound to root (NO_GREF_CHECK)', 'run'),
 ('pcactn.ts', "else if (p.aud === opts.audience) checks.audience = 'pass';", "else if (true) checks.audience = 'pass';", 'audience not compared (NO_AUD_CHECK)', 'run'),
 ('pcactn.ts', "verifyLeafSuite({ alg: p.alg, holder: leafCap.holder", "(true as boolean) || verifyLeafSuite({ alg: p.alg, holder: leafCap.holder", 'leaf signature not verified (NO_LEAF_SIG)', 'run'),
 ('capability.ts', "if (hashCanonical(c.caveats[j]) !== hashCanonical(parent.caveats[j])) {", "if (false as boolean) {", 'caveat prefix not enforced (widening)', 'run'),
 ('capability.ts', "if (c.caveats.length < parent.caveats.length) {", "if (false as boolean) {", 'dropped ancestor caveats accepted', 'run'),
 ('capability.ts', "if (c.parent !== capHash(parent)) return", "if (false as boolean) return", 'parent hash link not checked', 'run'),
 ('capability.ts', "if (c.issuer !== parent.holder) {", "if (false as boolean) {", 'hop issuer not required to be the previous holder', 'run'),
 ('server/verify.ts', "leaf.caveats.slice(opts.grant.caveats.length)", "leaf.caveats.slice(-1)", 'only the last delegated caveat enforced (NO_ANCESTOR_CAV)', 'run'),
 ('replay.ts', "if (until !== undefined && until >= nowMs) return Promise.resolve(false);", "if (until !== undefined && until > nowMs) return Promise.resolve(false);", 'retention boundary off-by-one (nonce resurrected at exp+skew)', 'seq'),
 ('replay.ts', "if (last !== undefined && !(counter > last)) return Promise.resolve(false);", "if (last !== undefined && !(counter >= last)) return Promise.resolve(false);", 'counter not strictly increasing', 'seq'),
 ('threshold.ts', "if (prevRole !== undefined && prevRole !== s.role) return fail('signer set registers one key under two roles');", "", 'one key allowed under two roles (NO_SET_DISTINCT)', 'thr'),
 ('threshold.ts', "const signed = shareMessage(share.role, message, signerSet, t, share.alg);", "const signed = shareMessage(share.role, message, signerSet, 1, share.alg);", 'share not bound to t (UNBOUND_SHARE)', 'thr'),
]
def run(root, kind):
    cwd = os.path.join(root, 'tools/pca-formal/conformance')
    tsx = os.path.join(root, 'packages/pca/node_modules/.bin/tsx')
    cmd = {'run': [tsx, 'run.ts', 'single-rand', str(N), '11'], 'seq': [tsx, 'seq.ts', 'rand', '200', '11'], 'thr': [tsx, 'thr.ts', 'rand', '4000', '11']}[kind]
    out = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    try: d = json.loads(out.stdout.strip().splitlines()[-1])
    except Exception: return None, out.stderr[-300:]
    return d, ''
results = []
for (f, old, new, name, kind) in MUT:
    tmp = tempfile.mkdtemp(prefix='pcamut-')
    try:
        os.makedirs(os.path.join(tmp, 'tools/pca-formal'))
        shutil.copytree(os.path.join(REPO, 'tools/pca-formal/conformance'), os.path.join(tmp, 'tools/pca-formal/conformance'))
        os.makedirs(os.path.join(tmp, 'packages/pca'))
        shutil.copytree(os.path.join(REPO, 'packages/pca/src'), os.path.join(tmp, 'packages/pca/src'), ignore=shutil.ignore_patterns('*.test.ts'))
        for n in ('package.json', 'tsconfig.json'): shutil.copy(os.path.join(REPO, 'packages/pca', n), os.path.join(tmp, 'packages/pca', n))
        shutil.copy(os.path.join(REPO, 'tsconfig.base.json'), tmp)
        os.symlink(os.path.join(REPO, 'packages/pca/node_modules'), os.path.join(tmp, 'packages/pca/node_modules'))
        os.symlink(os.path.join(REPO, 'node_modules'), os.path.join(tmp, 'node_modules'))
        p = os.path.join(tmp, 'packages/pca/src', f)
        s = open(p).read()
        if s.count(old) != 1:
            results.append((name, f, 'PATTERN-NOT-UNIQUE (%d)' % s.count(old))); continue
        open(p, 'w').write(s.replace(old, new))
        d, err = run(tmp, kind)
        if d is None: results.append((name, f, 'ERROR ' + err)); continue
        tot = d.get('n', d.get('sequences', d.get('cases')))
        results.append((name, f, ('KILLED' if d['disagree'] > 0 else 'SURVIVED') + ' (disagree %d of %d)' % (d['disagree'], tot)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
for name, f, r in results: print('%-62s %-18s %s' % (name, f, r))
