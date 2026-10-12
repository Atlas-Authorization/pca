// record-corpus.test.ts - run the REAL conformance corpus (vectors.json + vectors-adversarial.json.gz, 3,221 decodable vectors
// + 1,278 parse-time rejects) through the PRODUCTION verifier (packages/pca/src: verifyPCActn / verifyPCActnCore, which call the
// verified core through the bridge) and RECORD every call the glue makes into the verified core as one case line of the
// diverse-compilation case grammar (see gen-cases.mjs / formal/dafny/difftargets/Harness.dfy). Lazy closures are evaluated
// eagerly (they are pure; a case whose closure throws is dropped). The resulting file is then replayed through every compiled
// Dafny target (cs/go/java/py/js) and the bridge by formal/dafny/difftargets/crosscheck.sh: so the compiled targets are exercised
// on the exact distribution of facts production produces, not only on synthetic inputs.
//   PCA_RECORD_OUT=/path/corpus.cases pnpm vitest run test/diverse/record-corpus.test.ts
import { writeFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';

const { LINES, B, resI, STAT, safe, dropped } = vi.hoisted(() => {
  const LINES: string[] = [];
  const dropped = { n: 0 };
  const messages = new Map<string, number>();
  const mid = (m: unknown): number => {
    const k = typeof m === 'string' ? m : JSON.stringify(m);
    let v = messages.get(k);
    if (v === undefined) { v = messages.size; messages.set(k, v); }
    return v;
  };
  const B = (b: unknown) => (b ? 1 : 0);
  const resI = (r: { ok: boolean; m?: unknown }) => (r.ok ? -1 : mid(r.m));
  const STAT = (s: string | undefined) => (s === undefined ? -1 : s === 'pass' ? 0 : s === 'fail' ? 1 : 2);
  const safe = (n: unknown) => (typeof n === 'number' && Number.isSafeInteger(n) ? n : 0);
  return { LINES, mid, B, resI, STAT, safe, dropped };
});

vi.mock('../../src/verdict', async (orig) => {
  const m = await orig<typeof import('../../src/verdict')>();
  const rec = <A extends unknown[], R>(f: (...a: A) => R, line: (a: A) => string): ((...a: A) => R) => (...a: A) => { const r = f(...a); try { LINES.push(line(a)); } catch { /* unrecordable */ } return r; };
  return {
    ...m,
    audienceStatus: rec(m.audienceStatus, ([h, a, e]) => `aud ${B(h)} ${a === 'absent' ? 0 : a === 'null' ? 1 : 2} ${B(e)}`),
    validityDecision: rec(m.validityDecision, ([c, iat, exp, now]) => `val ${B(c)} ${iat} ${exp} ${c ? now : 0}`),
    versionStatus: rec(m.versionStatus, ([v]) => `ver ${B(v)}`),
    grantRefBoundStatus: rec(m.grantRefBoundStatus, ([a, b, c]) => `gref ${B(a)} ${B(b)} ${B(c)}`),
    counterStatus: rec(m.counterStatus, ([v]) => `ctr ${B(v)}`),
    suitePolicy: rec(m.suitePolicy, ([a, b]) => `suite ${B(a)} ${B(b)}`),
    pqBinding: rec(m.pqBinding, ([a, b, c, d]) => `pqb ${B(a)} ${B(b)} ${B(c)} ${B(d)}`),
    pqResolve: rec(m.pqResolve, ([f]) => `pqr ${B(f.trusted)} ${B(f.artifactKeyOk)} ${B(f.pinPresent)} ${B(f.pinEquals)} ${B(f.commitPresent)} ${B(f.commitMatches)} ${B(f.allowUnbound)}`),
    leafDecision: <M>(present: boolean, suiteErr: () => { ok: boolean; m?: M }, sigIsString: boolean, verify: () => boolean) => {
      const r = m.leafDecision(present, suiteErr as never, sigIsString, verify);
      try { LINES.push(`leaf ${B(present)} ${present ? resI(suiteErr()) : -1} ${B(sigIsString)} ${B(verify())}`); } catch { /* */ }
      return r;
    },
    capChainStatus: <M>(ne: boolean, rg: () => boolean, walk: () => { ok: boolean; m?: M }) => {
      const r = m.capChainStatus(ne, rg, walk as never);
      try { LINES.push(`cap ${B(ne)} ${B(ne && rg())} ${ne && rg() ? resI(walk()) : -1}`); } catch { /* */ }
      return r;
    },
    hookStatus: rec(m.hookStatus, ([e, o]) => `hook ${B(e)} ${B(o)}`),
    planDecision: rec(m.planDecision, ([s, r, a]) => `plan ${B(s)} ${B(r)} ${a === undefined ? -1 : B(a)}`),
    beaconDecision: rec(m.beaconDecision, ([a, b, c, d]) => `beacon ${B(a)} ${B(b)} ${B(c)} ${B(d)}`),
    reversibilityDecision: rec(m.reversibilityDecision, ([d, s]) => `rev ${d} ${s === undefined ? -1 : s}`),
    thresholdRule: rec(m.thresholdRule, ([t, rel, th, ht]) => `thr ${t} ${B(rel)} ${STAT(th)} ${ht === undefined ? 'n' : ht}`),
  };
});

vi.mock('../../src/chain', async (orig) => {
  const m = await orig<typeof import('../../src/chain')>();
  return {
    ...m,
    decideChain: (length: number, hopAt: (i: number) => any, ceq: (a: any, b: any) => boolean, alloc: () => any) => {
      const n = Math.min(length, m.MAX_CHAIN_DEPTH + 1);
      const r = m.decideChain(length, hopAt, ceq, alloc);
      try {
        const hops = Array.from({ length: n }, (_, i) => hopAt(i));
        const els: any[] = hops.flatMap((h) => [...h.caveats]);
        const cls: number[] = []; // equivalence classes of caveat elements under production ceq
        const reps: any[] = [];
        const safeEq = (a: any, b: any) => { try { return ceq(a, b); } catch { return false; } };
        const clsOf = (e: any) => { for (let k = 0; k < reps.length; k++) if (safeEq(e, reps[k]) && safeEq(reps[k], e)) return k; reps.push(e); return reps.length - 1; };
        void cls;
        const parts = hops.map((h) => {
          const cv = [...h.caveats].map(clsOf);
          // a closure that throws was never reached by production (decideChain returned normally), so any substitute value is behaviourally irrelevant
          const tv = <T>(f: () => T, d: T): T => { try { return f(); } catch { return d; } };
          return `${B(h.wellTyped)} ${B(h.hasParent)} ${B(h.rootIssuerOk)} ${cv.length} ${cv.join(' ')} ${B(tv(h.parentLinkOk, true))} ${B(tv(h.issuerIsParentHolder, true))} ${resI(tv(h.suite, { ok: true }))} ${resI(tv(h.pq, { ok: true }))} ${resI(tv(h.sig, { ok: true }))}`;
        });
        void els;
        LINES.push(`chain 0 ${n} ${resI((() => { try { return alloc(); } catch { return { ok: true }; } })())} ${parts.join(' ')}`.replace(/\s+/g, ' '));
      } catch (e) { if (dropped.n++ < 3) console.log('chain record dropped:', String(e)); }
      return r;
    },
  };
});

vi.mock('../../src/threshold', async (orig) => {
  const m = await orig<typeof import('../../src/threshold')>();
  const R: Record<string, number> = { agent: 0, guardian: 1, principal: 2 };
  return {
    ...m,
    decideThreshold: (signers: any[], shares: any[], t: number, baseline: any) => {
      const r = m.decideThreshold(signers, shares, t, baseline);
      try {
        const keys = new Map<unknown, number>(); const kid = (k: unknown) => { let v = keys.get(k); if (v === undefined) { v = keys.size + 10; keys.set(k, v); } return v; };
        const sg = signers.map((s) => `${s.role === undefined ? -1 : R[s.role]} ${B(s.keyOk)} ${B(s.pqOk)} ${kid(s.key)}`);
        const sh = shares.map((s) => `${B(s.wellFormed)} ${s.role === undefined ? -1 : R[s.role]} ${kid(s.key)} ${B(s.algKnown)} ${B(s.pqPkOk)} ${B(s.sigOk())}`);
        const bl = baseline ? ` 1 ${B(baseline.holderIsString)} ${kid(baseline.holder)} ${B(baseline.pqKeyOk())} ${B(baseline.leafSigOk())}` : ' 0';
        LINES.push(`th2 ${t} ${signers.length} ${sg.join(' ')} ${shares.length} ${sh.join(' ')}${bl}`.replace(/\s+/g, ' '));
      } catch { /* */ }
      return r;
    },
  };
});

vi.mock('../../src/replay', async (orig) => {
  const m = await orig<typeof import('../../src/replay')>();
  return {
    ...m,
    replayPre: (f: any) => {
      try { LINES.push(`rp ${B(f.nowOk)} ${B(f.verifierAudOk)} ${B(f.isObject)} ${B(f.audMatches)} ${B(f.iatOk)} ${B(f.expOk)} ${f.iatOk ? safe(f.iat) : 0} ${f.expOk ? safe(f.exp) : 0} ${f.nowOk ? safe(f.now) : 0} ${f.skew} ${B(f.leafOk)} ${B(f.componentsOk)} ${B(f.counterOk)} ${B(f.hasNonce)} ${B(f.nonceOk)} ${B(f.requireNonce)} ${B(f.hasCounters)}`); } catch { /* */ }
      return m.replayPre(f);
    },
  };
});

import { decodePCActn, verifyPCActnCore as coreWired } from '../../../pca/src/pcactn';
import { verifyPCActn as verifyWired } from '../../../pca/src/server/verify';
import { loadCorpus } from '../support/corpus';

describe('record the production facts for the conformance corpus', () => {
  it('records core + full-verifier calls for every vector', async () => {
    const { core, adversarial } = loadCorpus();
    let n = 0;
    for (const v of [...core, ...adversarial]) {
      let p: any = v.pcactn;
      if (v.pcactn_json !== undefined) {
        try { p = decodePCActn(v.pcactn_json); } catch { await verifyWired(v.pcactn_json, { grant: v.grant, now: v.context.now, audience: v.context.aud } as never); continue; }
      }
      const o = { grant: v.grant, nowEpoch: v.context.now, audience: v.context.aud };
      await coreWired(p, o);
      for (const extra of n % 3 === 0 ? [{}, { require: ['counter', 'revocation', 'audience', 'validity', 'grant_ref_bound'] }, { allowedSuites: ['ed25519'] }] : [{}]) {
        await verifyWired(p, { grant: v.grant, now: v.context.now, audience: v.context.aud, ...extra } as never);
      }
      n++;
    }
    expect(n).toBeGreaterThan(3000);
    const kinds = new Map<string, number>();
    for (const l of LINES) kinds.set(l.split(' ')[0]!, (kinds.get(l.split(' ')[0]!) ?? 0) + 1);
    // eslint-disable-next-line no-console
    console.log('recorded', LINES.length, 'calls', Object.fromEntries(kinds));
    expect(LINES.length).toBeGreaterThan(5000);
    expect((kinds.get('chain') ?? 0)).toBeGreaterThan(1000);
    const out = process.env.PCA_RECORD_OUT;
    if (out) writeFileSync(out, LINES.join('\n') + '\n');
  });
});
