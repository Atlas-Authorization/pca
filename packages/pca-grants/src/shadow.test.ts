import { describe, expect, it } from 'vitest';
import { assembleBundle, bundleDigest, signBundle, verifyBundle, type DecisionKind, type PolicyBundleBody } from './bundle';
import {
  ShadowLog, promoteShadow, promotionGate, runShadow, shadowRecordField, signPromotionApproval, signWideningExplanation, verifyShadowDiff, type GateOptions,
} from './shadow';
import { b64u, publicKeyOf } from '@atlasauth/pca';

const LOGK = new Uint8Array(32).fill(41);
const PRINCIPAL = new Uint8Array(32).fill(42);
const P = b64u(publicKeyOf(PRINCIPAL));
const OTHER = new Uint8Array(32).fill(43);
const body = (over: Partial<PolicyBundleBody> = {}): PolicyBundleBody => ({ v: 1, kind: 'pca-policy-bundle', revision: 1, grants: ['g1'], template_digests: [], min_verifier_version: '0.5.0', issued_at: 1000, ...over });
const CAND = body({ grants: ['g1', 'g2'] });
const CD = bundleDigest(CAND);
const ENF = body({ shadow: [CD] });
const ED = bundleDigest(ENF);
type In = { n: number };
const enforced = (i: In): DecisionKind => (i.n < 5 ? 'allow' : i.n < 8 ? 'escalate' : 'deny');

function observe(log: ShadowLog, candidate: (i: In) => DecisionKind, inputs: number[]) {
  for (const n of inputs) {
    const r = runShadow({ n }, enforced, [{ digest: CD, decide: candidate }]);
    log.observe({ enforced_digest: ED, action_digest: `a${n}`, enforced: r.decision, outcome: r.shadow[0]!, at: 5 });
  }
}
const opts = (over: Partial<GateOptions> = {}): GateOptions => ({ shadow_digest: CD, enforced_digest: ED, minSamples: 3, principals: [P], surface: 'narrower', ...over });

describe('runShadow', () => {
  it('returns the enforced decision whatever the candidate does', () => {
    const calls: string[] = [];
    const r = runShadow({ n: 9 }, (i) => { calls.push('enforced'); return enforced(i); }, [
      { digest: 'permissive', decide: () => { calls.push('c1'); return 'allow'; } },
      { digest: 'throws', decide: () => { throw new Error('boom'); } },
      { digest: 'garbage', decide: () => 'maybe' as never },
      { digest: 'same', decide: () => 'deny' },
      { digest: 'tighter', decide: () => 'deny' },
    ]);
    expect(r.decision).toBe('deny');
    expect(calls).toEqual(['enforced', 'c1']);
    expect(r.shadow).toEqual([
      { digest: 'permissive', decision: 'allow', diverged: true, widening: true },
      { digest: 'throws', decision: 'error', diverged: false, widening: false },
      { digest: 'garbage', decision: 'error', diverged: false, widening: false },
      { digest: 'same', decision: 'deny', diverged: false, widening: false },
      { digest: 'tighter', decision: 'deny', diverged: false, widening: false },
    ]);
  });
  it('a candidate mutating its input cannot change what the enforced policy sees later', () => {
    const input = { n: 1 };
    runShadow(input, enforced, [{ digest: 'm', decide: (i) => { i.n = 99; return 'allow'; } }]);
    expect(input.n).toBe(1);
  });
  it('marks a tightening divergence as not widening', () => {
    expect(runShadow({ n: 1 }, enforced, [{ digest: 't', decide: () => 'deny' }]).shadow[0]).toEqual({ digest: 't', decision: 'deny', diverged: true, widening: false });
  });
  it('shadowRecordField drops the widening flag', () => {
    expect(shadowRecordField([{ digest: 'a', decision: 'allow', diverged: true, widening: true }])).toEqual([{ digest: 'a', decision: 'allow', diverged: true }]);
  });
});

describe('ShadowLog', () => {
  it('counts every observation and keeps a signed diff per divergence', () => {
    const log = new ShadowLog(LOGK);
    observe(log, (i) => (i.n === 1 ? 'deny' : i.n === 6 ? 'allow' : enforced(i)), [1, 2, 6, 9]);
    expect(log.stats(CD)).toEqual({ total: 4, diverged: 2, widened: 1, tightened: 1, errors: 0 });
    const d = log.diffs(CD);
    expect(d.map((x) => [x.action_digest, x.enforced, x.shadow, x.widening])).toEqual([['a1', 'allow', 'deny', false], ['a6', 'escalate', 'allow', true]]);
    expect(d.every((x) => verifyShadowDiff(x, log.signer))).toBe(true);
    expect(verifyShadowDiff({ ...d[0]!, shadow: 'allow' })).toBe(false);
    expect(verifyShadowDiff(d[0], b64u(publicKeyOf(OTHER)))).toBe(false);
    expect(log.stats('unknown')).toEqual({ total: 0, diverged: 0, widened: 0, tightened: 0, errors: 0 });
  });
  it('a candidate error is counted, not diffed', () => {
    const log = new ShadowLog(LOGK);
    observe(log, () => { throw new Error('x'); }, [1]);
    expect(log.stats(CD)).toEqual({ total: 1, diverged: 0, widened: 0, tightened: 0, errors: 1 });
    expect(log.diffs(CD)).toEqual([]);
  });
});

describe('promotionGate', () => {
  const tighter = (i: In): DecisionKind => (enforced(i) === 'allow' ? 'escalate' : enforced(i));
  it('passes a candidate that only tightens', () => {
    const log = new ShadowLog(LOGK);
    observe(log, tighter, [1, 2, 6]);
    expect(promotionGate(log, opts())).toEqual({ ok: true, samples: 3, widenings: 0, surface: 'narrower' });
  });
  it('needs enough samples', () => {
    const log = new ShadowLog(LOGK);
    observe(log, tighter, [1, 2]);
    expect(promotionGate(log, opts())).toMatchObject({ ok: false, code: 'too_few_samples', reason: '2 observation(s), need 3' });
  });
  it('refuses when the candidate failed even once', () => {
    const log = new ShadowLog(LOGK);
    observe(log, tighter, [1, 2, 6]);
    observe(log, () => { throw new Error('x'); }, [3]);
    expect(promotionGate(log, opts())).toMatchObject({ ok: false, code: 'shadow_errors' });
  });
  const widening = (i: In): DecisionKind => (i.n === 6 ? 'allow' : enforced(i));
  it('an unexplained widening blocks promotion and names the action', () => {
    const log = new ShadowLog(LOGK);
    observe(log, widening, [1, 2, 6]);
    expect(promotionGate(log, opts())).toMatchObject({ ok: false, code: 'unexplained_widening', unexplained: ['a6'] });
  });
  it('a principal explanation for exactly that action unblocks it; others do not', () => {
    const log = new ShadowLog(LOGK);
    observe(log, widening, [1, 2, 6]);
    const mine = signWideningExplanation(PRINCIPAL, { shadow_digest: CD, action_digest: 'a6', reason_digest: 'r' });
    expect(promotionGate(log, opts({ explanations: [mine] }))).toEqual({ ok: true, samples: 3, widenings: 1, surface: 'narrower' });
    const wrongAction = signWideningExplanation(PRINCIPAL, { shadow_digest: CD, action_digest: 'a1', reason_digest: 'r' });
    const wrongCandidate = signWideningExplanation(PRINCIPAL, { shadow_digest: 'other', action_digest: 'a6', reason_digest: 'r' });
    const stranger = signWideningExplanation(OTHER, { shadow_digest: CD, action_digest: 'a6', reason_digest: 'r' });
    const forged = { ...mine, action_digest: 'a6', reason_digest: 'tampered' };
    for (const e of [wrongAction, wrongCandidate, stranger, forged, 'junk', null]) expect(promotionGate(log, opts({ explanations: [e] })).ok).toBe(false);
  });
  it('a wider or unprovable surface needs a principal approval for this pair', () => {
    const log = new ShadowLog(LOGK);
    observe(log, tighter, [1, 2, 6]);
    for (const surface of ['wider', 'unknown'] as const) {
      expect(promotionGate(log, opts({ surface }))).toMatchObject({ ok: false, code: 'advisory_wider' });
      const ok = signPromotionApproval(PRINCIPAL, { shadow_digest: CD, enforced_digest: ED, at: 9 });
      expect(promotionGate(log, opts({ surface, approval: ok }))).toMatchObject({ ok: true, surface });
      for (const bad of [signPromotionApproval(OTHER, { shadow_digest: CD, enforced_digest: ED, at: 9 }), signPromotionApproval(PRINCIPAL, { shadow_digest: 'x', enforced_digest: ED, at: 9 }), signPromotionApproval(PRINCIPAL, { shadow_digest: CD, enforced_digest: 'x', at: 9 }), { ...ok, at: 10 }, undefined]) {
        expect(promotionGate(log, opts({ surface, approval: bad }))).toMatchObject({ ok: false, code: 'advisory_wider' });
      }
    }
  });
  it('refuses diffs recorded against another enforced revision, and bad options', () => {
    const log = new ShadowLog(LOGK);
    observe(log, tighter, [1, 2, 6]);
    expect(promotionGate(log, opts({ enforced_digest: 'later-revision' }))).toMatchObject({ ok: false, code: 'bad_diff' });
    expect(promotionGate(log, opts({ minSamples: 0 }))).toMatchObject({ ok: false, code: 'bad_input' });
    expect(promotionGate(log, opts({ surface: 'sideways' as never }))).toMatchObject({ ok: false, code: 'bad_input' });
  });
});

describe('bundle shadow member and promotion', () => {
  const S1 = new Uint8Array(32).fill(51);
  it('shadow is covered by the bundle signature and validated', () => {
    const sig = signBundle(ENF, S1);
    const b = assembleBundle(ENF, [sig]);
    const signer = sig.signer;
    expect(verifyBundle(b, { signers: [signer], threshold: 1, verifierVersion: '0.5.0' })).toMatchObject({ ok: true });
    expect(verifyBundle({ ...b, shadow: [] }, { signers: [signer], threshold: 1, verifierVersion: '0.5.0' })).toMatchObject({ ok: false, code: 'malformed' });
    expect(verifyBundle({ ...b, shadow: [CD, CD] }, { signers: [signer], threshold: 1, verifierVersion: '0.5.0' })).toMatchObject({ ok: false, code: 'malformed' });
    expect(verifyBundle({ ...b, shadow: ['other'] }, { signers: [signer], threshold: 1, verifierVersion: '0.5.0' })).toMatchObject({ ok: false, code: 'below_threshold' });
  });
  it('promoteShadow builds the next revision only behind a passing gate for a listed candidate', () => {
    const log = new ShadowLog(LOGK);
    observe(log, (i) => (enforced(i) === 'allow' ? 'escalate' : enforced(i)), [1, 2, 6]);
    const gate = promotionGate(log, opts());
    const next = promoteShadow(ENF, CAND, gate, 2000);
    expect(next).toEqual({ ...CAND, revision: 2, prev: ED, issued_at: 2000 });
    expect(next.shadow).toBeUndefined();
    const sig = signBundle(next, S1);
    expect(verifyBundle(assembleBundle(next, [sig]), { signers: [sig.signer], threshold: 1, verifierVersion: '0.5.0', last: { revision: 1, digest: ED } })).toMatchObject({ ok: true, revision: 2 });
    expect(() => promoteShadow(ENF, CAND, { ok: false, code: 'too_few_samples', reason: 'x' }, 2000)).toThrow('the gate did not pass (too_few_samples)');
    expect(() => promoteShadow(body(), CAND, gate, 2000)).toThrow("not listed in the enforced revision's shadow");
    expect(() => promoteShadow(ENF, body({ grants: ['zzz'] }), gate, 2000)).toThrow("not listed");
    expect(() => promoteShadow(ENF, CAND, gate, 1.5)).toThrow('bad time');
  });
});
