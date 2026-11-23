import { describe, expect, it } from 'vitest';
import { bundleDigest, type DecisionKind, type PolicyBundleBody } from './bundle';
import {
  PROMOTION_APPROVAL_DOMAIN,
  SHADOW_DIFF_DOMAIN,
  WIDENING_EXPLANATION_DOMAIN,
  ShadowLog,
  promotionGate,
  runShadow,
  verifyShadowDiff,
  type GateOptions,
} from './shadow';
import { signBody, signerOf } from './sig';

const LOGK = new Uint8Array(32).fill(51);
const PRINCIPAL = new Uint8Array(32).fill(52);
const LOGP = signerOf(LOGK);
const P = signerOf(PRINCIPAL);
const body = (over: Partial<PolicyBundleBody> = {}): PolicyBundleBody => ({ v: 1, kind: 'pca-policy-bundle', revision: 1, grants: ['g1'], template_digests: [], min_verifier_version: '0.5.0', issued_at: 1000, ...over });
const CD = bundleDigest(body({ grants: ['g1', 'g2'] }));
const ED = bundleDigest(body({ shadow: [CD] }));
type In = { n: number };
const enforced = (i: In): DecisionKind => (i.n < 5 ? 'allow' : i.n < 8 ? 'escalate' : 'deny');

function observe(log: ShadowLog, candidate: (i: In) => DecisionKind, inputs: number[]) {
  for (const n of inputs) {
    const r = runShadow({ n }, enforced, [{ digest: CD, decide: candidate }]);
    log.observe({ enforced_digest: ED, action_digest: `a${n}`, enforced: r.decision, outcome: r.shadow[0]!, at: 5 });
  }
}
const opts = (over: Partial<GateOptions> = {}): GateOptions => ({ shadow_digest: CD, enforced_digest: ED, minSamples: 2, principals: [P], surface: 'narrower', ...over });
const diffBase = { v: 1, shadow_digest: CD, enforced_digest: ED, action_digest: 'a1', enforced: 'deny', shadow: 'allow', widening: true, at: 5, signer: LOGP };
const signedDiff = (over: Record<string, unknown> = {}) => {
  const b = { ...diffBase, ...over };
  return { ...b, sig: signBody(SHADOW_DIFF_DOMAIN, b, LOGK) };
};
const explanation = (over: Record<string, unknown> = {}) => {
  const b = { v: 1, shadow_digest: CD, action_digest: 'a9', reason_digest: 'r', principal: P, ...over };
  return { ...b, sig: signBody(WIDENING_EXPLANATION_DOMAIN, b, PRINCIPAL) };
};
const approval = (over: Record<string, unknown> = {}) => {
  const b = { v: 1, shadow_digest: CD, enforced_digest: ED, at: 5, principal: P, ...over };
  return { ...b, sig: signBody(PROMOTION_APPROVAL_DOMAIN, b, PRINCIPAL) };
};
const widened = () => {
  const log = new ShadowLog(LOGK);
  observe(log, () => 'allow', [9, 8]);
  return log;
};

describe('verifyShadowDiff', () => {
  it('accepts a genuine diff and rejects a change to any signed field', () => {
    expect(verifyShadowDiff(signedDiff(), LOGP)).toBe(true);
    const d = signedDiff();
    for (const over of [{ at: 6 }, { action_digest: 'a2' }, { shadow_digest: 'x' }, { enforced_digest: 'x' }]) {
      expect(verifyShadowDiff({ ...d, ...over }, LOGP), JSON.stringify(over)).toBe(false);
    }
  });
  it('a genuine signature does not excuse a wrong version, a non-diff or a wrong widening flag', () => {
    expect(verifyShadowDiff(signedDiff({ v: 2 }), LOGP)).toBe(false);
    expect(verifyShadowDiff(signedDiff({ enforced: 'allow', shadow: 'allow', widening: false }), LOGP)).toBe(false);
    expect(verifyShadowDiff(signedDiff({ widening: false }), LOGP)).toBe(false);
    expect(verifyShadowDiff(signedDiff({ enforced: 'allow', shadow: 'deny', widening: true }), LOGP)).toBe(false);
    expect(verifyShadowDiff(signedDiff({ enforced: 'allow', shadow: 'deny', widening: false }), LOGP)).toBe(true);
    expect(verifyShadowDiff(signedDiff({ enforced: 'allow', shadow: 'allow', widening: true }), LOGP)).toBe(false);
    expect(verifyShadowDiff(signedDiff(), 'someone-else')).toBe(false);
  });
});

describe('promotionGate', () => {
  it('bad options are refused with the exact message', () => {
    expect(promotionGate(widened(), opts({ minSamples: 0 }))).toStrictEqual({ ok: false, code: 'bad_input', reason: 'bad gate options' });
  });
  it('candidate failures are counted in the reason', () => {
    const log = new ShadowLog(LOGK);
    observe(log, () => {
      throw new Error('x');
    }, [1, 2]);
    expect(promotionGate(log, opts())).toStrictEqual({ ok: false, code: 'shadow_errors', reason: '2 observation(s) where the candidate failed' });
  });
  it('a single tampered diff among genuine ones fails the gate, as does a diff for another enforced digest', () => {
    const log = widened();
    log.diffs(CD)[0]!.at = 999;
    expect(promotionGate(log, opts())).toMatchObject({ ok: false, code: 'bad_diff', reason: 'a recorded diff does not verify, belongs to another pair, or is missing' });
    const clean = widened();
    expect(promotionGate(clean, opts({ enforced_digest: 'another-enforced' }))).toMatchObject({ ok: false, code: 'bad_diff' });
  });
  it('lists unexplained widenings sorted and counted', () => {
    const r = promotionGate(widened(), opts());
    expect(r).toStrictEqual({ ok: false, code: 'unexplained_widening', reason: "2 widening(s) without a principal's explanation", unexplained: ['a8', 'a9'] });
    const one = promotionGate(widened(), opts({ explanations: [explanation({ action_digest: 'a9' })] }));
    expect(one).toMatchObject({ code: 'unexplained_widening', unexplained: ['a8'] });
  });
  it('explanations that are malformed, unsigned by a principal or for another candidate do not count', () => {
    const both = [explanation({ action_digest: 'a9' }), explanation({ action_digest: 'a8' })];
    expect(promotionGate(widened(), opts({ explanations: both }))).toStrictEqual({ ok: true, samples: 2, widenings: 2, surface: 'narrower' });
    for (const bad of [null, explanation({ v: 2 }), explanation({ reason_digest: '' }), explanation({ shadow_digest: 'other' }), { ...explanation(), sig: 'AAAA' }]) {
      const r = promotionGate(widened(), opts({ explanations: [bad, explanation({ action_digest: 'a8' })] }));
      expect(r, JSON.stringify(bad)).toMatchObject({ ok: false, code: 'unexplained_widening', unexplained: ['a9'] });
    }
    expect(promotionGate(widened(), opts({ principals: [], explanations: both }))).toMatchObject({ code: 'unexplained_widening' });
  });
  it('the surface verdict decides the advisory message and needs a genuine principal approval', () => {
    const both = [explanation({ action_digest: 'a9' }), explanation({ action_digest: 'a8' })];
    const wider = promotionGate(widened(), opts({ explanations: both, surface: 'wider' }));
    expect(wider).toStrictEqual({
      ok: false,
      code: 'advisory_wider',
      reason: 'the analyzer reports the candidate wider on the declared surfaces: a principal-signed approval is required',
    });
    expect(promotionGate(widened(), opts({ explanations: both, surface: 'unknown' }))).toMatchObject({
      reason: 'the analyzer reports the candidate not provably narrower on the declared surfaces: a principal-signed approval is required',
    });
    for (const a of [approval({ v: 2 }), approval({ shadow_digest: 'x' }), approval({ enforced_digest: 'x' }), undefined]) {
      expect(promotionGate(widened(), opts({ explanations: both, surface: 'wider', approval: a })), JSON.stringify(a)).toMatchObject({ code: 'advisory_wider' });
    }
    // a genuinely signed approval from a principal the gate does not list is refused (explanations still count: they come from the listed one)
    const OTHER = new Uint8Array(32).fill(53);
    const b = { v: 1, shadow_digest: CD, enforced_digest: ED, at: 5, principal: signerOf(OTHER) };
    const stranger = { ...b, sig: signBody(PROMOTION_APPROVAL_DOMAIN, b, OTHER) };
    expect(promotionGate(widened(), opts({ explanations: both, surface: 'wider', approval: stranger }))).toMatchObject({ code: 'advisory_wider' });
    expect(promotionGate(widened(), opts({ explanations: both, surface: 'wider', approval: approval(), principals: [] }))).toMatchObject({ code: 'unexplained_widening' });
    expect(promotionGate(widened(), opts({ explanations: both, surface: 'wider', approval: approval() }))).toMatchObject({ ok: true, surface: 'wider' });
  });
  it('an evaluation error fails closed with a typed refusal', () => {
    expect(promotionGate(widened(), opts({ explanations: 5 as never }))).toStrictEqual({ ok: false, code: 'bad_input', reason: 'evaluation error (fail closed)' });
  });
});
