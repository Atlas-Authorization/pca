import { describe, expect, it } from 'vitest';
import type { PCActn, PolicyDecision, VerifyResult } from '@atlasauth/pca';
import { cleanText, explainChain, explainDecision, explainVerification } from './index';

const pcactn = { ver: 2, aud: 'ins_1', iat: 1, exp: 2, counter: 1, grant_ref: 'g', action: { verb: 'v', resource: 'r' }, plan: { root: 'p', node_id: 'n' }, cap_chain: [] } as unknown as PCActn;
const allPass = { wire: 'pass', version: 'pass', audience: 'pass', validity: 'pass', cap_chain: 'pass', plan_inclusion: 'pass', leaf_signature: 'pass', counter: 'pass' };
const vr = (over: object): VerifyResult => ({ allow: true, checks: allPass, ...over }) as unknown as VerifyResult;

describe('explainVerification never presents a denial as an allow', () => {
  it('only an explicit allow: true with no failing check is an allow', () => {
    expect(explainVerification(pcactn, vr({})).verdict).toBe('allow');
    for (const allow of ['false', 'true', 1, {}, [], 'yes', null, undefined]) {
      const e = explainVerification(pcactn, vr({ allow, reason: 'nope' }));
      expect([e.verdict, e.allow], String(allow)).toEqual(['deny', false]);
    }
  });
  it('an allow that a failing check contradicts is explained as a denial, naming the check', () => {
    const e = explainVerification(pcactn, vr({ checks: { ...allPass, leaf_signature: 'fail' } }));
    expect([e.verdict, e.allow, e.decisive?.name]).toEqual(['deny', false, 'leaf_signature']);
    expect(e.summary).toBe('Denied: the verifier result says allow but the "leaf signature" check failed (inconsistent result, treated as a denial).');
  });
  it('a plain denial names the decisive check', () => {
    const e = explainVerification(pcactn, vr({ allow: false, checks: { ...allPass, audience: 'fail' }, reason: 'audience: aud mismatch' }));
    expect(e.verdict).toBe('deny');
    expect(e.decisive?.name).toBe('audience');
    expect(e.decisive?.detail).toBe('aud mismatch');
    expect(e.summary).toBe('Denied at the "audience binding" check: aud mismatch');
  });
  it('an allow with no per-check statuses is a denial', () => {
    for (const checks of [undefined, null, 5, [], 'x']) expect(explainVerification(pcactn, { allow: true, checks } as never).summary).toBe('Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial).');
  });
  it('is total: a missing or malformed input is a denial, never a throw', () => {
    const cases: [unknown, unknown][] = [[null, null], [undefined, vr({})], [pcactn, null], [pcactn, 5], [5, vr({})], [{ cap_chain: 5 }, vr({ checks: { cap_chain: 'fail' } })], [pcactn, { allow: true, checks: 5 }]];
    for (const [p, r] of cases) {
      const e = explainVerification(p as never, r as never);
      expect(e.verdict, JSON.stringify([p, r])).toBe('deny');
      expect(typeof e.toText()).toBe('string');
    }
    const none = explainVerification(null as never, null as never);
    expect(none.summary).toBe('Denied: the PCActn or the verifier result is missing');
    expect(none.decisive?.name).toBe('malformed');
  });
});

describe('explainDecision never presents a denial as an allow', () => {
  const decision = (over: object): PolicyDecision =>
    ({ admit: false, needStepUp: true, releaseGuardianShare: true, r: 0.5, requiredThreshold: { t: 2, proof: 'guardian', optimisticAllowed: false }, budget: { B: 1, tau: 0, asOf: 0 }, reasons: [], ...over }) as unknown as PolicyDecision;
  it('admission is strict: a truthy non-boolean is not an admit', () => {
    for (const admit of ['true', 1, {}, [], 'yes']) {
      const e = explainDecision(pcactn, decision({ admit }));
      expect([e.verdict, e.disposition, e.admission.admit], String(admit)).toEqual(['deny', 'step-up', false]);
    }
    expect(explainDecision(pcactn, decision({ admit: true })).verdict).toBe('allow');
    expect(explainDecision(pcactn, decision({ releaseGuardianShare: 'yes' })).disposition).toBe('denied');
  });
  it('a missing or malformed decision is a default-deny explanation', () => {
    for (const d of [null, undefined, 5, 'x', {}, { admit: true }, { admit: true, requiredThreshold: null }]) {
      const e = explainDecision(pcactn, d as never);
      expect([e.verdict, e.disposition], JSON.stringify(d)).toEqual(['deny', 'denied']);
      expect(e.reasons).toEqual(['no policy decision supplied (default-deny)']);
    }
  });
  it('an envelope or context that makes the explainer throw degrades to a denial', () => {
    const bad = { envelope: { predicates: 5 } as never, context: { action: {} as never } };
    const e = explainDecision(pcactn, decision({ admit: true }), bad);
    expect(e.verdict === 'allow' || e.verdict === 'deny').toBe(true);
    const boom = explainDecision(pcactn, decision({ admit: true, requiredThreshold: { get t(): never { throw new Error('x'); } } }));
    expect([boom.verdict, boom.reasons]).toEqual(['deny', ['the policy decision could not be explained (default-deny)']]);
  });
});

describe('explainChain says what it checked', () => {
  const chain = [{ id: 'a', issuer: 'P'.repeat(43), holder: 'H'.repeat(43), caveats: [], sig: 's' }] as never;
  it('an unverified trace is labelled as such', () => {
    const e = explainChain(chain);
    expect(e.verification).toBeUndefined();
    expect(e.toText().split('\n')[1]).toBe('UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.');
  });
  it('verify: true records the verdict and its reason', () => {
    const e = explainChain(chain, { verify: true });
    expect(e.verification?.ok).toBe(false);
    expect(e.toText()).toContain('NOT VALID: ');
    expect(explainChain(5 as never, { verify: true }).verification).toEqual({ ok: false, reason: 'chain is not an array' });
  });
  it('a non-array chain explains as empty', () => {
    expect(explainChain(null as never).summary).toBe('empty chain (no authority)');
  });
});

describe('no credential in an explanation', () => {
  const JWT = 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c2VyMSJ9.c2lnbmF0dXJlYnl0ZXM';
  const leaky = { ...pcactn, aud: `https://u:hunter2@host/x?token=${JWT}`, action: { verb: 'db.query', resource: `https://api/x?api_key=${"sk_" + "live_" + "x".repeat(32)}` } } as unknown as PCActn;
  it('the verification text and fields', () => {
    const e = explainVerification(leaky, vr({ allow: false, checks: { ...allPass, audience: 'fail', plan_inclusion: 'fail' } }));
    const dump = JSON.stringify(e) + e.toText();
    for (const s of ['hunter2', JWT, 'sk_live_xxxxxxxxxx']) expect(dump).not.toContain(s);
    expect(e.decisive?.detail).toContain('[redacted]');
  });
  it('a caveat value and a verifier reason in a decision', () => {
    const d = explainDecision(leaky, { admit: false, needStepUp: false, releaseGuardianShare: false, r: 1, requiredThreshold: { t: 3, proof: 'human', optimisticAllowed: false }, budget: { B: 0, tau: 0, asOf: 0 }, reasons: [`caveat(s) not satisfied: x`, `denied for Authorization: Bearer ${JWT}`] } as never);
    expect(JSON.stringify(d)).not.toContain(JWT);
  });
  it('cleanText keeps ordinary text', () => {
    for (const t of ['stripe.refund on charge:ch_1', 'aud "ins_1" matches', 'hop 2: bad signature']) expect(cleanText(t)).toBe(t);
    expect(cleanText('x'.repeat(401))).toBe(`${'x'.repeat(401).replace(/x{40,}/, '[redacted]')}`);
  });
});
