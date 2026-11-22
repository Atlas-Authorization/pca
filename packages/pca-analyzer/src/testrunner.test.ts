import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { generateBoundaryTests, policyTestsDoc, runPolicyTests, signPolicyTests, verifyPolicyTests, type PolicyInput } from './index';
import { refund } from './k2-fixtures';

const policy: PolicyInput = { predicates: [refund(500)], vetoes: [{ id: 'frozen', kind: 'deny', when: { verb: 'stripe.refund', resource: '/acct/frozen*' } }] };
const at = (amount: number, resource = '/acct/1') => ({ verb: 'stripe.refund', resource, params: { amount } });

describe('runPolicyTests', () => {
  const doc = policyTestsDoc(policy, [
    { name: 'small refund', action: at(100), expect: 'allow', decidedBy: 'permit[0]' },
    { name: 'at the cap', action: at(500), expect: 'allow' },
    { name: 'over the cap', action: at(501), expect: 'deny' },
    { name: 'frozen account', action: at(1, '/acct/frozen1'), expect: 'deny', decidedBy: 'frozen' },
  ]);

  it('passes on the policy it was written for', () => {
    expect(runPolicyTests(policy, doc, { requireDigest: true })).toEqual({ total: 4, passed: 4, failures: [], digestMatch: true, ok: true });
  });

  it('a loosened policy fails the case it changes, naming the decision and the clause', () => {
    const loose: PolicyInput = { ...policy, predicates: [refund(600)] };
    const r = runPolicyTests(loose, doc);
    expect(r.ok).toBe(false);
    expect(r.failures).toEqual([{ name: 'over the cap', expected: 'deny', got: 'allow', decidedBy: 'permit[0]' }]);
    expect(r.digestMatch).toBe(false);
  });

  it('a policy that drifts but passes every case still fails when the digest is required', () => {
    const drift: PolicyInput = { ...policy, predicates: [{ ...refund(500), resource: '/acct/*' }, { verb: 'stripe.list' }] };
    expect(runPolicyTests(drift, doc).ok).toBe(true);
    expect(runPolicyTests(drift, doc, { requireDigest: true })).toMatchObject({ ok: false, digestMatch: false });
  });

  it('asserts the deciding clause', () => {
    const wrong = policyTestsDoc(policy, [{ name: 'x', action: at(1, '/acct/frozen1'), expect: 'deny', decidedBy: 'permit[0]' }]);
    expect(runPolicyTests(policy, wrong).failures).toEqual([{ name: 'x', expected: 'deny', got: 'deny', decidedBy: 'frozen', expectedDecidedBy: 'permit[0]' }]);
  });

  it('signed examples verify, and any edit breaks the signature', () => {
    const k = generateKeyPair();
    const pub = b64u(k.publicKey);
    const s = signPolicyTests(doc, k.secretKey, pub);
    expect(verifyPolicyTests(s, pub)).toBe(true);
    expect(verifyPolicyTests({ ...s, doc: { ...doc, cases: doc.cases.slice(1) } }, pub)).toBe(false);
    expect(verifyPolicyTests(s, b64u(generateKeyPair().publicKey))).toBe(false);
  });
});

describe('generateBoundaryTests', () => {
  const gen = generateBoundaryTests(policy);
  it('writes a minimal allow, the points around each threshold, a trigger per prohibition and an unmentioned resource', () => {
    const names = gen.cases.map((c) => c.name);
    expect(names).toContain('permit[0]: minimal admitted action');
    // the point just below the cap IS the minimal admitted action (499), so it is not repeated
    expect(names).toEqual(['permit[0]: minimal admitted action', 'permit[0]: amount at 500', 'permit[0]: amount above 500', 'permit[0]: unmentioned resource', 'frozen: trigger']);
    const by = (n: string) => gen.cases.find((c) => c.name === n)!;
    expect(by('permit[0]: minimal admitted action').action.params).toEqual({ amount: 499 });
    expect(by('permit[0]: amount at 500').expect).toBe('allow');
    expect(by('permit[0]: amount above 500').expect).toBe('deny');
    expect(by('frozen: trigger')).toMatchObject({ expect: 'deny', decidedBy: 'frozen' });
  });

  it('the generated examples pass the policy they came from, and catch a widened cap', () => {
    expect(runPolicyTests(policy, gen, { requireDigest: true }).ok).toBe(true);
    const widened = runPolicyTests({ ...policy, predicates: [refund(501)] }, gen);
    expect(widened.ok).toBe(false);
    expect(widened.failures.map((f) => f.name)).toEqual(['permit[0]: amount above 500']);
    expect(runPolicyTests({ ...policy, predicates: [refund(499)] }, gen).failures.map((f) => f.name)).toEqual(['permit[0]: amount at 500']);
  });

  it('is deterministic', () => {
    expect(JSON.stringify(generateBoundaryTests(policy))).toBe(JSON.stringify(gen));
  });
});
