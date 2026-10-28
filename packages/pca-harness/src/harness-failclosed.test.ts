import { describe, expect, it } from 'vitest';
import { type PlanNode, type TrustBudget, type VerifyContext, DEFAULT_RISK_POLICY, encodeKey, generateKeyPair, mintRoot } from '@atlasauth/pca';
import { type Candidate, ENFORCED_CHECKS, HARNESS_MODEL_ID, HARNESS_VERSION, Harness, computeHarnessMeasurement, createHarnessAttestationVerifier } from './index';

const principal = generateKeyPair();
const agentKp = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: pub(principal), holder: pub(agentKp), caveats: [] });
const plan: PlanNode[] = [{ id: 'n1', verb: 'read', resource: 'doc:1' }, { id: 'n2', verb: 'summarize', resource: 'doc:1' }];
const budget = (B = 1): TrustBudget => { const now = Date.now(); return { B, tau: now, asOf: now }; };
const mk = (over: Partial<ConstructorParameters<typeof Harness>[0]> = {}) => new Harness({ grant, agentSecret: agentKp.secretKey, plan, audience: 'ins_t', budget: budget(), ...over });
const trusted: Candidate = { verb: 'read', resource: 'doc:1', nodeId: 'n1', inputs: [{ ref: 'brief', provenance: 'trusted' }] };

describe('harness constants are pinned (they feed the measurement an operator allowlists)', () => {
  it('version, model id and the enforced-check manifest', () => {
    expect(HARNESS_VERSION).toBe('0.1.0');
    expect(HARNESS_MODEL_ID).toBe('@atlasauth/pca-harness');
    expect(ENFORCED_CHECKS).toEqual(['plan_inclusion_before_signing', 'taint_provenance_fold', 'trust_budget_debit', 'pcactn_sign']);
  });
  it('the measurement changes with the version, the manifest order and every gating parameter', () => {
    const m = computeHarnessMeasurement(HARNESS_VERSION, ENFORCED_CHECKS, DEFAULT_RISK_POLICY);
    expect(computeHarnessMeasurement('0.1.1', ENFORCED_CHECKS, DEFAULT_RISK_POLICY)).not.toBe(m);
    expect(computeHarnessMeasurement(HARNESS_VERSION, [...ENFORCED_CHECKS].reverse(), DEFAULT_RISK_POLICY)).not.toBe(m);
    expect(computeHarnessMeasurement(HARNESS_VERSION, ENFORCED_CHECKS, { ...DEFAULT_RISK_POLICY, theta1: DEFAULT_RISK_POLICY.theta1 + 0.01 })).not.toBe(m);
    expect(computeHarnessMeasurement(HARNESS_VERSION, ENFORCED_CHECKS, { ...DEFAULT_RISK_POLICY, theta2: DEFAULT_RISK_POLICY.theta2 + 0.01 })).not.toBe(m);
    expect(computeHarnessMeasurement(HARNESS_VERSION, ENFORCED_CHECKS, { ...DEFAULT_RISK_POLICY, kappa: DEFAULT_RISK_POLICY.kappa + 1 })).not.toBe(m);
    expect(computeHarnessMeasurement(HARNESS_VERSION, ENFORCED_CHECKS, { ...DEFAULT_RISK_POLICY, weights: { ...DEFAULT_RISK_POLICY.weights, delta: DEFAULT_RISK_POLICY.weights.delta + 0.01 } })).not.toBe(m);
  });
});

describe('Harness.step: exact outcomes', () => {
  it('same node, same verb, different resource is out_of_plan with the committed action named', async () => {
    const h = mk();
    expect(await h.step(() => ({ verb: 'read', resource: 'doc:2', nodeId: 'n1' }))).toEqual({
      ok: false, reason: 'out_of_plan', detail: "action read doc:2 does not match committed node 'n1' (read doc:1)",
    });
    expect(h.counter).toBe(0);
    expect(h.budget.B).toBe(1);
  });
  it('a candidate with a non-string verb or resource is a bad_candidate, not an exception', async () => {
    const h = mk();
    for (const c of [{ verb: 1, resource: 'doc:1', nodeId: 'n1' }, { verb: 'read', resource: null, nodeId: 'n1' }, { verb: 'read', resource: 'doc:1', nodeId: 5 }, 'read', 7, undefined]) {
      expect(await h.step(() => c as never)).toEqual({ ok: false, reason: 'bad_candidate', detail: 'oracle returned a malformed candidate' });
    }
    expect(h.counter).toBe(0);
  });
  it('an oracle that throws a non-Error still refuses (never unhandled)', async () => {
    const h = mk();
    expect(await h.step(() => { throw 'plain string'; })).toEqual({ ok: false, reason: 'bad_candidate', detail: 'oracle failed: unknown error' });
  });
  it('an exhausted budget refuses with the required rung, reports the budget and debits nothing', async () => {
    const h = mk({ budget: budget(0) });
    const r = await h.step(() => trusted);
    expect(r).toMatchObject({ ok: false, reason: 'over_budget', requiredT: 3 });
    if (r.ok) throw new Error('unreachable');
    expect(r.detail).toMatch(/^budget 0\.0000 < cost \d+\.\d{4}; step up to a human co-sign$/);
    expect(r.budget).toEqual(h.budget);
    expect(h.counter).toBe(0);
  });
  it('a success debits the budget, counts the action and reports the same budget the harness now holds', async () => {
    const h = mk();
    const before = h.budget.B;
    const r = await h.step(() => trusted);
    if (!r.ok) throw new Error(r.detail);
    expect(h.counter).toBe(1);
    expect(r.budget).toEqual(h.budget);
    expect(h.budget.B).toBeLessThan(before);
    expect(r.risk.t).toBeGreaterThanOrEqual(1);
    expect(r.risk.t).toBeLessThanOrEqual(3);
    const r2 = await h.step(() => trusted);
    if (!r2.ok) throw new Error(r2.detail);
    expect(h.counter).toBe(2);
    expect([r.pcactn.counter, r2.pcactn.counter]).toEqual([1, 2]);
    expect(r2.pcactn.nonce).not.toBe(r.pcactn.nonce); // a fresh random nonce per action
  });
  it('an injected nonce source is used for the signed action', async () => {
    const h = mk({ nonce: () => 'fixed-nonce' });
    const r = await h.step(() => trusted);
    if (!r.ok) throw new Error(r.detail);
    expect(r.pcactn.nonce).toBe('fixed-nonce');
  });
  it('the signed risk claim equals the reported risk and is rounded to 6 decimals', async () => {
    const h = mk();
    const r = await h.step(() => ({ ...trusted, inputs: [{ ref: 'x', provenance: 'untrusted' }] }));
    if (!r.ok) throw new Error(r.detail);
    expect(r.pcactn.risk_claim.r).toBe(r.risk.r);
    expect(Math.round(r.risk.r * 1e6) / 1e6).toBe(r.risk.r);
    expect(r.pcactn.risk_claim.inputs).toEqual(r.risk.inputs);
  });
  it('a candidate with no inputs is untainted (the declared lineage is empty, not unknown)', async () => {
    const r = await mk().step(() => ({ verb: 'read', resource: 'doc:1', nodeId: 'n1' }));
    if (!r.ok) throw new Error(r.detail);
    expect(r.risk.taint).toBe(0);
    expect(r.pcactn.provenance.trusted_refs).toEqual([]);
  });
});

describe('Harness constructor: further refusals', () => {
  it.each([
    ['plan is not an array', { plan: 'x' }, /non-empty/],
    ['agentSecret is not a Uint8Array', { agentSecret: 'abc' }, /32-byte/],
    ['agentSecret is 33 bytes', { agentSecret: new Uint8Array(33) }, /32-byte/],
    ['budget missing', { budget: undefined }, /finite/],
    ['infinite tau', { budget: { B: 1, tau: Infinity, asOf: 1 } }, /finite/],
    ['NaN asOf', { budget: { B: 1, tau: 1, asOf: NaN } }, /finite/],
    ['audience is a number', { audience: 5 }, /audience/],
  ])('%s', (_n, over, re) => {
    expect(() => mk(over as never)).toThrow(re);
  });
  it('a zero budget is allowed (it simply refuses every machine-only action)', () => {
    expect(() => mk({ budget: budget(0) })).not.toThrow();
  });
});

describe('createHarnessAttestationVerifier: exact results', () => {
  const MEASUREMENT = computeHarnessMeasurement(HARNESS_VERSION, ENFORCED_CHECKS, DEFAULT_RISK_POLICY);
  const ctx = (att: unknown): VerifyContext => ({ grant, pcactn: { attestation: att } }) as unknown as VerifyContext;
  const att = (measurement: unknown, model_id: unknown = HARNESS_MODEL_ID) => ctx({ quote_digest: '', epoch: 0, model_id, measurement, operator: 'o' });

  it('allows an allowlisted measurement', () => {
    expect(createHarnessAttestationVerifier({ measurements: [MEASUREMENT] })(att(MEASUREMENT))).toEqual({ enforced: true, ok: true });
  });
  it('an allowlist that is empty, missing, not an array or only junk accepts nothing', () => {
    const reason = 'harness attestation configured with an empty measurement allowlist (fail closed)';
    for (const measurements of [[], undefined, 'abc', [''], [1, null], null]) {
      expect(createHarnessAttestationVerifier({ measurements: measurements as never })(att(MEASUREMENT))).toEqual({ enforced: true, ok: false, reason });
    }
  });
  it('an absent measurement (missing context, no block, empty or non-string) fails by default and is not-enforced only with required:false', () => {
    const required = 'harness attestation required but the PCActn carries no harness measurement (fail closed)';
    const v = createHarnessAttestationVerifier({ measurements: [MEASUREMENT] });
    const lax = createHarnessAttestationVerifier({ measurements: [MEASUREMENT], required: false });
    for (const c of [undefined as never, {} as never, ctx(undefined), ctx({}), att(''), att(5), att(null)]) {
      expect(v(c)).toEqual({ enforced: true, ok: false, reason: required });
      expect(lax(c)).toEqual({ enforced: false });
    }
  });
  it('a present measurement that is not allowlisted always fails, with required true or false', () => {
    const reason = 'harness measurement is not in the allowlisted set (unattested or unknown mediator)';
    for (const required of [true, false, undefined]) {
      expect(createHarnessAttestationVerifier({ measurements: [MEASUREMENT], required })(att('other'))).toEqual({ enforced: true, ok: false, reason });
    }
  });
  it('model id pinning: true pins the harness id, a string pins that string, empty string and false do not pin; the id is checked before the allowlist', () => {
    const wrong = createHarnessAttestationVerifier({ measurements: [MEASUREMENT], expectedModelId: true })(att(MEASUREMENT, 'other-model'));
    expect(wrong).toEqual({ enforced: true, ok: false, reason: `attestation.model_id 'other-model' is not the required harness identity '${HARNESS_MODEL_ID}'` });
    expect(createHarnessAttestationVerifier({ measurements: [MEASUREMENT], expectedModelId: 'acme-mediator' })(att(MEASUREMENT, 'acme-mediator'))).toEqual({ enforced: true, ok: true });
    expect(createHarnessAttestationVerifier({ measurements: [MEASUREMENT], expectedModelId: 'acme-mediator' })(att(MEASUREMENT))).toMatchObject({ ok: false });
    for (const expectedModelId of [false, '', undefined]) expect(createHarnessAttestationVerifier({ measurements: [MEASUREMENT], expectedModelId })(att(MEASUREMENT, 'anything'))).toEqual({ enforced: true, ok: true });
    expect(createHarnessAttestationVerifier({ measurements: [MEASUREMENT], expectedModelId: true })(att('not-allowlisted', 'other-model'))).toMatchObject({ reason: expect.stringContaining('model_id') });
    expect(createHarnessAttestationVerifier({ measurements: [MEASUREMENT], expectedModelId: true })(ctx({ measurement: MEASUREMENT }))).toMatchObject({ ok: false, reason: expect.stringContaining("'undefined'") });
  });
  it('the allowlist is copied at construction: later edits to the caller array change nothing', () => {
    const list = [MEASUREMENT];
    const v = createHarnessAttestationVerifier({ measurements: list });
    list.length = 0;
    expect(v(att(MEASUREMENT))).toEqual({ enforced: true, ok: true });
  });
});
