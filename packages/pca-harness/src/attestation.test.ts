import { describe, expect, it } from 'vitest';
import {
  type PlanNode,
  type TrustBudget,
  type VerifyContext,
  DEFAULT_RISK_POLICY,
  encodeKey,
  generateKeyPair,
  mintRoot,
} from '@atlasauth/pca';
import {
  type Candidate,
  ENFORCED_CHECKS,
  HARNESS_MODEL_ID,
  HARNESS_VERSION,
  Harness,
  computeHarnessMeasurement,
  createHarnessAttestationVerifier,
} from './index';

// --- fixtures ---------------------------------------------------------------------------------

const principal = generateKeyPair();
const agentKp = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);

const grant = mintRoot({
  principalSecret: principal.secretKey,
  principalPublic: pub(principal),
  holder: pub(agentKp),
  caveats: [],
});

const plan: PlanNode[] = [
  { id: 'n1', verb: 'read', resource: 'doc:1' },
  { id: 'n2', verb: 'summarize', resource: 'doc:1' },
];

const AUD = 'ins_harness_attest_test';
const fullBudget = (): TrustBudget => {
  const now = Date.now();
  return { B: 1, tau: now, asOf: now };
};

const mkHarness = (over: Partial<ConstructorParameters<typeof Harness>[0]> = {}) =>
  new Harness({ grant, agentSecret: agentKp.secretKey, plan, audience: AUD, budget: fullBudget(), ...over });

const oracle = (c: Candidate) => () => c;
const inPlanCandidate: Candidate = { verb: 'read', resource: 'doc:1', nodeId: 'n1', inputs: [{ ref: 'task-brief', provenance: 'trusted' }] };

/** The measurement an allowlisting operator would compute for the default-policy harness. */
const MEASUREMENT = computeHarnessMeasurement(HARNESS_VERSION, ENFORCED_CHECKS, DEFAULT_RISK_POLICY);

/** A VerifyContext carrying only an `attestation` block (all this hook reads). */
const ctxWithMeasurement = (measurement: string, modelId: string = HARNESS_MODEL_ID): VerifyContext =>
  ({
    grant,
    pcactn: { attestation: { quote_digest: '', epoch: 0, model_id: modelId, measurement, operator: 'acme' } },
  }) as unknown as VerifyContext;

describe('B1 server-side: an attested orchestration harness satisfies the L0 attestation hook', () => {
  describe('Harness stamps its self-measurement into the signed attestation block (opt-in)', () => {
    it('default OFF: the attestation block stays the empty stub (behaviour unchanged)', async () => {
      const h = mkHarness();
      const res = await h.step(oracle(inPlanCandidate));
      expect(res.ok).toBe(true);
      if (!res.ok) throw new Error(res.detail);
      expect(res.pcactn.attestation.measurement).toBe('');
      expect(res.pcactn.attestation.model_id).toBe('unattested');
    });

    it('opt-in: stamps measurement === harnessMeasurement(), model_id === HARNESS_MODEL_ID, empty quote_digest', async () => {
      const h = mkHarness({ attestation: { operator: 'acme' } });
      const res = await h.step(oracle(inPlanCandidate));
      expect(res.ok).toBe(true);
      if (!res.ok) throw new Error(res.detail);
      expect(res.pcactn.attestation.measurement).toBe(h.harnessMeasurement());
      expect(res.pcactn.attestation.measurement).toBe(MEASUREMENT);
      expect(res.pcactn.attestation.model_id).toBe(HARNESS_MODEL_ID);
      expect(res.pcactn.attestation.operator).toBe('acme');
      expect(res.pcactn.attestation.quote_digest).toBe(''); // no server-issued TEE nonce
    });
  });

  describe('createHarnessAttestationVerifier', () => {
    it('ACCEPTS a PCActn whose measurement is allowlisted', () => {
      const v = createHarnessAttestationVerifier({ measurements: [MEASUREMENT] });
      const r = v(ctxWithMeasurement(MEASUREMENT));
      expect(r).toEqual({ enforced: true, ok: true });
    });

    it('DENIES when the measurement mismatches the allowlist (unknown mediator)', () => {
      const v = createHarnessAttestationVerifier({ measurements: [MEASUREMENT] });
      const r = v(ctxWithMeasurement('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'));
      expect(r.enforced).toBe(true);
      expect(r.enforced && r.ok).toBe(false);
    });

    it('DENIES when the harness attestation is ABSENT but required (fail closed, default)', () => {
      const v = createHarnessAttestationVerifier({ measurements: [MEASUREMENT] });
      const r = v(ctxWithMeasurement(''));
      expect(r.enforced).toBe(true);
      expect(r.enforced && r.ok).toBe(false);
    });

    it('reports NOT-ENFORCED on an absent measurement when required:false (but a present mismatch still fails)', () => {
      const v = createHarnessAttestationVerifier({ measurements: [MEASUREMENT], required: false });
      expect(v(ctxWithMeasurement(''))).toEqual({ enforced: false });
      // A present-but-unallowlisted measurement is ALWAYS a hard fail, even when not required.
      const r = v(ctxWithMeasurement('ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ'));
      expect(r.enforced && r.ok).toBe(false);
    });

    it('DENIES when configured with an empty allowlist (fail closed)', () => {
      const v = createHarnessAttestationVerifier({ measurements: [] });
      const r = v(ctxWithMeasurement(MEASUREMENT));
      expect(r.enforced && r.ok).toBe(false);
    });

    it('pins model_id when expectedModelId is set: allowlisted measurement under a wrong identity is denied', () => {
      const v = createHarnessAttestationVerifier({ measurements: [MEASUREMENT], expectedModelId: true });
      expect(v(ctxWithMeasurement(MEASUREMENT, HARNESS_MODEL_ID))).toEqual({ enforced: true, ok: true });
      const r = v(ctxWithMeasurement(MEASUREMENT, 'some-other-mediator'));
      expect(r.enforced && r.ok).toBe(false);
    });
  });

  it('end-to-end: a harness with stamping emits a PCActn the allowlist verifier accepts', async () => {
    const h = mkHarness({ attestation: { operator: 'acme' } });
    const res = await h.step(oracle(inPlanCandidate));
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error(res.detail);
    const v = createHarnessAttestationVerifier({ measurements: [h.harnessMeasurement()] });
    const ctx = { grant, pcactn: res.pcactn } as unknown as VerifyContext;
    expect(v(ctx)).toEqual({ enforced: true, ok: true });

    // A verifier that allowlists only a DIFFERENT harness surface rejects this action.
    const other = computeHarnessMeasurement(HARNESS_VERSION, [...ENFORCED_CHECKS, 'extra_check'], DEFAULT_RISK_POLICY);
    const vOther = createHarnessAttestationVerifier({ measurements: [other] });
    const rOther = vOther(ctx);
    expect(rOther.enforced && rOther.ok).toBe(false);
  });
});
