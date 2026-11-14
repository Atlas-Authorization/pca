import { describe, expect, it } from 'vitest';
import { setAssuranceLabel } from './assurance';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { paramsDigest, type PlanNode } from './merkle';
import { buildPCActn, verifyPCActnCore, type Hook } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';

const principal = generateKeyPair();
const holder = generateKeyPair();
const { grant } = mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  holder: encodeKey(holder.publicKey),
  goal: 'x',
  envelope: { predicates: [{ verb: 'v', resource: 'r' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
});
const NOW = Date.UTC(2026, 9, 25, 12);
const node: PlanNode = { id: 'n', verb: 'v', resource: 'r', params_digest: paramsDigest({}), reversibility_class: 'reversible' };
const make = (counter = 1) => buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n', params: {}, counter, signerSecret: holder.secretKey, aud: 'rs', now: NOW });
const opts = { grant, audience: 'rs', nowEpoch: NOW, insecureSkipPlanRootCheck: true };

describe('verifyPCActnCore without optional layers', () => {
  it('reports the plan-root opt-out as not-enforced', async () => {
    const r = await verifyPCActnCore(make(), opts);
    expect(r.checks.plan_root_authorized).toBe('not-enforced');
    expect(r.allow).toBe(true);
  });
  it('refuses an intent v2 context it cannot enforce, with the reason', async () => {
    const r = await verifyPCActnCore(make(), { ...opts, intentV2: {} });
    expect(r.allow).toBe(false);
    expect(r.checks.intent_session).toBe('fail');
    expect(r.reason).toBe('intent_session: an intent v2 context is configured but this verifier does not load the intent layer (fail closed)');
  });
  it('refuses a fresh_at policy it cannot enforce, with the reason', async () => {
    const r = await verifyPCActnCore(make(), { ...opts, freshAt: { signer: 's', scope: 'x', local: {} } as never });
    expect(r.allow).toBe(false);
    expect(r.checks.fresh_at).toBe('fail');
    expect(r.reason).toBe('fresh_at: a fresh_at policy is configured but this verifier does not load the consistency-token extension (fail closed)');
    const none = await verifyPCActnCore(make(), opts);
    expect(none.checks.fresh_at).toBeUndefined();
  });
  it('refuses a negative counter as a format failure', async () => {
    const r = await verifyPCActnCore(make(-1), opts);
    expect(r.allow).toBe(false);
    expect(r.checks.counter_format).toBe('fail');
    expect(r.reason).toBe('counter_format: missing or not a non-negative safe integer');
    expect((await verifyPCActnCore(make(0), opts)).checks.counter_format).toBe('pass');
  });
});

describe('post-quantum issuer pin', () => {
  const pins = { [grant.issuer]: 'AAAA' };
  it('refuses a classical grant whose issuer is pinned', async () => {
    const r = await verifyPCActnCore(make(), { ...opts, pqPins: pins });
    expect(r.checks.pq_pin).toBe('fail');
    expect(r.reason).toBe('pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused');
  });
  it('does not apply the classical-root refusal to a grant that names a post-quantum suite', async () => {
    const r = await verifyPCActnCore(make(), { ...opts, grant: { ...grant, alg: 'ml-dsa-65' } as typeof grant, pqPins: pins });
    expect(r.checks.pq_pin).toBeUndefined();
  });
  it('does not apply when no pins are configured', async () => {
    expect((await verifyPCActnCore(make(), opts)).checks.pq_pin).toBeUndefined();
  });
});

describe('bond reporting and assurance sources', () => {
  it('does not add a bond check to a proof that was refused at the wire', async () => {
    const bad = { ...make(), bond_ref: 'b', intent_session: { session: 'x' } } as unknown as ReturnType<typeof make>;
    const r = await verifyPCActnCore(bad, opts);
    expect(r.checks).toEqual({ wire: 'fail' });
  });
  it('reports a bond_ref as unsupported and no bond check otherwise', async () => {
    const withBond = await verifyPCActnCore({ ...make(), bond_ref: 'b' } as unknown as ReturnType<typeof make>, opts);
    expect(withBond.checks.bond).toBe('unsupported');
    expect((await verifyPCActnCore(make(), opts)).checks.bond).toBeUndefined();
  });
  it('returns a result, not a throw, for a non-object proof', async () => {
    const r = await verifyPCActnCore(null as never, opts);
    expect(r.allow).toBe(false);
    expect(r.checks).toEqual({ wire: 'fail' });
  });
  it('builds the assurance report with no hooks and no enforcement gates', async () => {
    const r = await verifyPCActnCore(make(), { ...opts, assurance: true });
    expect(r.assurance?.attestation).toEqual({ outcome: 'not-enforced' });
  });
  it('builds the assurance report when enforce is present without an attestation gate', async () => {
    const r = await verifyPCActnCore(make(), { ...opts, enforce: {}, assurance: true });
    expect(r.assurance?.attestation).toEqual({ outcome: 'not-enforced' });
  });
  it('labels attestation from the enforcement gate verifier, not only from hooks', async () => {
    const hook: Hook = () => ({ enforced: true, ok: true });
    setAssuranceLabel(hook, { level: 'hardware', vendor: 'test-tee' });
    const r = await verifyPCActnCore(make(), { ...opts, enforce: { attestation: { verifier: hook } }, assurance: true });
    expect(r.assurance?.attestation).toEqual({ outcome: 'pass', level: 'hardware', vendor: 'test-tee' });
  });
});
