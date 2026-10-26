/**
 * 0.4.2 regression: verifyPCActn refused EVERY grant whose root signature is pure post-quantum or hybrid, even when the core
 * verifier accepted it. The policy layer (`decide()`) re-ran `verifyChain([grant])` with neither the verifier's stored grant
 * (`trustedRoot`) nor its PQ pins, so the R3-01 rule "a PQ root needs verifier-side authority" always refused it. decide() now
 * gets the same authority the core verifier uses; fail-closed is unchanged (a pin that disagrees still refuses).
 */
import { describe, expect, it } from 'vitest';
import { mintRoot, verifyChain, type Capability } from '../capability';
import { mintGrant } from '../envelope';
import { encodeKey, generateKeyPair } from '../keys';
import { buildPCActn } from '../pcactn';
import { decide, deriveDecideInput } from '../policy-vm';
import { encodeMlDsaPublicKey, mlDsa65Keygen, type SigAlg } from '../pq';
import { DEFAULT_RISK_POLICY } from '../risk';
import { verifyPCActn as verifyPCActn05 } from './verify';
const verifyPCActn = (p: Parameters<typeof verifyPCActn05>[0], o: Parameters<typeof verifyPCActn05>[1]): ReturnType<typeof verifyPCActn05> => verifyPCActn05(p, 'require' in o ? o : Object.create(o, { require: { value: [], enumerable: true } })); // report-only: these tests are not about the 0.5 default required checks (see breaking-05.test.ts)


const AUD = 'rs-pqroot';
const NOW = Date.UTC(2026, 9, 12, 12, 0, 0);
const lowRisk = { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 };

function pqGrant(alg: SigAlg) {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const ml = mlDsa65Keygen(new Uint8Array(32).fill(alg === 'ml-dsa-65' ? 11 : 12));
  // the envelope caveat exactly as mintGrant builds it (mintGrant itself only mints Ed25519 roots)
  const env = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    goal: 'refund an order',
    envelope: { predicates: [{ verb: 'refund', resource: 'order/*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  }).grant.caveats;
  const grant = mintRoot({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    caveats: env,
    suite: { alg, mlDsa: ml },
  });
  const plan = [{ id: 'n', verb: 'refund', resource: 'order/1', reversibility_class: 'reversible' as const }];
  const actn = buildPCActn({ grant, chain: [grant], plan, nodeId: 'n', counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW });
  const pin = encodeMlDsaPublicKey(ml.publicKey);
  const wrongPin = encodeMlDsaPublicKey(mlDsa65Keygen(new Uint8Array(32).fill(99)).publicKey);
  return { grant, actn, plan, pin, wrongPin };
}

describe.each(['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'] as SigAlg[])('verifyPCActn with a %s root', (alg) => {
  const s = pqGrant(alg);
  const run = (pqPins?: Record<string, string>, grant: Capability = s.grant) =>
    verifyPCActn(s.actn, { grant, now: NOW, audience: AUD, ...(pqPins ? { pqPins } : {}), context: { plan: s.plan, risk: lowRisk, params: {}, budget: { B: 1, tau: NOW, asOf: NOW } } });

  it('the root really is post-quantum', () => {
    expect(s.grant.alg).toBe(alg);
    expect(typeof s.grant.pq_pk).toBe('string');
  });
  // a budget is supplied: without one verifyPCActn fails closed to B=0 and reports it (that default is unchanged)
  it('accepts a valid action under the stored grant alone (as the core verifier does)', async () => {
    const v = await run();
    expect(v.reasons).toEqual([]);
    expect(v.checks.policy).toBe('pass');
    expect(v.allow).toBe(true);
  });
  it('accepts a valid action under the matching server-side pin', async () => {
    const v = await run({ [s.grant.issuer]: s.pin });
    expect(v.checks.pq_pin).toBe('pass');
    expect(v.checks.policy).toBe('pass');
    expect(v.allow).toBe(true);
  });
  it('rejects under a wrong pin, in the pin check AND in the policy layer (fail closed)', async () => {
    const v = await run({ [s.grant.issuer]: s.wrongPin });
    expect(v.allow).toBe(false);
    expect(v.checks.pq_pin).toBe('fail');
    expect(v.checks.policy).toBe('fail');
    expect(v.reasons.some((r) => r.includes('capability chain unverified'))).toBe(true);
  });
  it('decide() still refuses a PQ root with no verifier-side authority', () => {
    const input = deriveDecideInput(s.actn, { grant: s.grant, plan: s.plan, risk: lowRisk, budget: { B: 1, tau: NOW, asOf: NOW }, now: NOW });
    const { trustedRoot: _t, ...bare } = input;
    const d = decide(bare);
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.reasons[0]).toMatch(/^capability chain unverified: hop 0: root suite/);
    expect(decide(input).releaseGuardianShare).toBe(true);
  });
  it('deriveDecideInput carries the stored grant as trustedRoot and forwards pins; a wrong pin refuses', () => {
    const base = { grant: s.grant, plan: s.plan, risk: lowRisk, budget: { B: 1, tau: NOW, asOf: NOW }, now: NOW };
    const input = deriveDecideInput(s.actn, base);
    expect(input.trustedRoot).toBe(s.grant);
    expect('pqPins' in input).toBe(false);
    const pinned = deriveDecideInput(s.actn, { ...base, pqPins: { [s.grant.issuer]: s.pin } });
    expect(pinned.pqPins).toEqual({ [s.grant.issuer]: s.pin });
    expect(decide(pinned).releaseGuardianShare).toBe(true);
    const wrong = decide(deriveDecideInput(s.actn, { ...base, pqPins: { [s.grant.issuer]: s.wrongPin } }));
    expect(wrong.releaseGuardianShare).toBe(false);
    expect(wrong.reasons[0]).toMatch(/^capability chain unverified/);
  });
  it('verifyChain: with trustedRoot AND a pin, both must agree (a disagreeing pin refuses; trustedRoot never overrides it)', () => {
    expect(verifyChain([s.grant], s.grant.issuer, { trustedRoot: s.grant }).ok).toBe(true);
    expect(verifyChain([s.grant], s.grant.issuer, { trustedRoot: s.grant, pqPins: { [s.grant.issuer]: s.pin } }).ok).toBe(true);
    const r = verifyChain([s.grant], s.grant.issuer, { trustedRoot: s.grant, pqPins: { [s.grant.issuer]: s.wrongPin } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/pin .*does not match the stored grant's pq_pk \(fail closed\)/);
    // a pin for a DIFFERENT issuer does not bear on this root
    expect(verifyChain([s.grant], s.grant.issuer, { trustedRoot: s.grant, pqPins: { other: s.wrongPin } }).ok).toBe(true);
  });
  it('a trustedRoot that is NOT byte-identical to the root authorises nothing', () => {
    const other = pqGrant(alg).grant;
    const input = deriveDecideInput(s.actn, { grant: s.grant, plan: s.plan, risk: lowRisk, budget: { B: 1, tau: NOW, asOf: NOW }, now: NOW });
    expect(decide({ ...input, trustedRoot: other }).releaseGuardianShare).toBe(false);
  });
});
