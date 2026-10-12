import { describe, expect, it } from 'vitest';
import {
  agent,
  encodeKey,
  encodeMlDsaPublicKey,
  generateKeyPair,
  merkleRoot,
  mintRoot,
  mlDsa65Keygen,
  buildPCActn,
  planNodeLeaf,
  type PCActn,
  type PlanNode,
} from '@atlasauth/pca';
import * as a2a from './index';

/**
 * The A2A surfaces AUTHORIZE: a task / payment mandate is accepted only when the full server verifier (verifyPCActn)
 * allows it under a KNOWN authority: the caller's stored `grant`, or `expectedRootIssuer` (the principal the chain must
 * be rooted at). Without either it is a typed configuration error; a self-minted chain never passes; the grant's
 * predicates, limits, budget and threshold, allowedSuites and pqPins are enforced.
 */
const AUD = 'rs-a2a';
const NOW = Date.UTC(2026, 9, 11, 12, 0, 0);
const principal = generateKeyPair();
const pPub = encodeKey(principal.publicKey);
const a = agent({ principal, goal: 'reconcile refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, aud: AUD });

/** What a resource server knows about the action: its own copy of the one-node plan (authorized) and a budget. */
const ctxFor = (p: PCActn, params: Record<string, unknown>) => {
  const plan: PlanNode[] = [{ id: p.plan.node_id, verb: p.action.verb, resource: p.action.resource, params_digest: p.action.params_digest, reversibility_class: p.action.reversibility_class }];
  return { params, plan, planAuthorized: merkleRoot(plan.map(planNodeLeaf)) === p.plan.root, budget: { B: 1000, tau: NOW, asOf: NOW } };
};
const base = (p: PCActn, params: Record<string, unknown>) => ({
  aud: AUD,
  now: NOW,
  hooks: { revocation: () => ({ enforced: true as const, ok: true }) },
  context: ctxFor(p, params),
});
const task = (p: PCActn) => a2a.attachPcaToA2ATask({ id: 't', status: { state: 'submitted' } }, p);
const act = (verb: string, resource: string, params: Record<string, unknown>, counter = 1) => a.act(verb, resource, params, { counter, now: NOW }).pcactn;

describe('A2A: authority is required (typed error), never the chain itself', () => {
  it('verifyA2ATask / verifyA2APaymentMandate / pcaA2AMiddleware refuse a config with neither grant nor expectedRootIssuer', async () => {
    const p = act('stripe.refund', 'charge:ch_1', { amount: 10, currency: 'usd' });
    const code = async (f: () => unknown) => {
      try {
        await f();
      } catch (e) {
        return (e as { code?: string }).code;
      }
      return undefined;
    };
    expect(await code(() => a2a.verifyA2ATask(task(p), { aud: AUD, now: NOW } as never))).toBe('authority_required');
    const mandate = a2a.a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 10 }, paymentMethod: { type: 'card', token: 'tok_1' }, now: NOW });
    expect(await code(() => a2a.verifyA2APaymentMandate(mandate, p, { aud: AUD, now: NOW } as never))).toBe('authority_required');
    expect(await code(() => a2a.pcaA2AMiddleware({ aud: AUD } as never))).toBe('authority_required');
  });

  it('a self-minted chain naming the victim as issuer is refused (signed by the attacker key)', async () => {
    const atk = generateKeyPair();
    const forged = mintRoot({ principalSecret: atk.secretKey, principalPublic: pPub, holder: encodeKey(atk.publicKey), caveats: [{ type: 'ttl', secs: 3600 }] });
    const plan = [{ id: 'n', verb: 'stripe.refund', resource: 'charge:ch_1', reversibility_class: 'reversible' as const }];
    const p = buildPCActn({ grant: forged, chain: [forged], plan, nodeId: 'n', counter: 1, signerSecret: atk.secretKey, aud: AUD, now: NOW });
    const r = await a2a.verifyA2ATask(task(p), { ...base(p, {}), expectedRootIssuer: pPub });
    expect(r.ok).toBe(false);
  });
});

describe('A2A: the full verifier decides', () => {
  it('an in-scope purchase is accepted with expectedRootIssuer and with the stored grant', async () => {
    const params = { amount: 10, currency: 'usd' };
    const p = act('stripe.refund', 'charge:ch_1', params);
    const r1 = await a2a.verifyA2ATask(task(p), { ...base(p, params), expectedRootIssuer: pPub });
    expect(r1.ok, r1.reason).toBe(true);
    const r2 = await a2a.verifyA2ATask(task(p), { ...base(p, params), grant: a.grant });
    expect(r2.ok, r2.reason).toBe(true);
  });

  it('an action outside the grant (predicates) is refused', async () => {
    const p = act('github.delete_repo', 'repo:prod', {});
    const r = await a2a.verifyA2ATask(task(p), { ...base(p, {}), grant: a.grant });
    expect(r.ok).toBe(false);
    expect(r.reason ?? '').toMatch(/no predicate permits/);
  });

  it('an over-limit purchase is refused (limits)', async () => {
    const params = { amount: 10_000, currency: 'usd' };
    const p = act('stripe.refund', 'charge:ch_1', params);
    const r = await a2a.verifyA2ATask(task(p), { ...base(p, params), grant: a.grant });
    expect(r.ok).toBe(false);
  });

  it('no budget supplied: fail-closed deny-metered budget forces a step-up (budget / threshold enforced)', async () => {
    const params = { amount: 90, currency: 'usd' };
    const p = act('stripe.refund', 'charge:ch_1', params);
    const { budget: _b, ...ctxNoBudget } = ctxFor(p, params);
    void _b;
    const r = await a2a.verifyA2ATask(task(p), { aud: AUD, now: NOW, hooks: { revocation: () => ({ enforced: true as const, ok: true }) }, context: ctxNoBudget, grant: a.grant });
    expect(r.ok).toBe(false);
  });

  it('the payment mandate path decides with the full verifier too', async () => {
    const p = act('github.delete_repo', 'repo:prod', {});
    const mandate = a2a.a2aPaymentMandateFromPca(p, { amount: { currency: 'USD', value: 10 }, paymentMethod: { type: 'card', token: 'tok_1' }, now: NOW });
    const r = await a2a.verifyA2APaymentMandate(mandate, p, { ...base(p, {}), grant: a.grant });
    expect(r.ok).toBe(false);
  });

  it('allowedSuites refuses a pure-PQ root; with expectedRootIssuer a PQ root needs a pin', async () => {
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(3));
    const holder = generateKeyPair();
    const pq = mintRoot({ principalSecret: principal.secretKey, principalPublic: pPub, holder: encodeKey(holder.publicKey), caveats: [{ type: 'ttl', secs: 3600 }], suite: { alg: 'ml-dsa-65', mlDsa: ml } });
    const plan = [{ id: 'n', verb: 'stripe.refund', resource: 'charge:ch_1', reversibility_class: 'reversible' as const }];
    const p = buildPCActn({ grant: pq, chain: [pq], plan, nodeId: 'n', counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW });
    const suites = await a2a.verifyA2ATask(task(p), { ...base(p, {}), grant: pq, allowedSuites: ['ed25519'] });
    expect(suites.ok).toBe(false);
    expect(suites.result?.checks['cap_chain']).toBe('fail');
    const unpinned = await a2a.verifyA2ATask(task(p), { ...base(p, {}), expectedRootIssuer: pPub });
    expect(unpinned.result?.checks['pq_pin']).toBe('fail');
    const pinned = await a2a.verifyA2ATask(task(p), { ...base(p, {}), expectedRootIssuer: pPub, pqPins: { [pPub]: encodeMlDsaPublicKey(ml.publicKey) } });
    expect(pinned.result?.checks['pq_pin']).toBe('pass');
  });
});
