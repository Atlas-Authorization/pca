import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { admitsConcrete, diffPolicies, signAccessRequest, subsumes, suggestNarrowing, verifyAccessRequest, type ObservedAction, type PolicyInput } from './index';
import { DEFAULT_CATALOG, extendCatalog, resolveAction } from '@atlasauth/pca/ext/research';
import { refund, rng } from './k2-fixtures';

// the built-in catalog prices payout and refund alike (both irreversible, money moving); the ranking test needs payout to be the bigger blast
const payoutWorse = extendCatalog(DEFAULT_CATALOG, [{ ...resolveAction(DEFAULT_CATALOG, 'stripe.payout').spec, blastRadius: 1 }]);

const policy: PolicyInput = { predicates: [refund(500), { verb: 'stripe.payout', resource: '/acct/*', where: [{ field: 'action.params.amount', op: 'lte', value: 10000 }] }], caveats: [] };
const ledger = (n: number, f: (i: number) => Partial<ObservedAction> = () => ({})): ObservedAction[] =>
  Array.from({ length: n }, (_, i) => ({ verb: 'stripe.refund', resource: `/acct/42/ch_${i}`, params: { amount: 20 + i * 10 }, source: 'ledger' as const, outcome: 'allowed' as const, ...f(i) }));

describe('suggestNarrowing', () => {
  it('proposes a narrower grant, proven subsumed by the original, and lists what was never used', () => {
    const r = suggestNarrowing(policy, ledger(7), { catalog: payoutWorse });
    expect(r.used).toBe(7);
    expect(r.proposal).toBeDefined();
    const pred = (r.proposal as { predicates: unknown[] }).predicates;
    expect(pred).toEqual([
      {
        verb: 'stripe.refund',
        resource: '/acct/42/*',
        where: [
          { field: 'action.params.amount', op: 'lte', value: 500 },
          { field: 'action.params.amount', op: 'lte', value: 88 }, // 80 * 1.1, rounded up
        ],
      },
    ]);
    expect(subsumes(policy, r.proposal!)).toEqual({ subsumes: true });
    expect(r.coversObserved).toBe(true);
    expect(r.diff?.widens).toBe(false);
    expect(r.findings.map((f) => [f.kind, f.verb])).toEqual([['unused-predicate', 'stripe.payout'], ['unreached-cap', 'stripe.refund']]);
    expect(r.findings[0]!.rank).toBeGreaterThan(r.findings[1]!.rank); // payout is the bigger blast radius
  });

  it('counts, and never uses, observations the agent merely claims', () => {
    const r = suggestNarrowing(policy, [...ledger(6), { verb: 'stripe.payout', resource: '/acct/1', params: { amount: 9000 }, source: 'agent', outcome: 'allowed' }]);
    expect(r.rejected).toBe(1);
    expect(r.used).toBe(6);
    expect(JSON.stringify(r.proposal)).not.toContain('stripe.payout');
  });

  it('an observation the policy does not admit cannot widen it', () => {
    const outside: ObservedAction = { verb: 'stripe.refund', resource: '/vault/1', params: { amount: 100000 }, source: 'ledger', outcome: 'allowed' };
    const r = suggestNarrowing(policy, [...ledger(6), outside]);
    expect(admitsConcrete(r.proposal!, { verb: 'stripe.refund', resource: '/vault/1', params: { amount: 1 } })).toBe(false);
    expect(r.coversObserved).toBe(false);
  });

  it('a refused attempt becomes an access request for a human, and never loosens the grant', () => {
    const denied: ObservedAction[] = [0, 1, 2].map(() => ({ verb: 'stripe.refund', resource: '/acct/42/ch_big', params: { amount: 900 }, source: 'ledger', outcome: 'denied' }));
    const r = suggestNarrowing(policy, [...ledger(6), ...denied], { taskBinding: 'goal:abc' });
    expect(r.accessRequests).toHaveLength(1);
    expect(r.accessRequests[0]).toMatchObject({ kind: 'pca-access-request', verb: 'stripe.refund', denied_count: 3, example_params: { amount: 900 }, task_binding: 'goal:abc' });
    expect(admitsConcrete(r.proposal!, { verb: 'stripe.refund', resource: '/acct/42/ch_big', params: { amount: 900 } })).toBe(false);
    expect(r.taskBinding).toBe('goal:abc');
    const k = generateKeyPair();
    const pub = b64u(k.publicKey);
    const signed = signAccessRequest(r.accessRequests[0]!, k.secretKey, pub);
    expect(verifyAccessRequest(signed, pub)).toBe(true);
    expect(verifyAccessRequest({ ...signed, request: { ...signed.request, denied_count: 99 } }, pub)).toBe(false);
    expect(verifyAccessRequest(signed, b64u(generateKeyPair().publicKey))).toBe(false);
  });

  it('decay: the re-minted grant lapses', () => {
    const r = suggestNarrowing(policy, ledger(6), { decay: { nowSec: 1000, expiresInSecs: 86400 } });
    expect((r.proposal as { caveats: unknown[] }).caveats).toEqual([{ type: 'expires', at: 87400 }]);
  });

  it('narrows an enum parameter, but not below the sample floor', () => {
    const p: PolicyInput = { predicates: [{ verb: 'v', resource: '/r/*' }] };
    const obs = Array.from({ length: 6 }, (_, i) => ({ verb: 'v', resource: `/r/${i % 2}`, params: { kind: i % 2 ? 'a' : 'b' }, source: 'ledger' as const }));
    expect((suggestNarrowing(p, obs).proposal as { predicates: Array<{ where?: unknown }> }).predicates[0]!.where).toEqual([{ field: 'action.params.kind', op: 'in', value: ['a', 'b'] }]);
    expect((suggestNarrowing(p, obs.slice(0, 4)).proposal as { predicates: Array<{ where?: unknown }> }).predicates[0]!.where).toBeUndefined();
  });

  it('says why there is no proposal when nothing observed matches', () => {
    const r = suggestNarrowing(policy, []);
    expect(r.proposal).toBeUndefined();
    expect(r.reason).toBe('no ledger observation matches any predicate');
  });

  it('property: a proposal is never wider than the original, whatever was observed', () => {
    const rand = rng(3);
    const verbs = ['stripe.refund', 'stripe.payout', 'stripe.other'];
    let proposals = 0;
    for (let round = 0; round < 40; round++) {
      const obs: ObservedAction[] = Array.from({ length: 5 + Math.floor(rand() * 8) }, () => ({
        verb: verbs[Math.floor(rand() * 3)]!,
        resource: `/acct/${Math.floor(rand() * 3)}/x${Math.floor(rand() * 5)}`,
        params: { amount: Math.floor(rand() * 20000) },
        source: rand() < 0.2 ? 'agent' : 'ledger',
        outcome: rand() < 0.15 ? 'denied' : 'allowed',
      }));
      const r = suggestNarrowing(policy, obs);
      if (r.proposal) {
        proposals++;
        expect(subsumes(policy, r.proposal).subsumes).toBe(true);
        expect(diffPolicies(policy, r.proposal).widens).toBe(false);
      }
    }
    expect(proposals).toBeGreaterThan(10);
  });
});
