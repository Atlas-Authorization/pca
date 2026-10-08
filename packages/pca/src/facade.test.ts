import { describe, expect, it } from 'vitest';
import { agent, compilePolicy, parseLimit } from './facade';
import { generateKeyPair } from './keys';
import { verifyChain } from './capability';
import { readEnvelope, verifyGoalCommit } from './envelope';
import { decodePCActn, verifyPCActnCore } from './pcactn';
import { b64u } from './hash';

const principal = () => generateKeyPair();
const AUD = 'ins_test';

describe('parseLimit', () => {
  it('parses dollar/period, dollar, count/period, bare count', () => {
    expect(parseLimit('$500/day')).toEqual({ amount: 500, unit: 'usd', periodMs: 86_400_000 });
    expect(parseLimit('$500')).toEqual({ amount: 500, unit: 'usd' });
    expect(parseLimit('10/hour')).toEqual({ amount: 10, unit: 'count', periodMs: 3_600_000 });
    expect(parseLimit('10')).toEqual({ amount: 10, unit: 'count' });
    expect(parseLimit('$12.50/week')).toEqual({ amount: 12.5, unit: 'usd', periodMs: 604_800_000 });
  });
  it('throws on malformed / unknown period', () => {
    expect(() => parseLimit('')).toThrow();
    expect(() => parseLimit('abc')).toThrow();
    expect(() => parseLimit('$5/fortnight')).toThrow();
  });
});

describe('compilePolicy', () => {
  it('turns a monetary limit into a hard per-call ceiling predicate + dollars budget', () => {
    const p = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, now: 1_000 });
    const pred = p.predicates.find((x) => x.verb === 'stripe.refund')!;
    expect(pred.where).toEqual([
      { field: 'action.params.amount', op: 'lte', value: 500 },
      { field: 'action.params.amount', op: 'gte', value: 0 },
    ]);
    expect(p.budgetModel).toBe('dollars');
    expect(p.riskPolicy.kappa).toBe(500);
    expect(p.riskPolicy.bMax).toBe(500);
    expect(p.riskPolicy.weights.gamma).toBe(1);
    // period window → expires caveat
    expect(p.caveats).toContainEqual({ type: 'expires', at: 1_000 + 86_400_000 });
  });

  it('sets reversibility_max to the STRICTEST granted action', () => {
    const p = compilePolicy({ permissions: { gmail: ['send', 'draft'] } }); // send=irreversible, draft=reversible
    expect(p.caveats).toContainEqual({ type: 'reversibility_max', class: 'irreversible' });
    expect(p.budgetModel).toBe('risk'); // no $ limits
  });

  it('a single count limit becomes a grant-wide rate caveat', () => {
    const p = compilePolicy({ permissions: { slack: ['post_message'] }, limits: { post_message: '5/hour' } });
    expect(p.caveats).toContainEqual({ type: 'rate', max: 5, per_secs: 3_600 });
  });

  it('rejects empty permissions', () => {
    expect(() => compilePolicy({ permissions: {} })).toThrow();
  });
});

describe('agent()', () => {
  it('mints a grant that verifyChain accepts and whose goal commitment opens', () => {
    const pk = principal();
    const a = agent({ principal: pk, goal: 'reconcile refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
    const chain = verifyChain(a.chain, a.principalPublic);
    expect(chain.ok).toBe(true);
    const env = readEnvelope(a.grant)!;
    expect(env).not.toBeNull();
    expect(verifyGoalCommit(env.goal_commit, 'reconcile refunds', a.goalSalt)).toBe(true);
    expect(a.autonomyBound).toBe(500); // bMax/κ · κ = 500
  });

  it('act() produces a PCActn that verifies offline (chain + leaf sig + audience)', async () => {
    const pk = principal();
    const a = agent({ principal: pk, goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
    const { pcactn, encoded, dryRun } = a.act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' }, { counter: 1 });
    expect(dryRun.allowed).toBe(true);
    expect(dryRun.t).toBe(1); // within cap → auto
    // round-trips on the wire
    expect(decodePCActn(encoded)).toEqual(pcactn);
    // the real bar: the offline verifier ACCEPTS it (no check fails)
    const res = await verifyPCActnCore(pcactn, { grant: a.grant, audience: AUD, nowEpoch: pcactn.iat });
    expect(res.allow).toBe(true);
    expect(res.checks.wire).toBe('pass');
    expect(res.checks.cap_chain).toBe('pass');
    expect(res.checks.plan_inclusion).toBe('pass');
    expect(res.checks.leaf_signature).toBe('pass');
    expect(res.checks.audience).toBe('pass');
  });

  it('dryRun denies an over-cap refund (ceiling predicate) and an ungranted verb', () => {
    const a = agent({ principal: principal(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
    expect(a.dryRun('stripe.refund', 'charge:ch_1', { amount: 999, currency: 'usd' }).allowed).toBe(false);
    expect(a.dryRun('stripe.payout', 'acct_1', { amount: 1 }).allowed).toBe(false); // not granted
    expect(a.dryRun('stripe.refund', 'charge:ch_1', { amount: 10, currency: 'usd' }).allowed).toBe(true);
  });

  it('auto-increments the action counter when not supplied', () => {
    const a = agent({ principal: principal(), goal: 'g', permissions: { gmail: ['send'] }, aud: AUD });
    const c1 = a.act('gmail.send', 'msg:1', {}).pcactn.counter;
    const c2 = a.act('gmail.send', 'msg:2', {}).pcactn.counter;
    expect(c2).toBe(c1 + 1);
  });

  it('subAgent() delegates: chain grows by one hop, still verifies, and can act', async () => {
    const pk = principal();
    const a = agent({ principal: pk, goal: 'g', permissions: { gmail: ['send'] }, aud: AUD });
    const sub = a.subAgent();
    expect(sub.chain.length).toBe(a.chain.length + 1);
    expect(verifyChain(sub.chain, a.principalPublic).ok).toBe(true);
    // sub-agent holder differs from parent
    expect(b64u(sub.holder.publicKey)).not.toBe(b64u(a.holder.publicKey));
    const { pcactn } = sub.act('gmail.send', 'msg:1', {}, { counter: 1 });
    const res = await verifyPCActnCore(pcactn, { grant: a.grant, audience: AUD, nowEpoch: pcactn.iat });
    expect(res.allow).toBe(true);
    expect(res.checks.cap_chain).toBe('pass');
    expect(res.checks.plan_inclusion).toBe('pass');
    expect(res.checks.leaf_signature).toBe('pass'); // signed by the SUB-agent's holder key
  });

  it('non-money permission uses the risk budget model and still builds a valid action', async () => {
    const a = agent({ principal: principal(), goal: 'g', permissions: { github: ['create_pr'] }, aud: AUD });
    expect(a.policy.budgetModel).toBe('risk');
    const { pcactn, dryRun } = a.act('github.create_pr', 'repo:acme/app', { title: 'x' }, { counter: 1 });
    expect(dryRun.allowed).toBe(true);
    const res = await verifyPCActnCore(pcactn, { grant: a.grant, audience: AUD, nowEpoch: pcactn.iat });
    expect(res.allow).toBe(true);
    expect(res.checks.leaf_signature).toBe('pass');
  });

  it('act() requires an audience', () => {
    const a = agent({ principal: principal(), goal: 'g', permissions: { gmail: ['send'] } }); // no aud
    expect(() => a.act('gmail.send', 'msg:1', {})).toThrow(/aud/);
  });
});
