/**
 * r13 mutation kills for facade.ts: exact parseLimit / compilePolicy outcomes (messages, the uncatalogued fallback spec,
 * strictest reversibility, budget-model selection and the dollars risk policy), the risk claim of act(), every optional
 * act() field, the dry-run reasons and the counter. `sev` is a module-level helper, so each test uses a fresh module.
 * Also the dry-run fix: a single count limit compiles to a `rate` caveat, which the local dry run used to fail always.
 */
import { describe, expect, it, vi } from 'vitest';
import { generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';
import { RATE_LIMITED_REFUND_CATALOG } from './rate-limited-refund.test-util';

/** Capture an outcome so a thrown error is compared (name + message) instead of failing the test as an error. */
type Settled<T> = { ok: true; value: T } | { ok: false; error: { name: string; message: string } };
function settle<T>(f: () => T): Settled<T> {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    const x = e as Error;
    return { ok: false, error: { name: x?.name, message: x?.message } };
  }
}
const ok = <T>(value: T) => ({ ok: true as const, value });

async function fresh() {
  vi.resetModules();
  return import('./facade');
}
const P = () => generateKeyPair();
const AUD = 'ins_t';
const DAY = 86_400_000;

describe('facade: parseLimit messages and shapes', () => {
  it('empty, blank and non-string limits are refused as empty', async () => {
    const f = await fresh();
    for (const s of ['', '   ', 5 as never]) expect(() => f.parseLimit(s)).toThrow(new Error('parseLimit: empty limit'));
  });
  it('a zero amount is accepted; a limit without a period has no periodMs key', async () => {
    const f = await fresh();
    expect(settle(() => f.parseLimit('0'))).toEqual(ok({ amount: 0, unit: 'count' }));
    expect(f.parseLimit('$5')).toStrictEqual({ amount: 5, unit: 'usd' });
    expect(f.parseLimit('$5/day')).toStrictEqual({ amount: 5, unit: 'usd', periodMs: DAY });
  });
});

describe('facade: compilePolicy', () => {
  it('an uncatalogued verb falls back to an irreversible, high-blast spec', async () => {
    const f = await fresh();
    const p = f.compilePolicy({ permissions: { acme: ['x.y', 'z'] } });
    expect(p.actions).toStrictEqual([
      { connector: 'acme', action: 'x.y', verb: 'acme.x.y', reversibility: 'irreversible', blastRadius: 0.8, description: '(uncatalogued) acme.x.y' },
      { connector: 'acme', action: 'z', verb: 'acme.z', reversibility: 'irreversible', blastRadius: 0.8, description: '(uncatalogued) acme.z' },
    ]);
  });
  it('the fallback uses the whole verb as the action when the part after the connector is empty', async () => {
    const f = await fresh();
    const p = f.compilePolicy({ permissions: { acme: [''] } });
    expect(p.actions[0]).toMatchObject({ connector: 'acme', action: 'acme.', verb: 'acme.' });
  });
  it('non-array permissions and an empty permission map are refused with exact messages', async () => {
    const f = await fresh();
    expect(() => f.compilePolicy({ permissions: { gmail: 'send' as never } })).toThrow(new Error('compilePolicy: permissions.gmail must be an array'));
    expect(() => f.compilePolicy({ permissions: {} })).toThrow(new Error('compilePolicy: no permissions granted'));
  });
  it('predicates: catalog resource or *, a count limit adds no ceiling', async () => {
    const f = await fresh();
    const p = f.compilePolicy({ permissions: { gmail: ['send'], stripe: ['refund'], github: ['read'] }, limits: { refund: '10/day' } });
    expect(p.predicates).toStrictEqual([
      { verb: 'gmail.send', resource: '*' },
      { verb: 'stripe.refund', resource: '*' },
      { verb: 'github.read', resource: '*' },
    ]);
  });
  it('reversibility_max is the strictest granted class', async () => {
    const f = await fresh();
    expect(f.compilePolicy({ permissions: { github: ['read', 'merge_pr'] } }).caveats[0]).toStrictEqual({ type: 'reversibility_max', class: 'irreversible' });
    expect(f.compilePolicy({ permissions: { gmail: ['draft', 'send'] } }).caveats[0]).toStrictEqual({ type: 'reversibility_max', class: 'irreversible' });
    expect(f.compilePolicy({ permissions: { gmail: ['draft'] } }).caveats[0]).toStrictEqual({ type: 'reversibility_max', class: 'reversible' });
  });
  it('the expires window is the SMALLEST period named', async () => {
    const f = await fresh();
    const p = f.compilePolicy({ permissions: { gmail: ['send'], slack: ['post_message'] }, limits: { send: '5/day', post_message: '9/hour' }, now: 1000 });
    expect(p.caveats).toContainEqual({ type: 'expires', at: 1000 + 3_600_000 });
  });
  it('budget model: count limits alone stay on risk; explicit dollars / risk win over auto', async () => {
    const f = await fresh();
    const count = f.compilePolicy({ permissions: { gmail: ['send'] }, limits: { send: '5/day' } });
    expect(count.budgetModel).toBe('risk');
    expect(count.riskPolicy).toStrictEqual(DEFAULT_RISK_POLICY);
    const d = f.compilePolicy({ permissions: { gmail: ['send'] }, budgetModel: 'dollars' });
    expect(d.budgetModel).toBe('dollars');
    expect(d.riskPolicy).toStrictEqual(DEFAULT_RISK_POLICY); // no $ limit: nothing to denominate, default weights
    const r = f.compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100' }, budgetModel: 'risk' });
    expect(r.budgetModel).toBe('risk');
    expect(r.riskPolicy).toStrictEqual(DEFAULT_RISK_POLICY);
    expect(f.compilePolicy({ permissions: { gmail: ['send'] } }).riskPolicy).toStrictEqual(DEFAULT_RISK_POLICY);
  });
  it('dollars risk policy: kappa = largest cap, bMax = sum; a $0 cap floors both at 1', async () => {
    const f = await fresh();
    const p = f.compilePolicy({ permissions: { stripe: ['refund', 'charge'] }, limits: { refund: '$100', charge: '$500' } });
    expect(p.riskPolicy).toStrictEqual({
      weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 },
      // a refund and a charge are irreversible (one definition): the default co-sign tiers stay (W7b)
      theta1: DEFAULT_RISK_POLICY.theta1, theta2: DEFAULT_RISK_POLICY.theta2, kappa: 500, lambda: 0, rho: DEFAULT_RISK_POLICY.rho, bMax: 600,
    });
    // with nothing irreversible granted the within-cap tiers open up (theta = 1)
    const q = f.compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100' }, catalog: RATE_LIMITED_REFUND_CATALOG });
    expect([q.riskPolicy.theta1, q.riskPolicy.theta2, q.riskPolicy.kappa, q.riskPolicy.bMax]).toEqual([1, 1, 100, 100]);
    expect(settle(() => { const r = f.compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$0' } }).riskPolicy; return [r.kappa, r.bMax]; })).toEqual(ok([1, 1]));
  });
  it('a riskPolicy override merges its weights over the derived ones', async () => {
    const f = await fresh();
    const p = f.compilePolicy({ permissions: { gmail: ['send'] }, riskPolicy: { weights: { alpha: 0.5 } as never } });
    expect(p.riskPolicy.weights).toStrictEqual({ ...DEFAULT_RISK_POLICY.weights, alpha: 0.5 });
  });
  it('an invalid derived risk policy is refused with the validator reason', async () => {
    const f = await fresh();
    expect(() => f.compilePolicy({ permissions: { gmail: ['send'] }, riskPolicy: { kappa: 0 } })).toThrow(
      new Error('compilePolicy: derived risk policy invalid: risk_policy.kappa must be > 0'),
    );
  });
});

describe('facade: act() risk claim', () => {
  it('dollars model: amount / kappa; a missing amount falls back to the blast radius', async () => {
    const f = await fresh();
    const a = f.agent({ principal: P(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$100' }, aud: AUD });
    expect(a.act('stripe.refund', 'ch_1', { amount: 42 }).pcactn.risk_claim).toStrictEqual({ r: 0.42, inputs: { blastRadius: 0.42 } });
    expect(settle(() => a.act('stripe.refund', 'ch_1', {}).pcactn.risk_claim.r)).toEqual(ok(0.9));
    // kappa is re-read at act time; a non-positive kappa falls back to the blast radius too
    a.policy.riskPolicy.kappa = 0;
    expect(a.act('stripe.refund', 'ch_1', { amount: 42 }).pcactn.risk_claim.r).toBe(0.9);
  });
  it('risk model: the blast radius, even for a money-moving action with an amount', async () => {
    const f = await fresh();
    const a = f.agent({ principal: P(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$100' }, budgetModel: 'risk', aud: AUD });
    expect(a.act('stripe.refund', 'ch_1', { amount: 42 }).pcactn.risk_claim.r).toBe(0.9);
    const g = f.agent({ principal: P(), goal: 'g', permissions: { gmail: ['send'] }, aud: AUD });
    expect(g.act('gmail.send', 'm').pcactn.risk_claim).toStrictEqual({ r: 0.8, inputs: { blastRadius: 0.8 } });
  });
  it('an explicit risk override is clamped to [0,1]', async () => {
    const f = await fresh();
    const a = f.agent({ principal: P(), goal: 'g', permissions: { gmail: ['send'] }, aud: AUD });
    expect(a.act('gmail.send', 'm', {}, { risk: 0.3 }).pcactn.risk_claim.r).toBe(0.3);
    expect(a.act('gmail.send', 'm', {}, { risk: 7 }).pcactn.risk_claim.r).toBe(1);
    expect(a.act('gmail.send', 'm', {}, { risk: -2 }).pcactn.risk_claim.r).toBe(0);
  });
});

describe('facade: act() fields and counter', () => {
  it('now, ttlMs, nonce and caution reach the PCActn', async () => {
    const f = await fresh();
    const now = 5_000_000; // far from the wall clock, so a dropped `now` is visible
    const a = f.agent({ principal: P(), goal: 'g', permissions: { gmail: ['send'] }, aud: AUD, now });
    const { pcactn } = a.act('gmail.send', 'm', {}, { now: now + 5, ttlMs: 60_000, nonce: 'nonce-1', caution: 0.4 });
    expect(pcactn.iat).toBe(now + 5);
    expect(pcactn.exp).toBe(now + 5 + 60_000);
    expect(pcactn.nonce).toBe('nonce-1');
    expect(pcactn.caution).toBe(0.4);
  });
  it('act without any audience names the facade requirement', async () => {
    const f = await fresh();
    const a = f.agent({ principal: P(), goal: 'g', permissions: { gmail: ['send'] } });
    expect(() => a.act('gmail.send', 'm')).toThrow(
      new Error('act: aud (resource-server / instance id) is required (pass opts.aud or AgentOptions.aud)'),
    );
  });
  it('an explicit counter advances the auto counter past it', async () => {
    const f = await fresh();
    const a = f.agent({ principal: P(), goal: 'g', permissions: { gmail: ['send'] }, aud: AUD });
    expect(a.act('gmail.send', 'm', {}, { counter: 10 }).pcactn.counter).toBe(10);
    expect(a.act('gmail.send', 'm').pcactn.counter).toBe(11);
  });
  it("act's dry run is evaluated at the act's own now", async () => {
    const f = await fresh();
    const t0 = Date.now() - 3 * DAY;
    const a = f.agent({ principal: P(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD, now: t0 });
    expect(a.act('stripe.refund', 'ch_1', { amount: 1 }, { now: t0 + 1000 }).dryRun).toStrictEqual({ allowed: true, t: 1 });
  });
  it('encodeGrant is the JSON of the grant; agent now and agentBinding are used as given', async () => {
    const f = await fresh();
    const binding = { operator: 'op-9' };
    const a = f.agent({ principal: P(), goal: 'g', permissions: { gmail: ['send'] }, now: 123_456, agentBinding: binding });
    expect(JSON.parse(a.encodeGrant())).toStrictEqual(JSON.parse(JSON.stringify(a.grant)));
    expect(a.budget).toStrictEqual({ B: DEFAULT_RISK_POLICY.bMax, tau: 123_456, asOf: 123_456 });
    const env = a.grant.caveats.find((c) => c.type === 'envelope') as unknown as { agent_binding: unknown };
    expect(env.agent_binding).toStrictEqual(binding);
  });
});

describe('facade: dryRun reasons', () => {
  it('an ungranted verb reports the predicate reason', async () => {
    const f = await fresh();
    const a = f.agent({ principal: P(), goal: 'g', permissions: { gmail: ['send'] } });
    expect(a.dryRun('gmail.delete', 'm')).toStrictEqual({ allowed: false, reason: 'no predicate permits gmail.delete on m' });
  });
  it('failed caveats are listed by type, comma separated', async () => {
    const f = await fresh();
    const a = f.agent({ principal: P(), goal: 'g', permissions: { github: ['create_pr'] }, limits: { create_pr: '0/day' }, now: 1000 });
    expect(a.dryRun('github.create_pr', 'r', {}, { now: 1000 + 2 * DAY })).toStrictEqual({ allowed: false, reason: 'caveat(s) failed: expires, rate' });
  });
  it('fix: a single count limit (rate caveat) no longer denies every local dry run', async () => {
    const f = await fresh();
    const a = f.agent({ principal: P(), goal: 'g', permissions: { github: ['create_pr'] }, limits: { create_pr: '20/day' }, aud: AUD });
    expect(a.policy.caveats).toContainEqual({ type: 'rate', max: 20, per_secs: 86_400 });
    expect(a.dryRun('github.create_pr', 'r').allowed).toBe(true);
    expect(a.act('github.create_pr', 'r').dryRun.allowed).toBe(true);
  });
  it('the delegation depth of the handle is chain length - 1', async () => {
    const f = await fresh();
    const a = f.agent({ principal: P(), goal: 'g', permissions: { gmail: ['send'] } });
    a.policy.caveats.push({ type: 'delegation_depth', max: 0 });
    expect(a.dryRun('gmail.send', 'm').allowed).toBe(true);
    expect(a.subAgent().dryRun('gmail.send', 'm')).toStrictEqual({ allowed: false, reason: 'caveat(s) failed: delegation_depth' });
  });
  it('risk outside [0,1] is clamped from the blast radius (custom catalog)', async () => {
    const f = await fresh();
    const mk = (blastRadius: number) => ({ connector: 'c', action: 'a', verb: 'c.a', reversibility: 'reversible' as const, blastRadius, description: 'd' });
    for (const [b, r] of [[5, 1], [-3, 0]] as const) {
      const spec = mk(b);
      const cat = { get: (v: string) => (v === 'c.a' ? spec : undefined), forConnector: () => [spec], all: () => [spec] };
      const a = f.agent({ principal: P(), goal: 'g', permissions: { c: ['a'] }, catalog: cat, aud: AUD });
      expect(a.act('c.a', 'x').pcactn.risk_claim.r).toBe(r);
    }
  });
});
