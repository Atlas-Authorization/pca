import { describe, expect, it } from 'vitest';
import { mintGrant } from '../envelope';
import { encodeKey, generateKeyPair } from '../keys';
import { merkleRoot, paramsDigest, planNodeLeaf, type PlanNode } from '../merkle';
import { buildPCActn, type PCActn } from '../pcactn';
import { type RiskPolicy } from '../risk';
import { authorizeExecution } from './authorize-execution';
import { createAuthorizer, type AuthorizeOptions, type AuthorizeResult } from './authorize';
import { createExecutor, memoryOperationStore } from './operations';
import { createPlanRegistry, memoryAtomicKv, type PlanRegistry } from './plan-lifecycle';
import { atomicMemoryPcaStore, memoryPcaStore } from './require-pca';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'ops-rs';
const ZERO: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };

const PARAMS = { n1: { invoice: 'inv_1' }, n2: { payee: 'acme', amount: 40 } };
const NODES: PlanNode[] = [
  { id: 'n1', verb: 'invoices.read', resource: 'invoices', params_digest: paramsDigest(PARAMS.n1), reversibility_class: 'reversible' },
  { id: 'n2', verb: 'payments.send', resource: 'payments', params_digest: paramsDigest(PARAMS.n2), reversibility_class: 'irreversible' },
];
const ROOT = merkleRoot(NODES.map(planNodeLeaf));

function setup() {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    goal: 'pay the invoice',
    envelope: { predicates: [{ verb: ['invoices.read', 'payments.send'], resource: '*' }], caveats: [], agent_binding: {}, risk_policy: ZERO },
  });
  let counter = 0;
  const sign = (nodeId: 'n1' | 'n2', plan: PlanNode[] = NODES): PCActn =>
    buildPCActn({ grant, chain: [grant], plan, nodeId, params: PARAMS[nodeId], counter: ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW });
  return { grant, sign };
}

const opOf = (nodeId: 'n1' | 'n2', params: Record<string, unknown> = PARAMS[nodeId]) => {
  const n = NODES.find((x) => x.id === nodeId)!;
  return { verb: n.verb, resource: n.resource, params };
};

function options(grant: { id: string }, plans: PlanRegistry, clock: { t: number }, over: Partial<AuthorizeOptions> = {}): AuthorizeOptions {
  return {
    audience: AUD,
    resolveGrant: async (ref) => (ref === grant.id ? (grant as never) : null),
    budgetStore: atomicMemoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    plans,
    now: () => clock.t,
    ...over,
  };
}

const settle = (r: AuthorizeResult) => ({
  allow: r.allow,
  failed: Object.entries(r.verdict.checks)
    .filter(([, s]) => s === 'fail')
    .map(([k]) => k)
    .sort(),
  plan_state: r.verdict.checks.plan_state,
  ...(r.allow ? {} : { reason: r.reason }),
});

async function toAuthorized(reg: PlanRegistry, grantRef: string, expiresAt?: number) {
  expect((await reg.draft(grantRef, NODES)).ok).toBe(true);
  expect((await reg.validate(grantRef, ROOT)).ok).toBe(true);
  expect((await reg.commit(grantRef, ROOT)).ok).toBe(true);
  expect((await reg.authorize(grantRef, ROOT, { by: 'principal', ...(expiresAt !== undefined ? { expiresAt } : {}) })).ok).toBe(true);
}

describe('plan registry: states and transitions', () => {
  it('draft -> validated -> committed -> authorized, in order only; the state is named on a refused transition', async () => {
    const clock = { t: NOW };
    const reg = createPlanRegistry({ now: () => clock.t });
    const d = await reg.draft('g1', NODES);
    expect(d.ok && [d.record.state, d.record.root]).toEqual(['draft', ROOT]);
    expect(await reg.commit('g1', ROOT)).toEqual({ ok: false, state: 'draft', reason: `plan ${ROOT} is draft: cannot commit` });
    expect(await reg.authorize('g1', ROOT, { by: 'p' })).toEqual({ ok: false, state: 'draft', reason: `plan ${ROOT} is draft: cannot authorize` });
    expect((await reg.validate('g1', ROOT)).ok).toBe(true);
    expect(await reg.authorize('g1', ROOT, { by: 'p' })).toEqual({ ok: false, state: 'validated', reason: `plan ${ROOT} is validated: cannot authorize` });
    expect((await reg.commit('g1', ROOT)).ok).toBe(true);
    expect(await reg.validate('g1', ROOT)).toEqual({ ok: false, state: 'committed', reason: `plan ${ROOT} is committed: cannot validate` });
    expect(await reg.authorize('g1', ROOT, { by: '' })).toEqual({ ok: false, state: 'committed', reason: 'an approval names who approved (`by`)' });
    clock.t = NOW + 5;
    const a = await reg.authorize('g1', ROOT, { by: 'principal', expiresAt: NOW + 1000 });
    expect(a.ok && a.record).toEqual({
      grantRef: 'g1',
      root: ROOT,
      nodes: NODES,
      state: 'authorized',
      createdAt: NOW,
      validatedAt: NOW,
      committedAt: NOW,
      authorizedAt: NOW + 5,
      approval: { by: 'principal', expiresAt: NOW + 1000 },
    });
    expect(await reg.draft('g1', NODES)).toEqual({ ok: false, state: 'authorized', reason: `plan ${ROOT} already exists (authorized)` });
    expect((await reg.revoke('g1', ROOT, 'principal changed their mind')).ok).toBe(true);
    expect(await reg.revoke('g1', ROOT, 'again')).toEqual({ ok: false, state: 'revoked', reason: `plan ${ROOT} is revoked: cannot revoke` });
    expect(await reg.commit('g2', ROOT)).toEqual({ ok: false, state: 'unknown', reason: `plan ${ROOT} is unknown for this grant` });
  });

  it('validate refuses malformed plans and honours the server validator (a throw refuses)', async () => {
    const reg = createPlanRegistry();
    const dup = [NODES[0]!, { ...NODES[1]!, id: 'n1' }];
    const r1 = merkleRoot(dup.map(planNodeLeaf));
    await reg.draft('g', dup);
    expect(await reg.validate('g', r1)).toEqual({ ok: false, state: 'draft', reason: `plan ${r1} is invalid: duplicate node id 'n1'` });
    const odd = [{ ...NODES[0]!, reversibility_class: 'sometimes' }];
    const r2 = merkleRoot(odd.map(planNodeLeaf));
    await reg.draft('g', odd);
    expect(await reg.validate('g', r2)).toEqual({ ok: false, state: 'draft', reason: `plan ${r2} is invalid: node 'n1' has an unknown reversibility class 'sometimes'` });
    expect(await reg.draft('g', [])).toEqual({ ok: false, state: 'unknown', reason: 'the plan cannot be committed: merkleRoot: empty leaf set' });
    const v = createPlanRegistry({ validator: (rec) => (rec.nodes.every((n) => n.verb !== 'payments.send') ? { ok: true } : { ok: false, reason: 'payments need a separate plan' }) });
    await v.draft('g', NODES);
    expect(await v.validate('g', ROOT)).toEqual({ ok: false, state: 'draft', reason: `plan ${ROOT} is invalid: payments need a separate plan` });
    const t = createPlanRegistry({
      validator: () => {
        throw new Error('catalog down');
      },
    });
    await t.draft('g', NODES);
    expect(await t.validate('g', ROOT)).toEqual({ ok: false, state: 'draft', reason: `plan ${ROOT} is invalid: validator error (fail closed): catalog down` });
  });

  it('executable only when authorized, unexpired, and the nodes still hash to the root; check() refuses changed params', async () => {
    const kv = memoryAtomicKv();
    const reg = createPlanRegistry({ kv, now: () => NOW });
    await reg.draft('g', NODES);
    await reg.validate('g', ROOT);
    await reg.commit('g', ROOT);
    expect(await reg.status('g', ROOT)).toEqual(expect.objectContaining({ state: 'committed', executable: false, reason: `plan ${ROOT} is committed but not authorized by the principal` }));
    expect(await reg.isPlanAuthorized('g', ROOT)).toBe(false);
    await reg.authorize('g', ROOT, { by: 'p', expiresAt: NOW + 100 });
    expect((await reg.status('g', ROOT, NOW + 99)).executable).toBe(true);
    expect(await reg.status('g', ROOT, NOW + 100)).toEqual(expect.objectContaining({ executable: false, reason: `plan ${ROOT}: the principal's approval expired at ${NOW + 100}` }));
    expect((await reg.check('g', ROOT, { nodeId: 'n2', operation: opOf('n2'), now: NOW })).executable).toBe(true);
    expect(await reg.check('g', ROOT, { nodeId: 'n2', operation: opOf('n2', { payee: 'acme', amount: 400 }), now: NOW })).toEqual(
      expect.objectContaining({ executable: false, reason: `plan ${ROOT}: the operation (payments.send on payments with these params) is not what the principal approved` }),
    );
    expect(await reg.check('g', ROOT, { nodeId: 'n9', now: NOW })).toEqual(expect.objectContaining({ executable: false, reason: `plan ${ROOT} has no node 'n9'` }));
    // stored nodes edited behind the registry's back: no longer executable
    const key = `pca-plan:g:${ROOT}`;
    const rec = (await kv.get(key)) as { nodes: PlanNode[] };
    await kv.set(key, { ...rec, nodes: [{ ...NODES[0]! }, { ...NODES[1]!, params_digest: paramsDigest({ payee: 'evil', amount: 40 }) }] });
    expect(await reg.status('g', ROOT, NOW)).toEqual(expect.objectContaining({ executable: false, reason: `plan ${ROOT}: the stored nodes no longer hash to the root` }));
  });
});

describe('authorize({ plans }): a committed plan is not executable until authorized, and the state is named', () => {
  it('draft, validated, committed, revoked and expired plans are denied with the state; the authorized plan runs', async () => {
    const { grant, sign } = setup();
    const clock = { t: NOW };
    const reg = createPlanRegistry({ now: () => clock.t });
    const az = createAuthorizer(options(grant, reg, clock));
    const deny = (state: string) => ({ allow: false, failed: ['plan_root_authorized', 'plan_state'], plan_state: 'fail', reason: `plan_state: plan ${ROOT} is ${state}` });

    await reg.draft(grant.id, NODES);
    expect(settle(await az({ pcactn: sign('n2'), operation: opOf('n2') }))).toEqual(deny('draft, not authorized'));
    await reg.validate(grant.id, ROOT);
    expect(settle(await az({ pcactn: sign('n2'), operation: opOf('n2') }))).toEqual(deny('validated, not authorized'));
    await reg.commit(grant.id, ROOT);
    expect(settle(await az({ pcactn: sign('n2'), operation: opOf('n2') }))).toEqual(deny('committed but not authorized by the principal'));
    await reg.authorize(grant.id, ROOT, { by: 'principal', expiresAt: NOW + 60_000 });
    expect(settle(await az({ pcactn: sign('n1'), operation: opOf('n1') }))).toEqual({ allow: true, failed: [], plan_state: 'pass' });
    expect(settle(await az({ pcactn: sign('n2'), operation: opOf('n2') }))).toEqual({ allow: true, failed: [], plan_state: 'pass' });
    clock.t = NOW + 60_000;
    expect(settle(await az({ pcactn: sign('n2'), operation: opOf('n2') }))).toEqual({
      allow: false,
      failed: ['plan_root_authorized', 'plan_state'],
      plan_state: 'fail',
      reason: `plan_state: plan ${ROOT}: the principal's approval expired at ${NOW + 60_000}`,
    });
    clock.t = NOW;
    await reg.revoke(grant.id, ROOT, 'invoice disputed');
    expect(settle(await az({ pcactn: sign('n2'), operation: opOf('n2') }))).toEqual(deny('revoked (invoice disputed)'));
  });

  it('changed params against an authorized plan are refused (the binding names it first)', async () => {
    const { grant, sign } = setup();
    const clock = { t: NOW };
    const reg = createPlanRegistry({ now: () => clock.t });
    await toAuthorized(reg, grant.id);
    const r = await createAuthorizer(options(grant, reg, clock))({ pcactn: sign('n2'), operation: opOf('n2', { payee: 'acme', amount: 400 }) });
    expect(settle(r)).toEqual({
      allow: false,
      failed: ['operation', 'params_digest'],
      plan_state: 'pass',
      reason: "operation: the proof's params_digest does not match the params of this payments.send operation",
    });
  });

  it('an unknown root is denied with its state, or falls back to single-step when configured', async () => {
    const { grant, sign } = setup();
    const clock = { t: NOW };
    const reg = createPlanRegistry({ now: () => clock.t });
    const oneStep = [NODES[1]!];
    const root1 = merkleRoot(oneStep.map(planNodeLeaf));
    const p = () => sign('n2', [{ ...NODES[1]!, id: 'n2' }]);
    expect(settle(await createAuthorizer(options(grant, reg, clock))({ pcactn: p(), operation: opOf('n2') }))).toEqual({
      allow: false,
      failed: ['plan_root_authorized', 'plan_state'],
      plan_state: 'fail',
      reason: `plan_state: plan ${root1} is unknown to the plan registry`,
    });
    expect(settle(await createAuthorizer(options(grant, reg, clock, { plan: 'single-step' }))({ pcactn: p(), operation: opOf('n2') }))).toEqual({ allow: true, failed: [], plan_state: undefined });
    // a registered root wins over single-step: a revoked one-step plan is denied even with single-step on
    await reg.draft(grant.id, oneStep);
    await reg.revoke(grant.id, root1, 'no');
    expect(settle(await createAuthorizer(options(grant, reg, clock, { plan: 'single-step' }))({ pcactn: p(), operation: opOf('n2') })).reason).toBe(`plan_state: plan ${root1} is revoked (no)`);
  });

  it('without `plans` nothing changes: no plan_state check, the planAuthorized boolean still decides', async () => {
    const { grant, sign } = setup();
    const clock = { t: NOW };
    const base = { ...options(grant, createPlanRegistry(), clock), plans: undefined };
    const yes = await createAuthorizer({ ...base, context: () => ({ plan: NODES, planAuthorized: true }) })({ pcactn: sign('n2'), operation: opOf('n2') });
    expect(settle(yes)).toEqual({ allow: true, failed: [], plan_state: undefined });
    expect('plan_state' in yes.verdict.checks).toBe(false);
    const no = await createAuthorizer({ ...base, context: () => ({ plan: NODES, planAuthorized: false }) })({ pcactn: sign('n2'), operation: opOf('n2') });
    expect(settle(no)).toEqual({ allow: false, failed: ['plan_root_authorized'], plan_state: undefined, reason: 'plan_root_authorized: the plan root has not been authorized by the principal' });
  });

  it('a plan from context() wins over the registry (the registry is not consulted)', async () => {
    const { grant, sign } = setup();
    const clock = { t: NOW };
    const reg = createPlanRegistry({ now: () => clock.t });
    let consulted = 0;
    const spy: PlanRegistry = { ...reg, context: async (...a) => (consulted++, reg.context(...a)) };
    const r = await createAuthorizer(options(grant, spy, clock, { context: () => ({ plan: NODES, planAuthorized: true }) }))({ pcactn: sign('n2'), operation: opOf('n2') });
    expect([settle(r), consulted]).toEqual([{ allow: true, failed: [], plan_state: undefined }, 0]);
  });
});

describe('the plan lifecycle with the other entry points', () => {
  it('isPlanAuthorized for authorizeExecution: allowed while authorized, denied once revoked', async () => {
    const { grant, sign } = setup();
    const reg = createPlanRegistry({ now: () => NOW });
    const one = [{ ...NODES[1]!, id: 'n2' }];
    const root1 = merkleRoot(one.map(planNodeLeaf));
    await reg.draft(grant.id, one);
    await reg.validate(grant.id, root1);
    await reg.commit(grant.id, root1);
    const run = () =>
      authorizeExecution(sign('n2', one), opOf('n2'), {
        audience: AUD,
        grant,
        state: memoryPcaStore(),
        isRevoked: () => false,
        isPlanAuthorized: reg.isPlanAuthorized,
        now: () => NOW,
      });
    expect((await run()).allow).toBe(false);
    await reg.authorize(grant.id, root1, { by: 'p' });
    expect((await run()).allow).toBe(true);
    await reg.revoke(grant.id, root1, 'stop');
    const d = await run();
    expect(d.allow ? '' : d.reason).toBe('plan_root_authorized: the plan root has not been authorized by the principal');
  });

  it('the executor re-checks the plan before an irreversible step: revoked between authorize and execute -> aborted', async () => {
    const { grant, sign } = setup();
    const clock = { t: NOW };
    const reg = createPlanRegistry({ now: () => clock.t });
    await toAuthorized(reg, grant.id);
    let runs = 0;
    let calls = 0;
    const ex = createExecutor({
      ...options(grant, reg, clock),
      operations: memoryOperationStore(),
      hooks: {
        // 1st call: the authorize decision; 2nd: the executor's recheck. The plan is revoked in between.
        revocation: async () => {
          if (++calls === 2) await reg.revoke(grant.id, ROOT, 'withdrawn');
          return { enforced: true, ok: true };
        },
      },
    });
    const out = await ex({ pcactn: sign('n2'), operation: opOf('n2') }, () => {
      runs++;
      return 'paid';
    });
    expect(out).toEqual({ status: 'aborted', operationId: expect.any(String), reason: `recheck: plan ${ROOT} is revoked (withdrawn)`, replayed: false });
    expect(runs).toBe(0);
  });
});
