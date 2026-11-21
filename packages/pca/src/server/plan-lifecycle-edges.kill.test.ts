/** Plan registry edges: each structural rule on its own, stored records it did not write, races, and check()'s per-action rules. */
import { describe, expect, it } from 'vitest';
import { merkleRoot, paramsDigest, planNodeLeaf, type PlanNode } from '../merkle';
import { createPlanRegistry, memoryAtomicKv, type PlanRecord, type PlanRegistry, type PlanStatus } from './plan-lifecycle';
import type { AtomicKv } from './require-pca';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const PARAMS = { n1: { invoice: 'inv_1' }, n2: { payee: 'acme', amount: 40 } };
const NODES: PlanNode[] = [
  { id: 'n1', verb: 'invoices.read', resource: 'invoices', params_digest: paramsDigest(PARAMS.n1), reversibility_class: 'reversible' },
  { id: 'n2', verb: 'payments.send', resource: 'payments', params_digest: paramsDigest(PARAMS.n2), reversibility_class: 'irreversible' },
];
const rootOf = (nodes: PlanNode[]) => merkleRoot(nodes.map(planNodeLeaf));
const ROOT = rootOf(NODES);
const keyOf = (g: string, root: string) => `pca-plan:${g}:${root}`;
const brief = (s: PlanStatus) => ({ state: s.state, executable: s.executable, reason: s.reason });

async function authorizedReg(expiresAt?: number) {
  const kv = memoryAtomicKv();
  const reg = createPlanRegistry({ kv, now: () => NOW });
  expect((await reg.draft('g', NODES)).ok).toBe(true);
  expect((await reg.validate('g', ROOT)).ok).toBe(true);
  expect((await reg.commit('g', ROOT)).ok).toBe(true);
  expect((await reg.authorize('g', ROOT, { by: 'p', ...(expiresAt !== undefined ? { expiresAt } : {}) })).ok).toBe(true);
  return { kv, reg };
}

/** Draft `nodes` and validate them; the validate result. */
async function validateNodes(nodes: unknown[]) {
  const reg = createPlanRegistry({ now: () => NOW });
  const d = await reg.draft('g', nodes as PlanNode[]);
  if (!d.ok) throw new Error(`fixture: draft refused: ${d.reason}`);
  return { root: d.record.root, v: await reg.validate('g', d.record.root) };
}

describe('validate: each structural rule on its own', () => {
  it('a stored draft with no nodes, or a null node, is invalid (no throw)', async () => {
    const kv = memoryAtomicKv();
    const reg = createPlanRegistry({ kv, now: () => NOW });
    await kv.set(keyOf('g', 'R0'), { grantRef: 'g', root: 'R0', nodes: [], state: 'draft', createdAt: NOW });
    expect(await reg.validate('g', 'R0')).toEqual({ ok: false, state: 'draft', reason: 'plan R0 is invalid: a plan needs at least one node' });
    await kv.set(keyOf('g', 'R1'), { grantRef: 'g', root: 'R1', nodes: [null], state: 'draft', createdAt: NOW });
    expect(await reg.validate('g', 'R1')).toEqual({ ok: false, state: 'draft', reason: 'plan R1 is invalid: every node needs an id' });
  });
  it('a non-string or empty id needs an id', async () => {
    for (const id of [5, '']) {
      const { root, v } = await validateNodes([{ ...NODES[0]!, id }]);
      expect(v).toEqual({ ok: false, state: 'draft', reason: `plan ${root} is invalid: every node needs an id` });
    }
  });
  it('a non-string or empty verb, and a non-string or empty resource, are refused', async () => {
    for (const over of [{ verb: 5 }, { verb: '' }, { resource: 5 }, { resource: '' }]) {
      const { root, v } = await validateNodes([{ ...NODES[0]!, ...over }]);
      expect(v).toEqual({ ok: false, state: 'draft', reason: `plan ${root} is invalid: node 'n1' needs a verb and a resource` });
    }
  });
  it('a node without a reversibility class is valid', async () => {
    const { reversibility_class: _c, ...plain } = NODES[0]!;
    void _c;
    const { v } = await validateNodes([plain]);
    expect(v.ok && v.record.state).toBe('validated');
  });
  it('stored nodes edited after the draft no longer hash to the root', async () => {
    const kv = memoryAtomicKv();
    const reg = createPlanRegistry({ kv, now: () => NOW });
    await reg.draft('g', NODES);
    const rec = (await kv.get(keyOf('g', ROOT))) as PlanRecord;
    await kv.set(keyOf('g', ROOT), { ...rec, nodes: [NODES[0]!, { ...NODES[1]!, resource: 'other' }] });
    expect(await reg.validate('g', ROOT)).toEqual({ ok: false, state: 'draft', reason: `plan ${ROOT} is invalid: the stored nodes no longer hash to the root` });
  });
});

describe('validate: unknown plans, other states and the validator', () => {
  it('an unknown root is refused with the unknown state', async () => {
    expect(await createPlanRegistry().validate('g', 'nope')).toEqual({ ok: false, state: 'unknown', reason: 'plan nope is unknown for this grant' });
  });
  it('a plan past draft is refused before the validator runs', async () => {
    let calls = 0;
    const reg = createPlanRegistry({ now: () => NOW, validator: () => (calls++, { ok: false, reason: 'no' }) });
    await reg.draft('g', NODES);
    const revoked = await reg.revoke('g', ROOT, 'x');
    expect(revoked.ok).toBe(true);
    expect(await reg.validate('g', ROOT)).toEqual({ ok: false, state: 'revoked', reason: `plan ${ROOT} is revoked: cannot validate` });
    expect(calls).toBe(0);
  });
  it('a validator that approves validates; nothing, or a non-boolean ok, is a plain refusal; a non-Error throw is unknown', async () => {
    const run = async (validator: () => unknown) => {
      const reg = createPlanRegistry({ now: () => NOW, validator: validator as never });
      await reg.draft('g', NODES);
      return reg.validate('g', ROOT);
    };
    const ok = await run(() => ({ ok: true }));
    expect(ok.ok && ok.record.state).toBe('validated');
    expect(await run(() => undefined)).toEqual({ ok: false, state: 'draft', reason: `plan ${ROOT} is invalid: refused by the validator` });
    expect(await run(() => ({ ok: 'no', reason: 'x' }))).toEqual({ ok: false, state: 'draft', reason: `plan ${ROOT} is invalid: refused by the validator` });
    expect(
      await run(() => {
        throw 'catalog down';
      }),
    ).toEqual({ ok: false, state: 'draft', reason: `plan ${ROOT} is invalid: validator error (fail closed): unknown` });
  });
  it('a plan revoked while the validator ran is not validated, and says why', async () => {
    let reg: PlanRegistry | undefined;
    reg = createPlanRegistry({
      now: () => NOW,
      validator: async () => {
        await reg!.revoke('g', ROOT, 'withdrawn');
        return { ok: true };
      },
    });
    await reg.draft('g', NODES);
    expect(await reg.validate('g', ROOT)).toEqual({ ok: false, state: 'revoked', reason: `plan ${ROOT} is revoked: cannot validate` });
  });
});

describe('draft', () => {
  it('needs a non-empty string grant', async () => {
    const reg = createPlanRegistry();
    for (const g of ['', 5]) expect(await reg.draft(g as never, NODES)).toEqual({ ok: false, state: 'unknown', reason: 'a plan needs a grant' });
    expect(await reg.get('', ROOT)).toBeUndefined();
  });
  it('a node that throws a non-Error while hashing is reported as unknown', async () => {
    const bad = {
      get id(): string {
        throw 'boom';
      },
      verb: 'v',
      resource: 'r',
    };
    expect(await createPlanRegistry().draft('g', [bad as PlanNode])).toEqual({ ok: false, state: 'unknown', reason: 'the plan cannot be committed: unknown' });
  });
});

describe('stored records the registry did not write', () => {
  it('null and a record without a root read as no record', async () => {
    const kv = memoryAtomicKv();
    const reg = createPlanRegistry({ kv });
    await kv.set(keyOf('g', 'a'), null);
    await kv.set(keyOf('g', 'b'), { nodes: [] });
    expect(await reg.get('g', 'a')).toBeUndefined();
    expect(await reg.get('g', 'b')).toBeUndefined();
  });
  it('an unknown plan has an exact status', async () => {
    expect(await createPlanRegistry().status('g', 'nope')).toEqual({ state: 'unknown', executable: false, reason: 'plan nope is unknown for this grant' });
  });
  it('a revoked record without a reason says so', async () => {
    const kv = memoryAtomicKv();
    const reg = createPlanRegistry({ kv, now: () => NOW });
    const rec = { grantRef: 'g', root: ROOT, nodes: NODES, state: 'revoked', createdAt: NOW };
    await kv.set(keyOf('g', ROOT), rec);
    expect(await reg.status('g', ROOT)).toEqual({ state: 'revoked', executable: false, reason: `plan ${ROOT} is revoked (no reason given)`, record: rec });
  });
  it('an authorized record without an approval is executable (no throw)', async () => {
    const { kv, reg } = await authorizedReg();
    const { approval: _a, ...rest } = (await kv.get(keyOf('g', ROOT))) as PlanRecord;
    void _a;
    await kv.set(keyOf('g', ROOT), rest);
    expect(brief(await reg.status('g', ROOT))).toEqual({ state: 'authorized', executable: true, reason: undefined });
  });
  it('isPlanAuthorized is false (not a throw, not undefined) when the store fails', async () => {
    const kv: AtomicKv = {
      get: async () => {
        throw new Error('store down');
      },
      set: async () => undefined,
      update: async () => undefined,
    };
    expect(await createPlanRegistry({ kv }).isPlanAuthorized('g', ROOT)).toBe(false);
  });
});

describe('authorize and revoke inputs', () => {
  async function committed() {
    const reg = createPlanRegistry({ now: () => NOW });
    await reg.draft('g', NODES);
    await reg.validate('g', ROOT);
    await reg.commit('g', ROOT);
    return reg;
  }
  it('a missing approval or a non-string by is refused with the current state', async () => {
    const reg = await committed();
    const why = 'an approval names who approved (`by`)';
    expect(await reg.authorize('g', ROOT, { by: 5 } as never)).toEqual({ ok: false, state: 'committed', reason: why });
    expect(await reg.authorize('g', ROOT, undefined as never)).toEqual({ ok: false, state: 'committed', reason: why });
    expect(await reg.authorize('g', 'nope', { by: '' })).toEqual({ ok: false, state: 'unknown', reason: why });
    expect((await reg.status('g', ROOT)).state).toBe('committed');
  });
  it('a non-finite expiresAt is refused with the current state (or unknown)', async () => {
    const reg = await committed();
    const why = 'approval.expiresAt must be a time (epoch ms)';
    expect(await reg.authorize('g', ROOT, { by: 'p', expiresAt: NaN })).toEqual({ ok: false, state: 'committed', reason: why });
    expect(await reg.authorize('g', 'nope', { by: 'p', expiresAt: Infinity })).toEqual({ ok: false, state: 'unknown', reason: why });
    expect((await reg.status('g', ROOT)).state).toBe('committed');
  });
  it('a validated and a committed plan can be revoked; a missing reason is stored as empty', async () => {
    const reg = createPlanRegistry({ now: () => NOW });
    await reg.draft('g', NODES);
    await reg.validate('g', ROOT);
    const v = await reg.revoke('g', ROOT, undefined as never);
    expect(v.ok && [v.record.state, v.record.revokedReason]).toEqual(['revoked', '']);
    const reg2 = await committed();
    const c = await reg2.revoke('g', ROOT, 'no');
    expect(c.ok && c.record.state).toBe('revoked');
  });
});

describe('check: the per-action rules', () => {
  it('a given now is used instead of the registry clock (also for context)', async () => {
    const { reg } = await authorizedReg(NOW + 100);
    expect((await reg.check('g', ROOT, { now: NOW + 100 })).executable).toBe(false);
    expect((await reg.check('g', ROOT, { now: NOW + 99 })).executable).toBe(true);
    expect((await reg.context('g', ROOT, NOW + 100))?.planAuthorized).toBe(false);
    expect((await reg.context('g', ROOT, NOW + 99))?.planAuthorized).toBe(true);
  });
  it('a plan that is not executable is answered as is, whatever node is asked for', async () => {
    const reg = createPlanRegistry({ now: () => NOW });
    await reg.draft('g', NODES);
    await reg.validate('g', ROOT);
    await reg.commit('g', ROOT);
    expect(brief(await reg.check('g', ROOT, { nodeId: 'n9' }))).toEqual({ state: 'committed', executable: false, reason: `plan ${ROOT} is committed but not authorized by the principal` });
    expect(brief(await reg.check('g', 'nope', { nodeId: 'n9' }))).toEqual({ state: 'unknown', executable: false, reason: 'plan nope is unknown for this grant' });
  });
  it('the node id is read for the decision as it is when checked', async () => {
    const { reg } = await authorizedReg();
    let reads = 0;
    const o = {
      get nodeId() {
        reads++;
        return reads === 1 ? undefined : 'n9';
      },
    };
    expect(brief(await reg.check('g', ROOT, o))).toEqual({ state: 'authorized', executable: true, reason: undefined });
  });
  it('an operation alone is matched against every node', async () => {
    const { reg } = await authorizedReg();
    expect((await reg.check('g', ROOT, { operation: { verb: 'payments.send', resource: 'payments', params: PARAMS.n2 } })).executable).toBe(true);
    expect(brief(await reg.check('g', ROOT, { operation: { verb: 'payments.send', resource: 'payments', params: { payee: 'evil', amount: 40 } } }))).toEqual({
      state: 'authorized',
      executable: false,
      reason: `plan ${ROOT}: the operation (payments.send on payments with these params) is not what the principal approved`,
    });
  });
  it('a node id alone only needs the node to exist', async () => {
    const { reg } = await authorizedReg();
    expect(brief(await reg.check('g', ROOT, { nodeId: 'n1' }))).toEqual({ state: 'authorized', executable: true, reason: undefined });
  });
  it('params that cannot be hashed are refused as such', async () => {
    const { reg } = await authorizedReg();
    const s = await reg.check('g', ROOT, { nodeId: 'n2', operation: { verb: 'payments.send', resource: 'payments', params: { amount: NaN } } });
    expect(brief(s)).toEqual({ state: 'authorized', executable: false, reason: `plan ${ROOT}: the operation's params cannot be hashed` });
    expect(s.record?.root).toBe(ROOT);
  });
  it('the verb and the resource must each match the node', async () => {
    const { reg } = await authorizedReg();
    for (const [verb, resource] of [['x', 'payments'], ['payments.send', 'y'], ['x', 'y']]) {
      expect(brief(await reg.check('g', ROOT, { nodeId: 'n2', operation: { verb: verb!, resource: resource!, params: PARAMS.n2 } }))).toEqual({
        state: 'authorized',
        executable: false,
        reason: `plan ${ROOT}: the operation (${verb} on ${resource} with these params) is not what the principal approved`,
      });
    }
  });
  it('without a node id, no node is singled out (even one whose id reads differently later)', async () => {
    const kv = memoryAtomicKv();
    const reg = createPlanRegistry({ kv, now: () => NOW });
    let reads = 0;
    const shifty = {
      ...NODES[0]!,
      get id() {
        reads++;
        return reads === 1 ? 'n1' : (undefined as unknown as string);
      },
    };
    await kv.set(keyOf('g', ROOT), { grantRef: 'g', root: ROOT, nodes: [shifty, NODES[1]!], state: 'authorized', createdAt: NOW });
    const s = await reg.check('g', ROOT, { operation: { verb: 'payments.send', resource: 'payments', params: PARAMS.n2 } });
    expect([s.executable, s.reason]).toEqual([true, undefined]);
  });
});
