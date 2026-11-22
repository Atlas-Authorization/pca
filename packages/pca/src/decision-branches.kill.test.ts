// Exact-outcome tests for decision.ts: the fail-closed catch paths of decideTighten / decideUnits, the condition walk
// (null, non-object, depth cap, a `not` read once), unit tag rendering and matching, the sorted read order, and the
// module-level tables (re-evaluated in a fresh module so they are rebuilt inside the test).
import { describe, expect, it, vi } from 'vitest';
import { decideTighten, decideUnits, decisionOf, isModelDerivedPath, meet, modelPathsRead } from './decision';

const MARKER = ['Stry', 'ker was here'].join('');

describe('decision.ts: meet only ranks the three own decision names', () => {
  it('an inherited key or a value that coerces to a decision name is unknown (deny)', () => {
    expect(meet('constructor' as never, 'allow')).toBe('deny');
    expect(meet('allow', 'toString' as never)).toBe('deny');
    expect(meet(['allow'] as never, 'allow')).toBe('deny');
    expect(meet('allow', ['escalate'] as never)).toBe('deny');
    expect(meet('escalate', 'allow')).toBe('escalate');
  });
});

describe('decision.ts: decisionOf skips non-string reasons', () => {
  it('a non-string reason next to an unsupported check is ignored, not a crash', () => {
    expect(decisionOf({ allow: false, checks: { x: 'unsupported', y: 'fail' }, reasons: [5 as never, 'y: escalate: z'] })).toBe('escalate');
  });
});

describe('decision.ts: isModelDerivedPath', () => {
  it('only env.world reads a single source', () => {
    expect(isModelDerivedPath('env.foo', ['w'])).toBe(false);
    expect(isModelDerivedPath('env.foo.w', ['w'])).toBe(false);
    expect(isModelDerivedPath('env.world.w', ['w'])).toBe(true);
  });
});

describe('decision.ts: modelPathsRead walk', () => {
  const read = (c: unknown, single?: string[]) => modelPathsRead([[{ where: [c] }]], single);
  it('null and non-object conditions contribute nothing', () => {
    expect(read(null)).toEqual([]);
    expect(read(Object.assign(() => 0, { field: 'env.class.x' }))).toEqual([]);
  });
  it('the nesting cap: depth 64 is read, depth 65 is not', () => {
    const nest = (k: number) => {
      let c: unknown = { field: 'env.class.deep' };
      for (let i = 0; i < k; i++) c = { all_of: [c] };
      return c;
    };
    expect(read(nest(64))).toEqual(['env.class.deep']);
    expect(read(nest(65))).toEqual([]);
  });
  it('`not` is followed through the value it had when tested', () => {
    let n = 0;
    const c = {
      get not() {
        return n++ === 0 ? { field: 'env.class.x' } : undefined;
      },
    };
    expect(read(c)).toEqual([]);
  });
  it('env.world is single-source only when a world is named (default: none)', () => {
    expect(read({ field: 'env.world' })).toEqual([]);
    expect(read({ field: 'env.world' }, ['w'])).toEqual(['env.world']);
  });
});

describe('decision.ts: decideTighten', () => {
  it('non-string single_source entries are dropped; an ok outcome carries no reason member', () => {
    const r = decideTighten({ predicates: [[{ where: [{ field: 'env.world' }] }]], single_source: [5 as never] });
    expect(r).toEqual({ outcome: 'ok', legacy: false, offending: [] });
    expect(Object.keys(r)).toEqual(['outcome', 'legacy', 'offending']);
  });
  it('an evaluation error fails closed with its message', () => {
    const boom = {
      get single_source(): string[] {
        throw new Error('boom');
      },
    };
    expect(decideTighten(boom)).toEqual({ outcome: 'deny', legacy: false, offending: [], reason: 'evaluation error (fail closed): boom' });
    const odd = {
      get single_source(): string[] {
        throw 'x';
      },
    };
    expect(decideTighten(odd)).toEqual({ outcome: 'deny', legacy: false, offending: [], reason: 'evaluation error (fail closed): unknown' });
  });
});

describe('decision.ts: decideUnits', () => {
  const tag = { kind: 'count' };
  it('an evaluation error fails closed with its message', () => {
    const boom = {
      get units(): unknown {
        throw new Error('boom');
      },
    };
    expect(decideUnits(boom)).toEqual({ ok: false, reason: 'evaluation error (fail closed): boom' });
    const odd = {
      get units(): unknown {
        throw 'x';
      },
    };
    expect(decideUnits(odd)).toEqual({ ok: false, reason: 'evaluation error (fail closed): unknown' });
  });
  it('a parameter without a unit id never picks up a schema entry named "undefined"', () => {
    expect(decideUnits({ verb: 'pay', units: { 'action.params.amount': { kind: 'money' } }, schema_units: { undefined: { kind: 'money' } }, verb_params: { 'action.params.amount': {} } })).toEqual({
      ok: false,
      reason: "'action.params.amount' is declared as no unit by the action schema but the policy term is tagged money (unit confusion)",
    });
  });
  it('untagged reads are reported in sorted order', () => {
    const where = [{ field: 'action.params.b', op: 'eq', value: 1 }, { field: 'action.params.a', op: 'eq', value: 1 }];
    expect(decideUnits({ verb: 'pay', units: {}, schema_units: { u: tag }, verb_params: { 'action.params.a': { unit: 'u' }, 'action.params.b': { unit: 'u' } }, predicates: [[{ verb: 'pay', where }]] })).toEqual({
      ok: false,
      reason: "a policy term reads 'action.params.a' (count) without a unit tag",
    });
  });
  it('only action.params.<name> paths need a tag, and only string paths are read', () => {
    expect(decideUnits({ verb: 'pay', units: {}, schema_units: { u: tag }, verb_params: { amount: { unit: 'u' } }, predicates: [[{ verb: 'pay', where: [{ field: 'amount', op: 'eq', value: 1 }] }]] })).toEqual({ ok: true });
    expect(decideUnits({ verb: 'pay', units: {}, schema_units: { u: tag }, verb_params: { 'action.params.a': { unit: 'u' } }, predicates: [[{ verb: 'pay', where: [{ field: ['action.params.a'], op: 'eq', value: 1 }] }]] })).toEqual({ ok: true });
  });
});

// Module-level tables and helpers are built once at import: re-evaluate the module so they are rebuilt inside the test.
async function fresh() {
  vi.resetModules();
  return import('./decision');
}

describe('decision.ts (fresh module): tables and unit helpers', () => {
  it('the decision ranks', async () => {
    const m = await fresh();
    expect(m.meet('allow', 'allow')).toBe('allow');
    expect(m.meet('allow', 'escalate')).toBe('escalate');
    expect(m.meet('deny', 'escalate')).toBe('deny');
  });
  it('the escalate reason prefixes', async () => {
    const m = await fresh();
    expect([...m.ESCALATE_REASON_PREFIXES]).toEqual(['intent_required:', 'escalate:']);
    expect(m.decisionOf({ allow: false, checks: { a: 'fail' }, reasons: ['a: intent_required: q'] })).toBe('escalate');
    expect(m.decisionOf({ allow: false, checks: { a: 'fail' }, reasons: ['a: escalate: q'] })).toBe('escalate');
    expect(m.decisionOf({ allow: false, checks: { a: 'fail' }, reasons: ['a: other: q'] })).toBe('deny');
  });
  it('the model env roots', async () => {
    const m = await fresh();
    expect([...m.MODEL_ENV_ROOTS]).toEqual(['class', 'prov', 'judge', 'detect']);
    for (const r of ['class', 'prov', 'judge', 'detect']) expect(m.isModelDerivedPath(`env.${r}.x`)).toBe(true);
    expect(m.isModelDerivedPath(`env.${MARKER}.x`)).toBe(false);
  });
  it('a bare `env` path is never model-derived, whatever the roots table holds', async () => {
    const m = await fresh();
    (m.MODEL_ENV_ROOTS as unknown[]).push(undefined);
    expect(m.isModelDerivedPath('env', ['w'])).toBe(false);
  });
  it('unit tags render kind/currency/exponent ("?" for a missing kind) and match exactly', async () => {
    const m = await fresh();
    const money = { kind: 'money', currency: 'USD', exponent: 2 };
    expect(m.decideUnits({ verb: 'pay', units: { 'action.params.amount': money }, schema_units: { u: money }, verb_params: { 'action.params.amount': { unit: 'u' } } })).toEqual({ ok: true });
    expect(m.decideUnits({ verb: 'pay', units: { 'action.params.amount': money }, schema_units: { u: { currency: 'USD' } }, verb_params: { 'action.params.amount': { unit: 'u' } } })).toEqual({
      ok: false,
      reason: "'action.params.amount' is declared as ?/USD by the action schema but the policy term is tagged money/USD/e2 (unit confusion)",
    });
  });
});
