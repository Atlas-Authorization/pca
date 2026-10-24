/**
 * 0.4.2 r12 mutation kills, part 2: the remaining module-load constants of action-schema.ts (reversibility classes,
 * parameter types, the parameter-path and unit-id patterns, the closed member sets, the small helper arrows, the date
 * pattern, the reversibility ranking and the wallet floor lists). Under Stryker's mutant switching these are built before
 * any mutant is active, so only a fresh module (vi.resetModules + dynamic import) sees them. Each check goes through an
 * exported function.
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  return import('./action-schema');
}

const P = 'action.params.x';
const decl = (extra: Record<string, unknown> = {}, type = 'integer') => ({ type, semantic: 's', sensitivity: 'free', ...extra });
const doc = (params: Record<string, unknown>, verbExtra: Record<string, unknown> = {}, docExtra: Record<string, unknown> = {}) => ({
  v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1',
  units: { u: { kind: 'count' } },
  verbs: [{ verb: 'a.b', kind: 'write', params, ...verbExtra }],
  ...docExtra,
});

describe('enumerations (fresh module)', () => {
  it('reversibility classes and parameter types are the normative lists', async () => {
    const s = await fresh();
    expect(s.SCHEMA_REVERSIBILITY).toStrictEqual(['reversible', 'rate_limited', 'irreversible']);
    expect(s.PARAM_TYPES).toStrictEqual(['string', 'integer', 'boolean', 'date', 'set', 'array']);
    for (const r of ['reversible', 'rate_limited', 'irreversible']) expect(s.actionSchemaShapeError(doc({}, { reversibility: r }), { signed: false })).toBeNull();
    expect(s.actionSchemaShapeError(doc({}, { reversibility: '' }), { signed: false })).toBe("verb 'a.b': unknown reversibility");
    for (const t of ['string', 'integer', 'boolean', 'date', 'array']) expect(s.actionSchemaShapeError(doc({ [P]: decl({}, t) }), { signed: false })).toBeNull();
    expect(s.actionSchemaShapeError(doc({ [P]: decl({ values: ['a'] }, 'set') }), { signed: false })).toBeNull();
    expect(s.actionSchemaShapeError(doc({ [P]: decl({}, '') }), { signed: false })).toBe("verb 'a.b': action.params.x: unknown type");
  });
});

describe('parameter path pattern (fresh module)', () => {
  it('is action.params.<1..64 word chars>, anchored at both ends', async () => {
    const s = await fresh();
    const e = (p: string) => s.actionSchemaShapeError(doc({ [p]: decl() }), { signed: false });
    expect(e('action.params.ab')).toBeNull();
    expect(e(`action.params.${'a'.repeat(64)}`)).toBeNull();
    expect(e('xaction.params.ab')).toBe("verb 'a.b': parameter path 'xaction.params.ab' is not action.params.<name>");
    expect(e('action.params.ab!')).toBe("verb 'a.b': parameter path 'action.params.ab!' is not action.params.<name>");
    expect(e(`action.params.${'a'.repeat(65)}`)).toBe(`verb 'a.b': parameter path 'action.params.${'a'.repeat(65)}' is not action.params.<name>`);
  });
});

describe('unit id pattern (fresh module)', () => {
  it('is dotted lowercase word segments, anchored at both ends (unit ids and accumulates_into)', async () => {
    const s = await fresh();
    const unit = (id: string) => s.actionSchemaShapeError(doc({}, {}, { units: { [id]: { kind: 'count' } } }), { signed: false });
    for (const ok of ['u', 'ab', 'a.bc', 'a.bc.d_9']) expect(unit(ok)).toBeNull();
    for (const bad of ['Xu', 'u-', 'a..b', '.a', 'a.', 'a.B']) expect(unit(bad)).toBe(`unit id '${bad}' is malformed`);
    const acc = (a: string) => s.actionSchemaShapeError(doc({ [P]: decl({ accumulates_into: [a] }) }), { signed: false });
    expect(acc('ab.cd.ef')).toBeNull();
    expect(acc('Xab')).toBe("verb 'a.b': action.params.x: accumulates_into entries must be unit ids");
  });
});

describe('closed member sets (fresh module)', () => {
  it('every optional document, verb, parameter and sig member is accepted', async () => {
    const s = await fresh();
    expect(s.actionSchemaShapeError(doc({}, {}, { state: [] }), { signed: false })).toBeNull();
    expect(s.actionSchemaShapeError(doc({}, {}, { units: { u: { kind: 'count' } } }), { signed: false })).toBeNull();
    const verb = {
      reversibility: 'reversible',
      reversibility_by: { param: P, map: { a: 'reversible' }, default: 'irreversible' },
      mcp: { tool: 't' }, openapi: { operationId: 'o' }, harm: {}, world: [], effects: {}, returns: {}, description: 'd',
    };
    const params = { [P]: decl({ values: ['a'] }, 'string') };
    expect(s.actionSchemaShapeError(doc(params, verb), { signed: false })).toBeNull();
    for (const k of Object.keys(verb)) {
      const { [k]: _drop, ...rest } = verb as Record<string, unknown>;
      void _drop;
      expect(s.actionSchemaShapeError(doc(params, rest), { signed: false })).toBeNull();
    }
    const paramVariants: Record<string, unknown>[] = [
      decl({ required: false }),
      decl({ values: ['a'] }, 'string'),
      decl({ min: 0, max: 5 }),
      decl({ unit: 'u' }),
      decl({ max_len: 10 }, 'string'),
      decl({ items: 'integer' }, 'array'),
      decl({ min_items: 0, max_items: 2 }, 'array'),
      decl({ default: 1, principal_neutral_default: true }),
      decl({ accumulates_into: ['u'] }),
      decl({ issued_by_site: true }),
      decl({ description: 'd' }),
    ];
    for (const d of paramVariants) expect(s.actionSchemaShapeError(doc({ [P]: d }), { signed: false }), JSON.stringify(d)).toBeNull();
    const signed = { ...doc({}), sig: { alg: 'ed25519', kid: 'k', value: 'AAAA', pq_value: 'AAAA' } };
    expect(s.actionSchemaShapeError(signed)).toBeNull();
  });
});

describe('helper predicates (fresh module)', () => {
  it('integers, non-negative item bounds, own members and string items behave', async () => {
    const s = await fresh();
    expect(s.paramValueViolation(decl() as never, 5)).toBeNull();
    expect(s.actionSchemaShapeError(doc({ [P]: decl({ min: 1, max: 3 }) }), { signed: false })).toBeNull();
    expect(s.actionSchemaShapeError(doc({ [P]: decl({ values: ['a'], min_items: 0, max_items: 1 }, 'set') }), { signed: false })).toBeNull();
    expect(s.actionSchemaShapeError(doc({ [P]: decl({ unit: 'u' }) }), { signed: false })).toBeNull();
    const d = doc({ [P]: decl() }) as never;
    expect(s.conformAction(d, 'a.b', { x: 3 })).toMatchObject({ ok: true });
    expect(s.paramValueViolation(decl({}, 'array') as never, ['a', 'b'])).toBeNull();
  });
});

describe('date pattern (fresh module)', () => {
  it('is YYYY-MM-DD, two-digit month and day, anchored at both ends', async () => {
    const s = await fresh();
    const v = (x: string) => s.paramValueViolation(decl({}, 'date') as never, x);
    expect(v('2024-02-29')).toBeNull();
    expect(v('0001-12-31')).toBeNull();
    for (const bad of ['x2024-02-29', '2024-02-29x', '2024-2-29', '2024-02-9', '24-02-29', 'abcd-02-29', '2024-ab-29', '2024-02-ab']) {
      expect(v(bad), bad).toStrictEqual({ code: 'out_of_domain', reason: 'not a calendar date YYYY-MM-DD' });
    }
  });
});

describe('reversibility ranking (fresh module)', () => {
  it('verbReversibility takes the maximum class and reversibilityOf maps the value', async () => {
    const s = await fresh();
    const v = (map: Record<string, string>, extra: Record<string, unknown> = {}) => ({
      verb: 'a.b', kind: 'write', params: { [P]: decl({}, 'boolean') }, reversibility_by: { param: P, map, ...extra },
    }) as never;
    expect(s.verbReversibility(v({ true: 'reversible', false: 'rate_limited' }))).toBe('rate_limited');
    expect(s.verbReversibility(v({ true: 'irreversible', false: 'reversible' }))).toBe('irreversible');
    expect(s.verbReversibility(v({ true: 'reversible', false: 'reversible' }))).toBe('reversible');
    expect(s.reversibilityOf(v({ true: 'reversible' }, { default: 'irreversible' }), { x: true })).toBe('reversible');
    expect(s.reversibilityOf(v({ true: 'rate_limited' }, { default: 'irreversible' }), { x: true })).toBe('rate_limited');
    expect(s.reversibilityOf(v({ '7': 'reversible' }, { default: 'irreversible' }), { x: 7 })).toBe('reversible');
  });
});

describe('wallet floor lists (fresh module)', () => {
  it('the default floor covers the normative prefixes and exact types', async () => {
    const s = await fresh();
    expect(s.WALLET_FLOOR_PREFIXES).toStrictEqual(['money.', 'party.', 'contact.', 'person.', 'credential.']);
    expect(s.WALLET_FLOOR_EXACT).toStrictEqual(['text.message']);
    for (const t of ['money.amount', 'party.payee', 'contact.email', 'person.name', 'credential.otp', 'text.message']) expect(s.floorApplies(t), t).toBe(true);
    expect(s.floorApplies('place.airport')).toBe(false);
    expect(s.floorApplies('')).toBe(false);
  });
});
