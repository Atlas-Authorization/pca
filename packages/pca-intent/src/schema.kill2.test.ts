import { describe, expect, it } from 'vitest';
import { canonicalizeStrict } from '@atlasauth/pca';
import { canonValue, deriveOmegaFromSchema } from './schema';

type Verbs = Parameters<typeof deriveOmegaFromSchema>[0]['schema']['verbs'];
type Param = Verbs[number]['params'][string];

const P = 'action.params.';
const mat = (type: Param['type'], extra: Partial<Param> = {}): Param => ({ type, semantic: 'thing.plain', sensitivity: 'material', ...extra });

describe('canonValue', () => {
  it('booleans are the literal words, anything that is not exactly true is false', () => {
    const d = mat('boolean');
    expect(canonValue(d, true)).toBe('true');
    expect(canonValue(d, false)).toBe('false');
    expect(canonValue(d, 'true')).toBe('false');
    expect(canonValue(d, 1)).toBe('false');
  });
  it('sets are sorted, arrays keep their order, everything else is canonical JSON', () => {
    const input = ['b', 'a', 'c'];
    expect(canonValue(mat('set'), input)).toBe(canonicalizeStrict(['a', 'b', 'c']));
    expect(input).toEqual(['b', 'a', 'c']);
    expect(canonValue(mat('array'), [3, 1])).toBe('[3,1]');
    expect(canonValue(mat('string'), 'x')).toBe('"x"');
  });
});

describe('deriveOmegaFromSchema: dimension shapes', () => {
  const verbs: Verbs = [
    {
      verb: 'a.pay',
      kind: 'write',
      params: {
        [P + 'p5']: mat('integer'),
        [P + 'p30']: mat('integer'),
        [P + 'neg']: mat('integer'),
        [P + 'plain']: mat('integer'),
        [P + 'dec']: mat('integer'),
        [P + 'to']: mat('string', { values: ['bob', 'al'] }),
        [P + 'cnt']: mat('string'),
        [P + 'who']: { type: 'string', semantic: 'party.payee', sensitivity: 'free' },
        [P + 'junk']: { type: 'string', semantic: 'text.note', sensitivity: 'free' },
      },
    },
  ];
  // computed inside each test: the derivation must run with the test's mutant active
  const shape = () => {
    const r = deriveOmegaFromSchema({
      schema: { verbs },
      slots: {
        verbs: ['a.pay'],
        constraints: [
          { verb: 'a.pay', path: P + 'to', oneOf: ['carol'], prefixOneOf: ['team/'] },
          { verb: 'a.pay', path: P + 'cnt', max: 5 },
          { verb: 'a.pay', path: 'env.hour', max: 18 },
        ],
      },
      confirmed: {
        [P + 'p5']: [5, 'x'],
        [P + 'p30']: [30, 7, 5],
        [P + 'neg']: [-5],
        [P + 'dec']: [2.5, '9', true],
      },
    });
    const vs = r.omega.verbs[0]!;
    const dim = (p: string) => vs.dims.find((d) => d.path === p);
    return { r, vs, dim };
  };

  it('keeps non-parameter dimensions and orders all dimensions by path', () => {
    const { r, vs, dim } = shape();
    expect(vs.dims.map((d) => d.path)).toEqual([P + 'cnt', P + 'dec', P + 'neg', P + 'p30', P + 'p5', P + 'plain', P + 'to', P + 'who', 'env.hour']);
    expect(dim('env.hour')).toMatchObject({ kind: 'num', lo: 0, hi: 23, cuts: [18] });
  });
  it('integers: confirmed safe integers become sorted cuts; domains follow the cuts', () => {
    const { r, vs, dim } = shape();
    expect(dim(P + 'p5')).toEqual({ kind: 'num', path: P + 'p5', lo: 0, hi: 15, cuts: [5], dist: 'loguniform' });
    expect(dim(P + 'p30')).toEqual({ kind: 'num', path: P + 'p30', lo: 0, hi: 60, cuts: [5, 7, 30], dist: 'loguniform' });
    expect(dim(P + 'neg')).toEqual({ kind: 'num', path: P + 'neg', lo: -6, hi: 10, cuts: [-5], dist: 'uniform' });
    expect(dim(P + 'plain')).toEqual({ kind: 'num', path: P + 'plain', lo: 0, hi: 10, cuts: [], dist: 'loguniform' });
    expect(dim(P + 'dec')).toEqual({ kind: 'num', path: P + 'dec', lo: 0, hi: 10, cuts: [], dist: 'loguniform' });
  });
  it('a silent integer with exactly one numeric confirmed value pins it; no other silent parameter does', () => {
    const { r, vs, dim } = shape();
    expect(r.defaults).toEqual([
      { verb: 'a.pay', path: P + 'dec', min: 2.5, max: 2.5 },
      { verb: 'a.pay', path: P + 'neg', min: -5, max: -5 },
      { verb: 'a.pay', path: P + 'p5', min: 5, max: 5 },
    ]);
    expect(r.canonOf).toEqual({});
  });
  it('strings: schema enum, slot values and prefixes, then ⊥; a numeric slot on a string leaves only ⊥', () => {
    const { r, vs, dim } = shape();
    expect(dim(P + 'to')).toEqual({
      kind: 'cat',
      path: P + 'to',
      values: [
        { kind: 'exact', value: 'al' },
        { kind: 'exact', value: 'bob' },
        { kind: 'exact', value: 'carol' },
        { kind: 'prefix', value: 'team/' },
        { kind: 'other', value: '⊥' },
      ],
    });
    expect(dim(P + 'cnt')).toEqual({ kind: 'cat', path: P + 'cnt', values: [{ kind: 'other', value: '⊥' }] });
    expect(dim(P + 'who')).toEqual({ kind: 'cat', path: P + 'who', values: [{ kind: 'other', value: '⊥' }] });
  });
  it('reports the floor override only for the parameter the wallet raised', () => {
    const { r, vs, dim } = shape();
    expect(r.overrides).toEqual([{ verb: 'a.pay', path: P + 'who', semantic: 'party.payee', declared: 'free', effective: 'material' }]);
  });
});

describe('deriveOmegaFromSchema: verb selection', () => {
  const free = (semantic: string): Param => ({ type: 'string', semantic, sensitivity: 'free' });
  const verbs: Verbs = [
    { verb: 'b.w', kind: 'write', params: { [P + 'm']: free('money.amount') } },
    { verb: 'a.w', kind: 'write', params: { [P + 'm']: free('party.payee') } },
    { verb: 'c.r', kind: 'read', params: { [P + 'm']: free('money.amount') } },
  ];
  it('defaults to every write verb plus the slot verbs, sorted, with equal weights', () => {
    const w = deriveOmegaFromSchema({ schema: { verbs } });
    expect(w.omega.verbs.map((v) => [v.verb, v.weight, v.reversibility])).toEqual([
      ['a.w', 0.5, 'irreversible'],
      ['b.w', 0.5, 'irreversible'],
    ]);
    expect(w.defaults).toEqual([]);
    const s = deriveOmegaFromSchema({ schema: { verbs }, slots: { verbs: ['c.r'], constraints: [] } });
    expect(s.omega.verbs.map((v) => [v.verb, v.weight, v.reversibility])).toEqual([
      ['a.w', 1 / 3, 'irreversible'],
      ['b.w', 1 / 3, 'irreversible'],
      ['c.r', 1 / 3, 'reversible'],
    ]);
  });
  it('sorts explicit verbs, skips undeclared ones, and reports overrides only for the chosen verbs', () => {
    const r = deriveOmegaFromSchema({ schema: { verbs }, verbs: ['b.w', 'z.u', 'a.w'] });
    expect(r.omega.verbs.map((v) => [v.verb, v.weight])).toEqual([
      ['a.w', 0.5],
      ['b.w', 0.5],
    ]);
    expect(r.overrides.map((o) => o.verb)).toEqual(['b.w', 'a.w']);
    expect(deriveOmegaFromSchema({ schema: { verbs }, verbs: [] }).omega.verbs).toEqual([]);
  });
});

describe('deriveOmegaFromSchema: canonical projections and default sets', () => {
  const verbs: Verbs = [
    {
      verb: 'a.set',
      kind: 'write',
      params: {
        [P + 'to']: mat('string'),
        [P + 'tags']: mat('set', { values: ['y', 'x'] }),
        [P + 'mode']: mat('string', { default: 'slow' }),
        [P + 'half']: mat('string', { principal_neutral_default: true }),
        [P + 'flag']: mat('boolean'),
        [P + 'arr']: mat('array', { principal_neutral_default: true, default: [2, 1] }),
      },
    },
  ];
  // prefixes the slot gives in UTF-16 order; the map orders them by UTF-8 bytes (U+FF5E before U+1F600)
  const wide = '～';
  const astral = '\u{1F600}';
  const run = () =>
    deriveOmegaFromSchema({
      schema: { verbs },
      slots: { verbs: ['a.set'], constraints: [{ verb: 'a.set', path: P + 'to', oneOf: ['b'], prefixOneOf: [astral, wide] }] },
      confirmed: { [P + 'to']: ['a'], [P + 'flag']: [true], [P + 'tags']: [['y', 'x']] },
    });

  it('boolean, set and array parameters project onto env.canon with their canonical texts', () => {
    const r = run();
    expect(r.omega.verbs).toHaveLength(1);
    expect(r.omega.verbs[0]!.dims).toEqual([
      { kind: 'cat', path: P + 'half', values: [{ kind: 'other', value: '⊥' }] },
      { kind: 'cat', path: P + 'mode', values: [{ kind: 'other', value: '⊥' }] },
      {
        kind: 'cat',
        path: P + 'to',
        values: [
          { kind: 'exact', value: 'a' },
          { kind: 'exact', value: 'b' },
          { kind: 'prefix', value: wide },
          { kind: 'prefix', value: astral },
          { kind: 'other', value: '⊥' },
        ],
      },
      { kind: 'cat', path: 'env.canon.arr', values: [{ kind: 'exact', value: '[2,1]' }, { kind: 'other', value: '⊥' }] },
      {
        kind: 'cat',
        path: 'env.canon.flag',
        values: [
          { kind: 'exact', value: 'false' },
          { kind: 'exact', value: 'true' },
          { kind: 'other', value: '⊥' },
        ],
      },
      { kind: 'cat', path: 'env.canon.tags', values: [{ kind: 'exact', value: '["x","y"]' }, { kind: 'other', value: '⊥' }] },
    ]);
    expect(r.canonOf).toEqual({ 'env.canon.arr': P + 'arr', 'env.canon.flag': P + 'flag', 'env.canon.tags': P + 'tags' });
  });

  it('only silent parameters with a default set (confirmed or principal-neutral default) are pinned', () => {
    expect(run().defaults).toEqual([
      { verb: 'a.set', path: 'env.canon.arr', oneOf: ['[2,1]'] },
      { verb: 'a.set', path: 'env.canon.flag', oneOf: ['true'] },
      { verb: 'a.set', path: 'env.canon.tags', oneOf: ['["x","y"]'] },
    ]);
  });
});

describe('deriveOmegaFromSchema: per-verb literals', () => {
  it('each verb takes the slot literals of its own verb only', () => {
    const verbs: Verbs = [
      { verb: 'a.one', kind: 'write', params: { [P + 'to']: mat('string') } },
      { verb: 'b.two', kind: 'write', params: { [P + 'to']: mat('string') } },
    ];
    const r = deriveOmegaFromSchema({ schema: { verbs }, slots: { verbs: [], constraints: [{ verb: 'b.two', path: P + 'to', oneOf: ['z'] }] } });
    expect(r.omega.verbs.map((v) => [v.verb, v.dims])).toEqual([
      ['a.one', [{ kind: 'cat', path: P + 'to', values: [{ kind: 'other', value: '⊥' }] }]],
      ['b.two', [{ kind: 'cat', path: P + 'to', values: [{ kind: 'exact', value: 'z' }, { kind: 'other', value: '⊥' }] }]],
    ]);
  });
});
