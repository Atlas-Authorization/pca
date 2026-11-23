import { describe, expect, it } from 'vitest';
import { deriveOmega } from './omega';
import { deriveOmegaFromSchema } from './schema';

type Verbs = Parameters<typeof deriveOmegaFromSchema>[0]['schema']['verbs'];
type Param = Verbs[number]['params'][string];

const P = 'action.params.';
const mat = (type: Param['type'], extra: Partial<Param> = {}): Param => ({ type, semantic: 'thing.plain', sensitivity: 'material', ...extra });
const derive = (params: Record<string, Param>, extra: Partial<Parameters<typeof deriveOmegaFromSchema>[0]> = {}) =>
  deriveOmegaFromSchema({ schema: { verbs: [{ verb: 'a.pay', kind: 'write', params }] }, ...extra });
const dimOf = (r: ReturnType<typeof derive>, path: string) => r.omega.verbs[0]!.dims.find((d) => d.path === path);

describe('deriveOmegaFromSchema: integer bounds and cuts', () => {
  it('cuts keep the values on both ends of the domain and drop the ones outside', () => {
    const r = derive({ [P + 'n']: mat('integer', { min: 0, max: 10 }) }, { confirmed: { [P + 'n']: [-1, 0, 5, 10, 11] } });
    expect(dimOf(r, P + 'n')).toEqual({ kind: 'num', path: P + 'n', lo: 0, hi: 10, cuts: [0, 5, 10], dist: 'loguniform' });
  });
  it('the schema min and max set the domain when no override is given', () => {
    const r = derive({ [P + 'n']: mat('integer', { min: 3, max: 40 }) });
    expect(dimOf(r, P + 'n')).toEqual({ kind: 'num', path: P + 'n', lo: 3, hi: 40, cuts: [], dist: 'loguniform' });
  });
  it('an explicit domain wins over the schema min and max', () => {
    const r = derive({ [P + 'n']: mat('integer', { min: 3, max: 40 }) }, { domains: { [P + 'n']: { lo: 5, hi: 20 } } });
    expect(dimOf(r, P + 'n')).toMatchObject({ lo: 5, hi: 20 });
  });
  it('a domain bound of zero is a real bound, not a missing one', () => {
    const r = derive({ [P + 'n']: mat('integer', { min: 3, max: 40 }) }, { domains: { [P + 'n']: { lo: 0, hi: 0 } } });
    expect(dimOf(r, P + 'n')).toMatchObject({ lo: 0, hi: 0 });
  });
  it('cuts from a slot constraint on an integer parameter are carried into the dimension', () => {
    const slots = { verbs: ['a.pay'], constraints: [{ verb: 'a.pay', path: P + 'n', max: 5 }] };
    const base = deriveOmega({ policies: [], slots, extraVerbs: ['a.pay'] });
    const expected = base.verbs[0]!.dims.find((d) => d.path === P + 'n');
    expect(expected?.kind).toBe('num');
    const baseCuts = expected && expected.kind === 'num' ? expected.cuts : [];
    expect(baseCuts.length).toBeGreaterThan(0);
    const r = derive({ [P + 'n']: mat('integer') }, { slots, domains: { [P + 'n']: { lo: -1000, hi: 1000 } } });
    expect(dimOf(r, P + 'n')).toMatchObject({ kind: 'num', cuts: baseCuts });
  });
});

describe('deriveOmegaFromSchema: silent default values', () => {
  it('the one-of list of a silent string default is sorted and de-duplicated', () => {
    const r = derive({ [P + 's']: mat('string') }, { confirmed: { [P + 's']: ['b', 'a', 'b', 'c'] } });
    expect(r.defaults).toEqual([{ verb: 'a.pay', path: P + 's', oneOf: ['a', 'b', 'c'] }]);
  });
});
