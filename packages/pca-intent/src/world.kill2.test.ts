import { describe, expect, it } from 'vitest';
import { OTHER, classifierDim, excessDim, liftOutcome, provenanceDim, withDims, worldDim, type NumDim, type Omega, type Outcome, type VerbSpace } from './index';

describe('worldDim and excessDim', () => {
  it('keeps only the cuts inside [lo, hi] (both ends included), sorted numerically and de-duplicated', () => {
    expect(worldDim('f', { lo: 10, hi: 100, cuts: [100, 50, 5, 10, 50, 101] }).cuts).toEqual([10, 50, 100]);
  });
  it('no cuts means none, and the distribution defaults to uniform', () => {
    expect(worldDim('f', { lo: 0, hi: 9 })).toEqual({ kind: 'num', path: 'env.world.f', lo: 0, hi: 9, cuts: [], dist: 'uniform' });
    expect(worldDim('f', { lo: 0, hi: 9, dist: 'loguniform' }).dist).toBe('loguniform');
  });
  it('the excess dimension is loguniform with cuts at 0 and each slack', () => {
    expect(excessDim('e', 1000)).toEqual({ kind: 'num', path: 'env.world.e', lo: 0, hi: 1000, cuts: [0], dist: 'loguniform' });
    expect(excessDim('e', 1000, [50, 10]).cuts).toEqual([0, 10, 50]);
  });
});

describe('provenanceDim and classifierDim', () => {
  it('provenance cells are exact first_party, exact trusted, then OTHER, under env.prov.<path>', () => {
    expect(provenanceDim('action.params.payee')).toEqual({
      kind: 'cat',
      path: 'env.prov.action.params.payee',
      values: [
        { kind: 'exact', value: 'first_party' },
        { kind: 'exact', value: 'trusted' },
        { kind: 'other', value: OTHER },
      ],
    });
  });
});

describe('withDims', () => {
  const dimA: NumDim = { kind: 'num', path: 'action.params.a', lo: 0, hi: 9, cuts: [], dist: 'uniform' };
  const mk = (verb: string): VerbSpace => ({ verb, reversibility: 'reversible', weight: 0.5, dims: [dimA] });
  const omega: Omega = { v: 1, verbs: [mk('x.one'), mk('x.two')], approximate: [] };

  it('adds the dims to the named verb only, kept sorted by path; other verbs are copied unchanged', () => {
    const out = withDims(omega, 'x.two', [classifierDim('c', ['y']), worldDim('w', { lo: 0, hi: 5 }), provenanceDim('action.params.z')]);
    expect(out.verbs[0]).toEqual(mk('x.one'));
    expect(out.verbs[0]!.dims).not.toBe(omega.verbs[0]!.dims);
    expect(out.verbs[1]!.dims.map((d) => d.path)).toEqual(['action.params.a', 'env.class.c', 'env.prov.action.params.z', 'env.world.w']);
    expect(omega.verbs[1]!.dims.length).toBe(1);
  });
  it('sorts many dims by path, whatever order they are given in', () => {
    const dims = Array.from({ length: 70 }, (_, i) => worldDim(`n${69 - i}`, { lo: 0, hi: 1 }));
    const out = withDims(omega, 'x.one', dims);
    const paths = out.verbs[0]!.dims.map((d) => d.path);
    expect(paths).toEqual([...paths].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));
    expect(paths.length).toBe(71);
  });
  it('dims with equal paths keep their given order (stable)', () => {
    const out = withDims(omega, 'x.one', [worldDim('w', { lo: 0, hi: 1 }), worldDim('w', { lo: 0, hi: 2 })]);
    expect(out.verbs[0]!.dims.slice(1).map((d) => (d as NumDim).hi)).toEqual([1, 2]);
  });
  it('refuses a duplicate path and an unknown verb with their messages', () => {
    expect(() => withDims(omega, 'x.one', [dimA])).toThrow(new Error('withDims: x.one already has a dimension action.params.a'));
    expect(() => withDims(omega, 'x.three', [worldDim('w', { lo: 0, hi: 1 })])).toThrow(new Error('withDims: no verb x.three in Ω'));
  });
});

describe('liftOutcome', () => {
  const o: Outcome = { verb: 'v', values: { 'action.params.amount': 5 } };

  it('world: numbers and strings are lifted, other types and missing names are not', () => {
    const paths = ['env.world.n', 'env.world.s', 'env.world.b', 'env.world.o', 'env.world.missing'];
    const env = { world: { n: 0, s: 'abc', b: true, o: { x: 1 } } };
    expect(liftOutcome(o, env, paths).values).toEqual({ 'action.params.amount': 5, 'env.world.n': 0, 'env.world.s': 'abc' });
    expect(Object.keys(liftOutcome(o, env, paths).values).sort()).toEqual(['action.params.amount', 'env.world.n', 'env.world.s']);
  });

  it('class: only strings are lifted, and only for paths under env.class.', () => {
    const env = { class: { tone: 'calm', n: 5, nothing: undefined } };
    const out = liftOutcome(o, env, ['env.class.tone', 'env.class.n', 'env.class.nothing', 'env.class.absent']);
    expect(Object.keys(out.values).sort()).toEqual(['action.params.amount', 'env.class.tone']);
    expect(out.values['env.class.tone']).toBe('calm');
  });

  it('a path outside every prefix is ignored even when its tail names an env.class label', () => {
    const env = { class: { abc: 'hit' }, world: { abc: 1 }, prov: { abc: 'trusted' } };
    const out = liftOutcome(o, env, ['xxxxxxxxxxabc']);
    expect(out.values).toEqual({ 'action.params.amount': 5 });
  });

  it('prov: a label is read through nested own objects; null, strings and inherited labels give agent', () => {
    const inherited = Object.create({ payee: 'trusted' }) as Record<string, unknown>;
    const env = { prov: { a: { b: 'trusted' }, nul: null, str: 'first_party', inh: { params: inherited } } };
    const paths = ['env.prov.a.b', 'env.prov.nul.x', 'env.prov.str.0', 'env.prov.inh.params.payee', 'env.prov.a.missing.deeper'];
    expect(liftOutcome(o, env, paths).values).toEqual({
      'action.params.amount': 5,
      'env.prov.a.b': 'trusted',
      'env.prov.nul.x': 'agent',
      'env.prov.str.0': 'agent',
      'env.prov.inh.params.payee': 'agent',
      'env.prov.a.missing.deeper': 'agent',
    });
  });

  it('class labels are read from own properties only', () => {
    const inherited = Object.create({ tone: 'calm' }) as Record<string, unknown>;
    expect(Object.keys(liftOutcome(o, { class: inherited }, ['env.class.tone']).values)).toEqual(['action.params.amount']);
  });
});
