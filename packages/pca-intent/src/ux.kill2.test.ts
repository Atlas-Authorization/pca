import { describe, expect, it } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';
import { parseCardAnswer, questionCard, type QuestionCard } from './ux';
import type { Omega } from './omega';

const AMT = 'action.params.amount';
const RES = 'action.resource';

const omega: Omega = {
  v: 1,
  approximate: [],
  verbs: [
    { verb: 'x.first', reversibility: 'reversible', weight: 0.5, dims: [] },
    {
      verb: 'x.second',
      reversibility: 'irreversible',
      weight: 0.5,
      dims: [
        { kind: 'num', path: AMT, lo: 0, hi: 10, cuts: [5], dist: 'uniform' },
        { kind: 'cat', path: RES, values: [{ kind: 'exact', value: '/a' }, { kind: 'prefix', value: '/p/' }, { kind: 'other', value: '⊥' }] },
      ],
    },
  ],
};

describe('questionCard', () => {
  it('picks the verb by name (not the first verb) and renders one fact per dimension', () => {
    const c = questionCard(omega, { verb: 'x.second', cell: [1, 0] });
    expect(c.verb).toBe('x.second');
    expect(c.reversibility).toBe('irreversible');
    expect(c.facts).toEqual([
      { path: AMT, label: 'amount', text: 'exactly 5' },
      { path: RES, label: 'resource', text: '"/a"' },
    ]);
    expect(c.partial).toEqual([
      { path: AMT, kind: 'num', lo: 5, hi: 5 },
      { path: RES, kind: 'cat', options: ['/a'] },
    ]);
  });
  it('renders a multi-value numeric cell with its representative, a prefix value and the other value', () => {
    const a = questionCard(omega, { verb: 'x.second', cell: [0, 1] });
    expect(a.facts[0]!.text).toBe('any value from 0 to 4 (for example 4)');
    expect(a.facts[1]!.text).toBe('anything under "/p/" not named elsewhere');
    const b = questionCard(omega, { verb: 'x.second', cell: [2, 2] });
    expect(b.facts[0]!.text).toBe('any value from 6 to 10 (for example 6)');
    expect(b.facts[1]!.text).toBe('any value not named anywhere in the grant or your request');
  });
  it('refuses an unknown verb with the exact message', () => {
    expect(() => questionCard(omega, { verb: 'nope', cell: [] })).toThrow(new Error('questionCard: no verb nope'));
  });
});

const card: QuestionCard = {
  v: 1,
  verb: 'x.second',
  cell: [1, 0],
  sentence: 's',
  facts: [],
  reversibility: 'irreversible',
  answers: ['yes', 'no', 'partly'],
  partial: [
    { path: AMT, kind: 'num', lo: 2, hi: 8 },
    { path: RES, kind: 'cat', options: ['/a'] },
  ],
  digest: hashCanonical({ x: 1 }),
};
const parse = (i: Parameters<typeof parseCardAnswer>[1]) => parseCardAnswer(card, i);
const err = (error: string) => ({ ok: false, error });
const AMT_SLOT_ERR = (k: string, a: number, b: number) => err(`${k} must be an integer in [${a}, ${b}]`);

describe('parseCardAnswer: yes / no', () => {
  it('maps yes to 1 and no to 0', () => {
    expect(parse({ answer: 'yes' })).toEqual({ ok: true, answer: 1 });
    expect(parse({ answer: 'no' })).toEqual({ ok: true, answer: 0 });
  });
});

describe('parseCardAnswer: newField', () => {
  it('refuses a field outside the allowed shapes', () => {
    for (const f of ['env.hour', 'action.params.', 'action.params.Bad', 'action.params.1x', 'xaction.resource', 'action.resourcex', 'action.params.a.b']) {
      expect(parse({ answer: 'partly', newField: f, notFor: ['x'] })).toEqual(err(`unknown field ${f}`));
    }
  });
  it('accepts action.resource and action.params.<snake_case> shapes', () => {
    for (const f of ['action.params.a_1', 'action.params._x', 'action.params.z9']) {
      expect(parse({ answer: 'partly', newField: f, notFor: ['x'] }).ok).toBe(true);
    }
  });
  it('refuses a field already on the card', () => {
    expect(parse({ answer: 'partly', newField: RES, notFor: ['x'] })).toEqual(err(`${RES} is already on the card; answer partly for it directly`));
  });
  it('refuses an empty value list, after dropping empty and non-string entries', () => {
    const e = err('name at least one value');
    expect(parse({ answer: 'partly', newField: 'action.params.ch', notFor: [] })).toEqual(e);
    expect(parse({ answer: 'partly', newField: 'action.params.ch', notFor: ['', 5 as unknown as string] })).toEqual(e);
    // a non-string with a positive length (an array) is still dropped
    expect(parse({ answer: 'partly', newField: 'action.params.ch', notFor: [['x'] as unknown as string] })).toEqual(e);
  });
  it('builds the new categorical dimension with de-duplicated values, then the other cell', () => {
    expect(parse({ answer: 'partly', newField: 'action.params.ch', notFor: ['#a', '#b', '#a', '', 7 as unknown as string] })).toEqual({
      ok: true,
      answer: {
        kind: 'partial',
        path: 'action.params.ch',
        newDim: { kind: 'cat', path: 'action.params.ch', values: [{ kind: 'exact', value: '#a' }, { kind: 'exact', value: '#b' }, { kind: 'other', value: '⊥' }] },
        parts: [{ values: ['#a', '#b'], y: 0 }, { other: true, y: 1 }],
      },
    });
  });
  it('a single-character value is kept', () => {
    const r = parse({ answer: 'partly', newField: 'action.params.ch', notFor: ['x'] });
    expect((r as { answer: { parts: unknown[] } }).answer.parts[0]).toEqual({ values: ['x'], y: 0 });
  });
});

describe('parseCardAnswer: field lookup', () => {
  it('refuses a path the card does not have, and picks the slot by path', () => {
    expect(parse({ answer: 'partly', path: 'env.hour', upTo: 3 })).toEqual(err('the card has no field env.hour'));
    expect(parse({ answer: 'partly', path: RES, notFor: ['/a'] }).ok).toBe(true);
    expect(parse({ answer: 'partly', path: AMT, upTo: 3 }).ok).toBe(true);
  });
});

describe('parseCardAnswer: numeric upTo', () => {
  it('accepts lo..hi-1 and builds yes-below / no-above parts', () => {
    expect(parse({ answer: 'partly', path: AMT, upTo: 2 })).toEqual({
      ok: true,
      answer: { kind: 'partial', path: AMT, cuts: [2], parts: [{ lo: 2, hi: 2, y: 1 }, { lo: 3, hi: 8, y: 0 }] },
    });
    expect(parse({ answer: 'partly', path: AMT, upTo: 7 })).toEqual({
      ok: true,
      answer: { kind: 'partial', path: AMT, cuts: [7], parts: [{ lo: 2, hi: 7, y: 1 }, { lo: 8, hi: 8, y: 0 }] },
    });
  });
  it('refuses out of range, hi, non-integers, negative zero', () => {
    const e = AMT_SLOT_ERR('upTo', 2, 7);
    for (const x of [1, 8, 9, 3.5, Number.NaN, 0]) expect(parse({ answer: 'partly', path: AMT, upTo: x })).toEqual(e);
  });
});

describe('parseCardAnswer: numeric from', () => {
  it('accepts lo+1..hi and builds no-below / yes-from parts', () => {
    expect(parse({ answer: 'partly', path: AMT, from: 3 })).toEqual({
      ok: true,
      answer: { kind: 'partial', path: AMT, cuts: [3], parts: [{ lo: 2, hi: 2, y: 0 }, { lo: 3, hi: 8, y: 1 }] },
    });
    expect(parse({ answer: 'partly', path: AMT, from: 8 })).toEqual({
      ok: true,
      answer: { kind: 'partial', path: AMT, cuts: [8], parts: [{ lo: 2, hi: 7, y: 0 }, { lo: 8, hi: 8, y: 1 }] },
    });
  });
  it('refuses lo, out of range, non-integers', () => {
    const e = AMT_SLOT_ERR('from', 3, 8);
    for (const x of [2, 1, 9, 4.5, Number.NaN]) expect(parse({ answer: 'partly', path: AMT, from: x })).toEqual(e);
  });
});

describe('parseCardAnswer: numeric except', () => {
  it('sorts numerically, de-duplicates, and puts the no-parts before the covering yes', () => {
    expect(parse({ answer: 'partly', path: AMT, except: [8, 2, 5, 5, 3] })).toEqual({
      ok: true,
      answer: {
        kind: 'partial',
        path: AMT,
        cuts: [2, 3, 5, 8],
        parts: [{ lo: 2, hi: 2, y: 0 }, { lo: 3, hi: 3, y: 0 }, { lo: 5, hi: 5, y: 0 }, { lo: 8, hi: 8, y: 0 }, { lo: 2, hi: 8, y: 1 }],
      },
    });
    expect(parse({ answer: 'partly', path: AMT, except: [10, 9, 2] }).ok).toBe(false);
  });
  it('sorts by value, not lexicographically', () => {
    const wide: QuestionCard = { ...card, partial: [{ path: AMT, kind: 'num', lo: 2, hi: 30 }] };
    const r = parseCardAnswer(wide, { answer: 'partly', path: AMT, except: [10, 9, 2, 21] });
    expect((r as { answer: { cuts: number[] } }).answer.cuts).toEqual([2, 9, 10, 21]);
  });
  it('refuses empty, any out-of-range member (inclusive bounds accepted), non-integers', () => {
    const e = err('except values must be integers in [2, 8]');
    expect(parse({ answer: 'partly', path: AMT, except: [] })).toEqual(e);
    expect(parse({ answer: 'partly', path: AMT, except: [3, 9] })).toEqual(e);
    expect(parse({ answer: 'partly', path: AMT, except: [1, 3] })).toEqual(e);
    expect(parse({ answer: 'partly', path: AMT, except: [3, 2.5] })).toEqual(e);
    expect(parse({ answer: 'partly', path: AMT, except: [2, 8] }).ok).toBe(true);
  });
  it('a numeric partly answer without upTo, from or except is refused', () => {
    expect(parse({ answer: 'partly', path: AMT } as never)).toEqual(err('a numeric partly answer needs upTo, from or except'));
  });
});

describe('parseCardAnswer: categorical notFor', () => {
  it('needs notFor', () => {
    expect(parse({ answer: 'partly', path: RES, upTo: 1 } as never)).toEqual(err('a categorical partly answer needs notFor'));
  });
  it('refuses an empty list after filtering empty and non-string entries', () => {
    const e = err('name at least one value');
    expect(parse({ answer: 'partly', path: RES, notFor: [] })).toEqual(e);
    expect(parse({ answer: 'partly', path: RES, notFor: ['', 3 as unknown as string] })).toEqual(e);
    expect(parse({ answer: 'partly', path: RES, notFor: [['/a'] as unknown as string] })).toEqual(e);
  });
  it('builds the partial with de-duplicated values and an other part', () => {
    expect(parse({ answer: 'partly', path: RES, notFor: ['/a', '/b', '/a', '', 3 as unknown as string] })).toEqual({
      ok: true,
      answer: { kind: 'partial', path: RES, values: ['/a', '/b'], parts: [{ values: ['/a', '/b'], y: 0 }, { other: true, y: 1 }] },
    });
  });
});
