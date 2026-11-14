import { describe, expect, it } from 'vitest';
import { hashCanonical, sha256, utf8 } from '@atlasauth/pca';
import { commitIntentMap, createLearner, emitIntentMap, type IntentMap, type Omega } from './index';

const secret = sha256(utf8('pca-intent-map-commit-kill/secret'));

// Two verbs of different arity. refund has cuts on both ends of its range; pay has a numeric and a categorical dimension.
const omega: Omega = {
  v: 1,
  approximate: [],
  verbs: [
    { verb: 'refund', reversibility: 'reversible', weight: 0.5, dims: [{ kind: 'num', path: 'action.params.units', lo: 0, hi: 9, cuts: [0, 3, 9], dist: 'uniform' }] },
    {
      verb: 'pay',
      reversibility: 'irreversible',
      weight: 0.5,
      dims: [
        { kind: 'num', path: 'action.params.amount', lo: 0, hi: 100, cuts: [20, 50, 80], dist: 'uniform' },
        { kind: 'cat', path: 'action.params.payee', values: [{ kind: 'exact', value: 'alice' }, { kind: 'exact', value: 'bob' }, { kind: 'other', value: '⊥' }] },
      ],
    },
  ],
};

function trainedMap(): IntentMap {
  const l = createLearner(omega, { eta: 0, tau: 1 });
  l.observe({ verb: 'pay', values: { 'action.params.amount': 30, 'action.params.payee': 'alice' } }, 1);
  l.observe({ verb: 'refund', values: { 'action.params.units': 5 } }, 1);
  return emitIntentMap(l);
}
const clone = (m: IntentMap): IntentMap => JSON.parse(JSON.stringify(m)) as IntentMap;
const leavesOf = (m: IntentMap) => commitIntentMap(m, secret).leaves;
const payVerb = (m: IntentMap) => m.omega.verbs.find((v) => v.verb === 'pay')!;
const refundCells = (m: IntentMap) => m.cells.filter((c) => c.verb === 'refund');

describe('commitIntentMap: the leaves', () => {
  it('one header per verb (sorted), with numeric and categorical dimensions in their committed shapes', () => {
    const headers = leavesOf(trainedMap()).filter((x) => x.kind === 'header');
    expect(headers.map((h) => h.leaf)).toEqual([
      {
        verb: 'pay',
        first: 2,
        cells: 21,
        dims: [
          { kind: 'num', path: 'action.params.amount', lo: 0, hi: 100, cuts: [20, 50, 80] },
          { kind: 'cat', path: 'action.params.payee', values: [{ kind: 'exact', value: 'alice' }, { kind: 'exact', value: 'bob' }, { kind: 'other', value: '⊥' }] },
        ],
      },
      { verb: 'refund', first: 23, cells: 5, dims: [{ kind: 'num', path: 'action.params.units', lo: 0, hi: 9, cuts: [0, 3, 9] }] },
    ]);
  });

  it('cuts on the boundary of the range are kept and cuts outside it are dropped (from the header and from the cell count)', () => {
    const m = clone(trainedMap());
    (payVerb(m).dims[0] as { cuts: number[] }).cuts = [-3, 20, 50, 80, 150];
    const headers = leavesOf(m).filter((x) => x.kind === 'header');
    expect(headers[0]!.leaf).toMatchObject({ verb: 'pay', cells: 21, dims: [{ cuts: [20, 50, 80] }, { kind: 'cat' }] });
    expect(headers[1]!.leaf).toMatchObject({ verb: 'refund', cells: 5, dims: [{ cuts: [0, 3, 9] }] });
  });

  it('the cells are committed in flat order, whatever the order they are listed in, with their own probability and grant flag', () => {
    const m = trainedMap();
    const reversed = { ...m, cells: [...m.cells].reverse() };
    const cells = leavesOf(reversed).filter((x) => x.kind === 'cell').map((x) => x.leaf as { verb: string; cell: number[]; p_ppm: number; in_grant: boolean });
    const key = (c: { verb: string; cell: number[] }) => `${c.verb}:${c.cell.join('.')}`;
    const flatOrder = [
      ...[0, 1, 2, 3, 4, 5, 6].flatMap((a) => [0, 1, 2].map((b) => `pay:${a}.${b}`)),
      ...[0, 1, 2, 3, 4].map((u) => `refund:${u}`),
    ];
    expect(cells.map(key)).toEqual(flatOrder);
    expect(cells).toHaveLength(26);
    expect(cells.find((c) => key(c) === 'pay:2.0')).toEqual({ verb: 'pay', cell: [2, 0], p_ppm: 1_000_000, in_grant: true });
    expect(cells.find((c) => key(c) === 'refund:3')).toEqual({ verb: 'refund', cell: [3], p_ppm: 1_000_000, in_grant: true });
    expect(cells.filter((c) => c.in_grant).map(key)).toEqual(['pay:2.0', 'refund:3']);
    for (const c of m.cells) expect(cells.find((x) => key(x) === key(c))).toEqual({ verb: c.verb, cell: c.cell, p_ppm: c.p_ppm, in_grant: c.in_grant });
  });

  it('the metrics leaf carries log2_vs_mbits only when the map has it; the learner leaf is the digest of the learner', () => {
    const m = trainedMap();
    const { log2_vs_mbits, ...rest } = m.metrics;
    expect(typeof log2_vs_mbits).toBe('number');
    const withKey = leavesOf(m);
    expect(withKey.find((x) => x.kind === 'metrics')!.leaf).toEqual({ ...rest, log2_vs_mbits });
    const without = leavesOf({ ...m, metrics: { ...m.metrics, log2_vs_mbits: null } });
    expect(without.find((x) => x.kind === 'metrics')!.leaf).toEqual(rest);
    expect(without.find((x) => x.kind === 'metrics')!.leaf).not.toHaveProperty('log2_vs_mbits');
    expect(withKey[withKey.length - 1]).toMatchObject({ kind: 'learner', leaf: { learner_digest: hashCanonical(m.learner) } });
    expect(withKey).toHaveLength(30);
  });
});

describe('commitIntentMap: refusals', () => {
  const refund = (m: IntentMap, cell: number[]) => ({ ...m, cells: m.cells.map((c) => (c === refundCells(m)[0] ? { ...c, cell } : c)) });
  it.each([[[5]], [[-1]], [[1.5]], [[Number.NaN]]])('a cell index %j outside 0..count-1 is refused', (cell) => {
    const m = trainedMap();
    expect(() => commitIntentMap(refund(m, cell), secret)).toThrow(new Error('commitIntentMap: cell index out of range for refund'));
  });
  it('a categorical dimension without values commits no cells for it and is refused by the committed header', () => {
    const m = clone(trainedMap());
    delete (payVerb(m).dims[1] as { values?: unknown }).values;
    m.cells = m.cells.filter((c) => c.verb !== 'pay');
    expect(() => commitIntentMap(m, secret)).toThrow(new Error('commitMap: header.cells must be a safe integer in [1, 1048576]'));
  });
});
