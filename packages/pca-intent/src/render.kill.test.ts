import { describe, expect, it } from 'vitest';
import type { Caveat, Condition, Predicate } from '@atlasauth/pca';
import { buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import {
  backTranslationDiff,
  claimDiff,
  claimsOf,
  labelOf,
  renderAction,
  renderCaveat,
  renderCondition,
  renderGrant,
  renderQuestion,
  type CatDim,
  type NumDim,
  type Omega,
  type PolicyInput,
  type VerbSpace,
} from './index';

const AMT = 'action.params.amount';
const RCP = 'action.params.recipient';

const cat = buildCatalog([
  defineAction({ connector: 'acme', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.5, description: 'Refund v1.2 charge.' }),
  defineAction({ connector: 'acme', action: 'wipe', reversibility: 'irreversible', blastRadius: 0.9, description: '\nWipe data.' }),
]);

describe('labelOf', () => {
  it('names the resource path, drops the path prefix and turns underscores into spaces', () => {
    expect(labelOf('action.resource')).toBe('resource');
    expect(labelOf('')).toBe('');
    expect(labelOf('action.params.max_amount_total')).toBe('max amount total');
  });
});

describe('renderCondition', () => {
  const F = 'action.params.max_amount';
  const leaf = (op: string, extra: Record<string, unknown> = { value: 5 }) => ({ field: F, op, ...extra }) as unknown as Condition;

  it.each([
    ['eq', 'is 5'],
    ['ne', 'is not 5'],
    ['in', 'is one of 5'],
    ['nin', 'is none of 5'],
    ['lt', 'is less than 5'],
    ['lte', 'is at most 5'],
    ['gt', 'is more than 5'],
    ['gte', 'is at least 5'],
    ['prefix', 'starts with 5'],
    ['like', 'matches the pattern 5'],
    ['matches', 'matches the regular expression 5'],
    ['is_a', 'is of type 5'],
    ['member_of', 'belongs to 5'],
  ])('renders %s', (op, tail) => {
    expect(renderCondition(leaf(op))).toBe(`the max amount ${tail}`);
  });

  it('renders exists as present unless the value is exactly false', () => {
    expect(renderCondition(leaf('exists', { value: false }))).toBe('the max amount is absent');
    expect(renderCondition(leaf('exists', { value: true }))).toBe('the max amount is present');
    expect(renderCondition(leaf('exists', {}))).toBe('the max amount is present');
  });

  it('names an unrecognised operator and says it is not understood', () => {
    expect(renderCondition(leaf('bogus'))).toBe('the max amount has an unrecognised test "bogus" (not understood)');
  });

  it('prefers a reference operand over the literal', () => {
    expect(renderCondition(leaf('eq', { ref: 'env.limit_total', value: 9 }))).toBe('the max amount is the limit total');
  });

  it('quotes strings, joins arrays element by element and prints other values plainly', () => {
    expect(renderCondition(leaf('eq', { value: 'x' }))).toBe('the max amount is "x"');
    expect(renderCondition(leaf('in', { value: ['a', 1, 'b'] }))).toBe('the max amount is one of "a", 1, "b"');
    expect(renderCondition(leaf('eq', { value: true }))).toBe('the max amount is true');
  });

  it('renders groups with parenthesised members', () => {
    const a = leaf('lte', { value: 1 });
    const b = leaf('gte', { value: 2 });
    expect(renderCondition({ all_of: [a, b] })).toBe('all of: (the max amount is at most 1) and (the max amount is at least 2)');
    expect(renderCondition({ any_of: [a, b] })).toBe('either (the max amount is at most 1) or (the max amount is at least 2)');
    expect(renderCondition({ not: a })).toBe('it is not the case that the max amount is at most 1');
  });

  it('renders a group without members as an empty list', () => {
    expect(renderCondition({ all_of: undefined } as unknown as Condition)).toBe('all of: ');
    expect(renderCondition({ any_of: undefined } as unknown as Condition)).toBe('either ');
    expect(renderCondition({ all_of: [] })).toBe('all of: ');
    expect(renderCondition({ any_of: [] })).toBe('either ');
  });

  it('flags anything that is neither a group nor a leaf as unreadable', () => {
    const msg = 'an unreadable condition (not understood)';
    expect(renderCondition(null as unknown as Condition)).toBe(msg);
    expect(renderCondition(5 as unknown as Condition)).toBe(msg);
    expect(renderCondition({} as unknown as Condition)).toBe(msg);
    expect(renderCondition({ field: 5, op: 'eq' } as unknown as Condition)).toBe(msg);
  });
});

describe('renderCaveat', () => {
  it('renders every known caveat type', () => {
    expect(renderCaveat({ type: 'expires', at: 86_400_000 })).toBe('The grant expires at 1970-01-02T00:00:00.000Z.');
    expect(renderCaveat({ type: 'not_before', at: 1_000 })).toBe('The grant is not valid before 1970-01-01T00:00:01.000Z.');
    expect(renderCaveat({ type: 'rate', max: 5, per_secs: 60 })).toBe('At most 5 actions in any 60 seconds.');
    expect(renderCaveat({ type: 'max_blast_radius', max: 0.5 })).toBe('No action whose blast radius exceeds 0.5 (on a 0–1 scale).');
    expect(renderCaveat({ type: 'reversibility_max', class: 'rate_limited' })).toBe('Nothing more severe than "rate-limited" (reversible < rate-limited < irreversible).');
    expect(renderCaveat({ type: 'delegation_depth', max: 2 })).toBe('It may be re-delegated at most 2 level(s) deep.');
    expect(renderCaveat({ type: 'budget_alloc', limit: 7 })).toBe('A trust-budget allocation of 7 is carried for sub-delegation.');
  });

  it('flags an unknown type and survives a missing caveat', () => {
    const tail = '(NOT UNDERSTOOD: do not rely on this grant until it is explained).';
    expect(renderCaveat({ type: 'mystery' })).toBe(`An unrecognised constraint of type "mystery" ${tail}`);
    expect(renderCaveat(undefined as unknown as Caveat)).toBe(`An unrecognised constraint of type "undefined" ${tail}`);
    expect(renderCaveat(null as unknown as Caveat)).toBe(`An unrecognised constraint of type "undefined" ${tail}`);
  });
});

describe('renderGrant', () => {
  it('renders an empty grant', () => {
    expect(renderGrant({ predicates: [], caveats: [] }, cat)).toBe('This grant allows nothing.');
  });

  it('renders numbered predicates, every resource matcher form and the limits block', () => {
    const p: PolicyInput = {
      predicates: [
        {
          verb: 'acme.refund',
          where: [
            { field: AMT, op: 'lte', value: 200 },
            { field: RCP, op: 'in', value: ['bob', 'al'] },
          ],
        },
        { verb: ['acme.wipe', 'nope.x'], resource: 'files/*' },
        { verb: '*', resource: 're:^a.*' },
      ],
      caveats: [{ type: 'rate', max: 5, per_secs: 60 }, { type: 'delegation_depth', max: 1 }],
    };
    expect(renderGrant(p, cat)).toBe(
      [
        'The agent may do the following, and nothing else:',
        '1. refund v1.2 charge [acme.refund, rate-limited], on any resource, only when the amount is at most 200, and the recipient is one of "bob", "al".',
        '2. \nWipe data [acme.wipe, irreversible]; or "nope.x" [uncatalogued: treated as irreversible], on resources under "files/".',
        '3. ANY action of any connector, on resources matching the regular expression "^a.*".',
        'Limits that apply to everything above:',
        '- At most 5 actions in any 60 seconds.',
        '- It may be re-delegated at most 1 level(s) deep.',
      ].join('\n'),
    );
  });

  it('omits the limits block when there are no caveats', () => {
    expect(renderGrant({ predicates: [{ verb: 'acme.refund', resource: '*' }] }, cat)).toBe(
      'The agent may do the following, and nothing else:\n1. refund v1.2 charge [acme.refund, rate-limited], on any resource.',
    );
  });

  it('renders exact and unreadable resource matchers', () => {
    const one = (resource: unknown) => renderGrant({ predicates: [{ verb: 'acme.refund', resource: resource as string }], caveats: [] }, cat).split('\n')[1];
    expect(one('x/y')).toBe('1. refund v1.2 charge [acme.refund, rate-limited], only on resource "x/y".');
    expect(one(5)).toBe('1. refund v1.2 charge [acme.refund, rate-limited], on an unreadable resource matcher (not understood).');
    expect(one('re:a*')).toBe('1. refund v1.2 charge [acme.refund, rate-limited], on resources matching the regular expression "a*".');
    expect(one('abc*')).toBe('1. refund v1.2 charge [acme.refund, rate-limited], on resources under "abc".');
  });
});

// ---- Omega-based surfaces --------------------------------------------------------------------------------------

const numDim: NumDim = { kind: 'num', path: AMT, lo: 0, hi: 100, cuts: [10, 20, 30, 40, 50], dist: 'uniform' };
const vsV: VerbSpace = { verb: 'v', reversibility: 'reversible', weight: 1, dims: [numDim] };
const omegaV: Omega = { v: 1, approximate: [], verbs: [vsV] };

const pol = (min?: number, max?: number): PolicyInput => {
  const where: Condition[] = [];
  if (min !== undefined) where.push({ field: AMT, op: 'gte', value: min });
  if (max !== undefined) where.push({ field: AMT, op: 'lte', value: max });
  return { predicates: [{ verb: 'v', resource: '*', ...(where.length ? { where } : {}) }], caveats: [] };
};
const none: PolicyInput = { predicates: [], caveats: [] };

const catA: CatDim = { kind: 'cat', path: RCP, values: [{ kind: 'exact', value: 'bob' }, { kind: 'prefix', value: 'al' }, { kind: 'other', value: '⊥' }] };
const numB: NumDim = { kind: 'num', path: AMT, lo: 0, hi: 100, cuts: [50], dist: 'uniform' };
// the cat dimension varies slowest in `w`, fastest in `u`
const vsW: VerbSpace = { verb: 'w', reversibility: 'reversible', weight: 0.5, dims: [catA, numB] };
const vsU: VerbSpace = { verb: 'u', reversibility: 'reversible', weight: 0.5, dims: [numB, catA] };
const omegaWU: Omega = { v: 1, approximate: [], verbs: [vsW, vsU] };
const omegaW: Omega = { v: 1, approximate: [], verbs: [vsW] };

/** Admits (bob, amount >= 51) and (al*, amount <= 49) only: not a product of its projections. */
const nonBox = (verb: string): Predicate[] => [
  { verb, resource: '*', where: [{ field: RCP, op: 'eq', value: 'bob' }, { field: AMT, op: 'gte', value: 51 }] },
  { verb, resource: '*', where: [{ field: RCP, op: 'prefix', value: 'al' }, { field: AMT, op: 'lte', value: 49 }] },
];
const box = (verb: string): Predicate[] => [
  { verb, resource: '*', where: [{ any_of: [{ field: RCP, op: 'eq', value: 'bob' }, { field: RCP, op: 'prefix', value: 'al' }] }] },
];
const NB: PolicyInput = { predicates: [...nonBox('w'), ...nonBox('u')], caveats: [] };
const BX: PolicyInput = { predicates: [...box('w'), ...box('u')], caveats: [] };

describe('claimsOf', () => {
  it('summarises a bounded numeric dimension as the range of its accepted cells', () => {
    expect(claimsOf(pol(10, 30), omegaV)).toEqual([{ verb: 'v', allowed: true, boxShaped: true, dims: [{ path: AMT, any: false, range: [10, 30] }] }]);
  });

  it('marks a dimension that does not restrict the verb as any', () => {
    expect(claimsOf(pol(), omegaV)).toEqual([{ verb: 'v', allowed: true, boxShaped: true, dims: [{ path: AMT, any: true, range: [0, 100] }] }]);
  });

  it('reports a verb that nothing admits', () => {
    expect(claimsOf(none, omegaV)).toEqual([{ verb: 'v', allowed: false, boxShaped: true, dims: [{ path: AMT, any: false }] }]);
  });

  it('keeps projections ordered however the cells are admitted and flags a non-box region', () => {
    expect(claimsOf(NB, omegaWU)).toEqual([
      { verb: 'w', allowed: true, boxShaped: false, dims: [{ path: RCP, any: false, values: ['bob', 'al*'] }, { path: AMT, any: false, range: [0, 100] }] },
      { verb: 'u', allowed: true, boxShaped: false, dims: [{ path: AMT, any: false, range: [0, 100] }, { path: RCP, any: false, values: ['bob', 'al*'] }] },
    ]);
  });

  it('reports a product region as box-shaped, with prefix cells starred', () => {
    expect(claimsOf(BX, omegaWU)).toEqual([
      { verb: 'w', allowed: true, boxShaped: true, dims: [{ path: RCP, any: false, values: ['bob', 'al*'] }, { path: AMT, any: true, range: [0, 100] }] },
      { verb: 'u', allowed: true, boxShaped: true, dims: [{ path: AMT, any: true, range: [0, 100] }, { path: RCP, any: false, values: ['bob', 'al*'] }] },
    ]);
  });
});

describe('claimDiff: kinds and wording', () => {
  const dim = (g: PolicyInput, s: PolicyInput) => claimDiff(g, s, omegaV);
  const one = (kind: string, x: string, y: string) => [{ verb: 'v', kind, path: AMT, text: `For v, the first reading allows amount ${x}; the second reading allows ${y}.` }];

  it('is empty for equal readings and for two readings that both allow nothing', () => {
    expect(dim(pol(10, 30), pol(10, 30))).toEqual([]);
    expect(dim(none, none)).toEqual([]);
  });

  it('names a verb only the first or only the second reading allows', () => {
    expect(dim(pol(), none)).toEqual([{ verb: 'v', kind: 'extra-verb', text: 'the first reading allows v; the second reading does not.' }]);
    expect(dim(none, pol())).toEqual([{ verb: 'v', kind: 'missing-verb', text: 'the second reading allows v; the first reading does not.' }]);
  });

  it('uses the given names in every sentence', () => {
    const names: [string, string] = ['A', 'B'];
    expect(claimDiff(pol(), none, omegaV, names)).toEqual([{ verb: 'v', kind: 'extra-verb', text: 'A allows v; B does not.' }]);
    expect(claimDiff(none, pol(), omegaV, names)).toEqual([{ verb: 'v', kind: 'missing-verb', text: 'B allows v; A does not.' }]);
    expect(claimDiff(pol(undefined, 50), pol(10, 30), omegaV, names)).toEqual([{ verb: 'v', kind: 'looser', path: AMT, text: 'For v, A allows amount 0 to 50; B allows 10 to 30.' }]);
    expect(claimDiff(NB, BX, omegaW, names)[0]).toEqual({ verb: 'w', kind: 'shape', text: 'A and B describe w with differently shaped rules.' });
  });

  it('classifies numeric ranges as looser, tighter or different at every boundary', () => {
    expect(dim(pol(undefined, 50), pol(10, 30))).toEqual(one('looser', '0 to 50', '10 to 30'));
    expect(dim(pol(undefined, 50), pol(undefined, 30))).toEqual(one('looser', '0 to 50', '0 to 30'));
    expect(dim(pol(undefined, 50), pol(10, 50))).toEqual(one('looser', '0 to 50', '10 to 50'));
    expect(dim(pol(10, 30), pol(undefined, 50))).toEqual(one('tighter', '10 to 30', '0 to 50'));
    expect(dim(pol(undefined, 30), pol(undefined, 50))).toEqual(one('tighter', '0 to 30', '0 to 50'));
    expect(dim(pol(10, 50), pol(undefined, 50))).toEqual(one('tighter', '10 to 50', '0 to 50'));
    expect(dim(pol(undefined, 30), pol(10, 50))).toEqual(one('different', '0 to 30', '10 to 50'));
    expect(dim(pol(10, 50), pol(undefined, 30))).toEqual(one('different', '10 to 50', '0 to 30'));
  });

  it('prints an unrestricted dimension as any value', () => {
    expect(dim(pol(), pol(10, 30))).toEqual(one('looser', 'any value', '10 to 30'));
    expect(dim(pol(10, 30), pol())).toEqual(one('tighter', '10 to 30', 'any value'));
  });

  it('flags a differently shaped region from either side, but not two non-box regions', () => {
    const shape = { verb: 'w', kind: 'shape', text: 'the first reading and the second reading describe w with differently shaped rules.' };
    expect(claimDiff(NB, BX, omegaW)).toEqual([
      shape,
      { verb: 'w', kind: 'looser', path: AMT, text: 'For w, the first reading allows amount 0 to 100; the second reading allows any value.' },
    ]);
    expect(claimDiff(BX, NB, omegaW)).toEqual([
      shape,
      { verb: 'w', kind: 'looser', path: AMT, text: 'For w, the first reading allows amount any value; the second reading allows 0 to 100.' },
    ]);
    expect(claimDiff(NB, NB, omegaW)).toEqual([]);
    expect(claimDiff(BX, BX, omegaW)).toEqual([]);
  });
});

describe('claimDiff: categorical dimensions', () => {
  const catOmega: Omega = {
    v: 1,
    approximate: [],
    verbs: [{ verb: 'c', reversibility: 'reversible', weight: 1, dims: [{ kind: 'cat', path: RCP, values: [{ kind: 'exact', value: 'a' }, { kind: 'exact', value: 'b' }, { kind: 'exact', value: 'c' }, { kind: 'other', value: '⊥' }] }] }],
  };
  const catPol = (list?: string[]): PolicyInput => ({ predicates: [{ verb: 'c', resource: '*', ...(list ? { where: [{ field: RCP, op: 'in' as const, value: list }] } : {}) }], caveats: [] });
  const one = (kind: string, x: string, y: string) => [{ verb: 'c', kind, path: RCP, text: `For c, the first reading allows recipient ${x}; the second reading allows ${y}.` }];
  const d = (g: PolicyInput, s: PolicyInput) => claimDiff(g, s, catOmega);

  it('classifies value sets by containment', () => {
    expect(d(catPol(['a', 'b']), catPol(['a']))).toEqual(one('looser', 'a, b', 'a'));
    expect(d(catPol(['a']), catPol(['a', 'b']))).toEqual(one('tighter', 'a', 'a, b'));
    expect(d(catPol(['a', 'b']), catPol(['b', 'c']))).toEqual(one('different', 'a, b', 'b, c'));
    expect(d(catPol(['b', 'c']), catPol(['a', 'b']))).toEqual(one('different', 'b, c', 'a, b'));
  });

  it('prints a dimension that admits every value as any value', () => {
    expect(d(catPol(), catPol(['a']))).toEqual(one('looser', 'any value', 'a'));
    expect(d(catPol(['a']), catPol())).toEqual(one('tighter', 'a', 'any value'));
  });
});

describe('backTranslationDiff', () => {
  it('words a dimension difference from the principal point of view', () => {
    const slots = { verbs: ['v'], constraints: [{ path: AMT, min: 10, max: 30 }] };
    expect(backTranslationDiff(pol(undefined, 50), slots, omegaV)).toEqual([
      { verb: 'v', kind: 'looser', path: AMT, text: 'For v, the grant allows amount 0 to 50; your request said 10 to 30.' },
    ]);
  });

  it('words a verb the request never mentioned and a verb the grant lacks', () => {
    expect(backTranslationDiff(pol(), { verbs: [], constraints: [] }, omegaV)).toEqual([
      { verb: 'v', kind: 'extra-verb', text: 'The grant allows v, which your request did not mention.' },
    ]);
    expect(backTranslationDiff(none, { verbs: ['v'], constraints: [] }, omegaV)).toEqual([
      { verb: 'v', kind: 'missing-verb', text: 'Your request mentions v, but the grant does not allow it.' },
    ]);
  });

  it('words a shape difference', () => {
    const slots = { verbs: ['w'], constraints: [{ path: RCP, oneOf: ['bob'], prefixOneOf: ['al'] }] };
    expect(backTranslationDiff({ predicates: nonBox('w'), caveats: [] }, slots, omegaW)).toEqual([
      { verb: 'w', kind: 'shape', text: "The grant's rule for w is a combination of cases that your request did not describe." },
      { verb: 'w', kind: 'looser', path: AMT, text: 'For w, the grant allows amount 0 to 100; your request said any value.' },
    ]);
  });
});

describe('renderQuestion and renderAction', () => {
  const dims: VerbSpace['dims'] = [numB, catA];
  const vs: VerbSpace = { verb: 'acme.refund', reversibility: 'rate_limited', weight: 1, dims };

  it('describes each cell of a catalogued verb, illustrating a numeric range by its boundary witness', () => {
    expect(renderQuestion(vs, [0, 0], cat)).toBe('Should the agent be allowed to: Refund v1.2 charge [acme.refund], with any amount from 0 to 49 (e.g. 49), recipient "bob"?');
    expect(renderQuestion(vs, [2, 1], cat)).toBe('Should the agent be allowed to: Refund v1.2 charge [acme.refund], with any amount from 51 to 100 (e.g. 51), a recipient under "al" (not otherwise named)?');
    expect(renderQuestion(vs, [1, 2], cat)).toBe('Should the agent be allowed to: Refund v1.2 charge [acme.refund], with amount exactly 50, a recipient not named anywhere in the grant or your request?');
  });

  it('asks about an uncatalogued verb without dimensions', () => {
    expect(renderQuestion({ verb: 'zzz', reversibility: 'reversible', weight: 1, dims: [] }, [], cat)).toBe('Should the agent be allowed to: perform "zzz"?');
  });

  it('renders a concrete action with sorted, typed values', () => {
    expect(renderAction(vs, { [RCP]: 'bob', [AMT]: 5 }, cat)).toBe('The agent wants to: Refund v1.2 charge [acme.refund, rate-limited], with amount 5, recipient "bob".');
  });

  it('renders an uncatalogued action and an action without values', () => {
    expect(renderAction({ verb: 'zzz', reversibility: 'rate_limited', weight: 1, dims: [] }, {}, cat)).toBe('The agent wants to: perform "zzz" [uncatalogued: treated as irreversible].');
  });
});
