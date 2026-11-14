// The README "Fail-closed behaviour" table as exact-outcome tests: each row is a missing or invalid X and the whole result.
import { describe, expect, it } from 'vitest';
import {
  BOTTOM, RULE22_ENGINE, allowSelectorError, idMatches, idPatternContains, idPatternError, policyDecision, profile, selectorMatchesFor, verifyPackLogEntry,
  type IdPattern, type Selector, type TraitPolicy,
} from '../src';

const closure = new Set(['pca.money_moving']);
const trait: Selector = { k: 'trait', id: 'pca.money_moving' };
const absent: Selector = { k: 'not', s: { k: 'trait', id: 'pca.destructive' } };

describe('unconfirmed means maximally dangerous (selectors)', () => {
  it('an unconfirmed action is matched by every prohibit selector, even one that does not match its closure, and by no allow selector', () => {
    expect(selectorMatchesFor({ k: 'trait', id: 'pca.destructive' }, 'prohibit', closure, false)).toBe(true);
    expect(selectorMatchesFor(absent, 'prohibit', new Set(['pca.destructive']), false)).toBe(true);
    expect(selectorMatchesFor(trait, 'allow', closure, false)).toBe(false);
    expect(selectorMatchesFor(trait, 'allow', closure, true)).toBe(true);
    expect(selectorMatchesFor({ k: 'trait', id: 'pca.destructive' }, 'prohibit', closure, true)).toBe(false);
  });

  const pol: TraitPolicy = { pinned: ['a.b.c'], allow: [trait], prohibit: [] };
  it('a verb outside the pinned set is denied (default) or escalated, never allowed; an unconfirmed pinned verb is denied', () => {
    expect(policyDecision(pol, 'x.y.z', closure, true)).toBe('deny');
    expect(policyDecision({ ...pol, on_new_action: 'escalate' }, 'x.y.z', closure, true)).toBe('escalate');
    expect(policyDecision(pol, 'a.b.c', closure, false)).toBe('deny');
    expect(policyDecision(pol, 'a.b.c', closure, true)).toBe('allow');
    expect(policyDecision({ ...pol, allow: [] }, 'a.b.c', closure, true)).toBe('deny');
    expect(policyDecision({ ...pol, prohibit: [trait] }, 'a.b.c', closure, true)).toBe('deny');
  });

  it('an allow selector with negation, or an unpinned any_of, is refused with its reason', () => {
    expect(allowSelectorError(absent, true)).toBe('an allow selector must not use negation: the absence of a trait is never a safety claim');
    expect(allowSelectorError({ k: 'any_of', ids: ['pca.money_moving'] }, false)).toBe('any_of in an allow selector requires the grant to be pinned to a pack digest');
    expect(allowSelectorError({ k: 'any_of', ids: ['pca.money_moving'] }, true)).toBeNull();
  });
});

describe('resource id patterns', () => {
  it('a malformed pattern is refused with its reason', () => {
    expect(idPatternError(null)).toBe("resource.id must be '*', {exact} or {prefix, class, len}");
    expect(idPatternError([])).toBe("resource.id must be '*', {exact} or {prefix, class, len}");
    expect(idPatternError({ exact: '' })).toBe('resource.id.exact must be 1..128 safe characters');
    expect(idPatternError({ exact: 'a b' })).toBe('resource.id.exact must be 1..128 safe characters');
    expect(idPatternError({ exact: 'a', extra: 1 })).toBe("resource.id must be '*', {exact} or {prefix, class, len}");
    expect(idPatternError({ prefix: 'inv_', class: 'nope', len: [1, 2] })).toBe('resource.id.class is not an id class');
    expect(idPatternError({ prefix: 'inv_', class: 'digits', len: [3, 2] })).toBe('resource.id.len: min > max');
    expect(idPatternError({ prefix: 'inv_', class: 'digits', len: [0, 2] })).toBe('resource.id.len must be [min, max] in 1..128');
    expect(idPatternError({ prefix: 'inv_', class: 'digits', len: [1, 129] })).toBe('resource.id.len must be [min, max] in 1..128');
    expect(idPatternError({ prefix: 'x', class: 'uuid', len: [36, 36] })).toBe('a uuid id has no prefix and length exactly [36, 36]');
    expect(idPatternError({ prefix: 'inv_', class: 'digits', len: [1, 4] })).toBeNull();
    expect(idPatternError('*')).toBeNull();
  });

  it('matching and containment fail closed on the boundaries', () => {
    const p: IdPattern = { prefix: 'inv_', class: 'digits', len: [2, 4] };
    expect(idMatches(p, 'inv_12')).toBe(true);
    expect(idMatches(p, 'inv_1')).toBe(false);
    expect(idMatches(p, 'inv_12345')).toBe(false);
    expect(idMatches(p, 'inv_1a')).toBe(false);
    expect(idMatches(p, 'x_12')).toBe(false);
    expect(idMatches('*', '')).toBe(false);
    expect(idMatches('*', 'a'.repeat(129))).toBe(false);
    expect(idPatternContains(p, '*')).toBe(false);
    expect(idPatternContains('*', p)).toBe(true);
    expect(idPatternContains(p, { prefix: 'inv_', class: 'digits', len: [2, 5] })).toBe(false);
    expect(idPatternContains(p, { prefix: 'inv_', class: 'hex', len: [2, 4] })).toBe(false);
    expect(idPatternContains({ exact: 'a' }, p)).toBe(false);
  });
});

describe('the rule-22 engine', () => {
  const grant = { caveats: ['window'], max_esc: 3, preauth_esc: 3 };
  it('a verb absent from the schema, floors that are not a profile, or a garbage document is denied', () => {
    expect(RULE22_ENGINE.decide({ doc: { verbs: [] }, verb: 'a.b.c', grant, context: [] })).toBe('deny');
    expect(RULE22_ENGINE.decide({ doc: { verbs: [{ verb: 'a.b.c', floors: { risk: 99 } }] }, verb: 'a.b.c', grant, context: [] })).toBe('deny');
    expect(RULE22_ENGINE.decide({ doc: { verbs: [{ verb: 'a.b.c' }] }, verb: 'a.b.c', grant, context: [] })).toBe('deny');
    expect(RULE22_ENGINE.decide({ doc: null as never, verb: 'a.b.c', grant, context: [] })).toBe('deny');
  });
  it('a valid floor is decided by the floor decision; a missing required caveat escalates', () => {
    const floors = profile({ caveats: ['window'], esc: 1 });
    expect(RULE22_ENGINE.decide({ doc: { verbs: [{ verb: 'a.b.c', floors }] }, verb: 'a.b.c', grant, context: [] })).toBe('allow');
    expect(RULE22_ENGINE.decide({ doc: { verbs: [{ verb: 'a.b.c', floors }] }, verb: 'a.b.c', grant: { ...grant, caveats: [] }, context: [] })).toBe('escalate');
    expect(RULE22_ENGINE.decide({ doc: { verbs: [{ verb: 'a.b.c', floors }] }, verb: 'a.b.c', grant: { ...grant, max_esc: 0 }, context: [] })).toBe('deny');
    expect(RULE22_ENGINE.decide({ doc: { verbs: [{ verb: 'a.b.c', floors: BOTTOM }] }, verb: 'a.b.c', grant: { caveats: [], max_esc: 0, preauth_esc: 0 }, context: [] })).toBe('allow');
  });
  it('a schema document that cannot be recomputed is refused with a reason, never accepted', () => {
    const r = RULE22_ENGINE.schemaError(null as never, undefined);
    expect(typeof r).toBe('string');
    expect(r).not.toBeNull();
  });
});

describe('a transparency entry that is not well formed', () => {
  it('verifyPackLogEntry returns false (never throws) for garbage bytes', () => {
    const pack = {} as never;
    expect(verifyPackLogEntry(pack, { statement: new Uint8Array([1, 2, 3]), receipt: new Uint8Array([]) }, { registry: {} as never, log: {} as never })).toBe(false);
  });
});
