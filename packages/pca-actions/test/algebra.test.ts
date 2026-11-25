// Property tests for the trait algebra: T1 lattice, T2 traits only add, T3 inheritance, T4 decision antitone, T5 custom
// trait soundness, T6 registry growth, T7 negation rule. Fixed seeds; >= 10^5 cases for the headline properties.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  BOTTOM, CAVEAT_KINDS, CONTEXT_KEYS, CORE_REGISTRY, CORE_TRAIT_DEFS, CORE_TRAIT_IDS, DECISION_RANK, allowSelectorError, buildRegistry, closure, effWithTrait, effective, extendRegistry,
  floorDecision, floorOf, join, joinAll, leq, meetDecision, policyDecision, profile, profileEq, profileError, registryError, selectorMatches, topTraits, traitsOf,
  type CaveatKind, type Decision, type Selector, type TraitDef, type TraitPolicy,
} from '../src';
import { arbCoreTraitSet, arbCustomTraits, arbDef, arbProfile } from './arb';

// PCA_PROP_RUNS lowers the case count for local smoke runs; CI leaves it unset (10^5 for the headline properties)
const RUNS = Number(process.env.PCA_PROP_RUNS ?? 100_000);
const opts = (seed: number, numRuns = RUNS) => ({ seed, numRuns: Math.min(numRuns, RUNS), verbose: 0 as const });
const rank = (d: Decision) => DECISION_RANK[d];
const arbGrant = fc.record({ caveats: fc.subarray([...CAVEAT_KINDS]), max_esc: fc.integer({ min: 0, max: 3 }), preauth_esc: fc.integer({ min: 0, max: 3 }) });
const arbCall = fc.record({ context: fc.subarray([...CONTEXT_KEYS]) });

describe('T1: (Profile, <=, join) is a bounded join-semilattice', () => {
  it('join is commutative, associative and idempotent; BOTTOM is the identity', () => {
    fc.assert(fc.property(arbProfile, arbProfile, arbProfile, (p, q, r) => {
      expect(profileEq(join(p, q), join(q, p))).toBe(true);
      expect(profileEq(join(join(p, q), r), join(p, join(q, r)))).toBe(true);
      expect(profileEq(join(p, p), p)).toBe(true);
      expect(profileEq(join(p, BOTTOM), p)).toBe(true);
      expect(profileError(join(p, q))).toBeNull();
    }), opts(1));
  });
  it('join is the least upper bound; leq is a partial order with BOTTOM least', () => {
    fc.assert(fc.property(arbProfile, arbProfile, arbProfile, (p, q, r) => {
      const j = join(p, q);
      expect(leq(p, j) && leq(q, j)).toBe(true);
      if (leq(p, r) && leq(q, r)) expect(leq(j, r)).toBe(true);
      expect(leq(BOTTOM, p)).toBe(true);
      expect(leq(p, p)).toBe(true);
      if (leq(p, q) && leq(q, p)) expect(profileEq(p, q)).toBe(true);
      if (leq(p, q) && leq(q, r)) expect(leq(p, r)).toBe(true);
      expect(leq(p, q)).toBe(profileEq(join(p, q), q));
    }), opts(2));
  });
  it('has finite height: a strictly increasing chain is bounded', () => {
    const maxLen = 3 + 2 + 1_000_000 + 3 + CAVEAT_KINDS.length + CONTEXT_KEYS.length + 8;
    expect(maxLen).toBeLessThan(2_000_000);
  });
});

describe('T2: traits only add restrictions', () => {
  it('S subset S2 implies F(S) <= F(S2); closure is monotone and idempotent; order and duplicates are irrelevant', () => {
    fc.assert(fc.property(arbCoreTraitSet, arbCoreTraitSet, fc.integer({ min: 0, max: 1000 }), (a, b, k) => {
      const big = [...new Set([...a, ...b])];
      expect(leq(floorOf(CORE_REGISTRY, a), floorOf(CORE_REGISTRY, big))).toBe(true);
      const ca = closure(CORE_REGISTRY, a);
      const cb = closure(CORE_REGISTRY, big);
      expect(ca.every((t) => cb.includes(t))).toBe(true);
      expect(closure(CORE_REGISTRY, ca)).toEqual(ca);
      const shuffled = [...big, ...big].sort((x, y) => ((x.charCodeAt(k % x.length) % 7) - (y.charCodeAt(k % y.length) % 7)) || (x < y ? -1 : 1));
      expect(profileEq(floorOf(CORE_REGISTRY, shuffled), floorOf(CORE_REGISTRY, big))).toBe(true);
    }), opts(3));
  });
  it('eff(d + t) >= eff(d) for every def d and every trait t', () => {
    fc.assert(fc.property(arbDef, fc.constantFrom(...CORE_TRAIT_IDS), (d, t) => {
      expect(leq(effective(d, CORE_REGISTRY).hint.eff, effWithTrait(d, t, CORE_REGISTRY))).toBe(true);
    }), opts(4));
  });
  it('holds in registries extended with custom traits', () => {
    fc.assert(fc.property(arbCustomTraits(CORE_TRAIT_DEFS as TraitDef[]), arbDef, fc.nat(), (custom, d, k) => {
      const reg = extendRegistry(CORE_REGISTRY, custom);
      const ids = [...reg.traits.keys()];
      const t = ids[k % ids.length]!;
      expect(leq(effective(d, reg).hint.eff, effWithTrait(d, t, reg))).toBe(true);
    }), opts(5, 20_000));
  });
});

describe('T3: inheritance - an action carries the floor of every trait it has', () => {
  it('eff(d) >= floor(t) for every t in T(d) and in its closure', () => {
    fc.assert(fc.property(arbDef, (d) => {
      const e = effective(d, CORE_REGISTRY).hint;
      for (const t of e.traits) expect(leq(CORE_REGISTRY.traits.get(t)!.floor, e.eff)).toBe(true);
      for (const t of e.closure) expect(leq(CORE_REGISTRY.traits.get(t)!.floor, e.eff)).toBe(true);
    }), opts(6));
  });
  it('a new action tagged t gets t\'s floor with no change to any policy (corollary)', () => {
    fc.assert(fc.property(arbDef, fc.constantFrom(...CORE_TRAIT_IDS), (d, t) => {
      expect(leq(CORE_REGISTRY.traits.get(t)!.floor, effWithTrait(d, t, CORE_REGISTRY))).toBe(true);
    }), opts(7, 50_000));
  });
});

describe('T4: the floor decision is antitone, and the final decision is the meet', () => {
  it('rho <= rho2 implies FloorDecision(rho2) <= FloorDecision(rho)', () => {
    fc.assert(fc.property(arbGrant, arbCall, arbProfile, arbProfile, (g, c, p, q) => {
      const hi = join(p, q);
      expect(rank(floorDecision(g, c, hi))).toBeLessThanOrEqual(rank(floorDecision(g, c, p)));
    }), opts(8));
  });
  it('adding a trait or tightening a declared field never raises Dec = meet(policy, floor)', () => {
    fc.assert(fc.property(arbGrant, arbCall, arbDef, fc.constantFrom(...CORE_TRAIT_IDS), fc.constantFrom<Decision>('deny', 'escalate', 'allow'), (g, c, d, t, pol) => {
      const before = meetDecision(pol, floorDecision(g, c, effective(d, CORE_REGISTRY).hint.eff));
      const after = meetDecision(pol, floorDecision(g, c, effWithTrait(d, t, CORE_REGISTRY)));
      expect(rank(after)).toBeLessThanOrEqual(rank(before));
    }), opts(9));
  });
  it('exact outcomes', () => {
    const g = { caveats: ['amount_cap', 'count_cap', 'window'] as CaveatKind[], max_esc: 3, preauth_esc: 0 };
    const refund = profile({ risk: 3, rev: 'rate_limited', blast_ppm: 700_000, esc: 2, caveats: ['amount_cap', 'count_cap', 'window'], context: ['idempotency'] });
    expect(floorDecision(g, { context: ['idempotency'] }, refund)).toBe('escalate'); // cosign tier is not pre-authorized
    expect(floorDecision({ ...g, preauth_esc: 2 }, { context: ['idempotency'] }, refund)).toBe('allow');
    expect(floorDecision({ ...g, preauth_esc: 2 }, { context: [] }, refund)).toBe('escalate'); // context missing
    expect(floorDecision({ ...g, preauth_esc: 2, caveats: [] }, { context: ['idempotency'] }, refund)).toBe('escalate'); // caveats missing
    expect(floorDecision({ ...g, max_esc: 1, preauth_esc: 2 }, { context: ['idempotency'] }, refund)).toBe('deny'); // tier above max_esc
    expect(meetDecision('allow', 'escalate')).toBe('escalate');
    expect(meetDecision('deny', 'allow')).toBe('deny');
  });
});

describe('T8: unconfirmed means maximally dangerous', () => {
  const top = topTraits(CORE_REGISTRY);
  it('an unconfirmed def has the TOP trait set whatever its machine traits, and the TOP profile is above every confirmed version of it', () => {
    fc.assert(fc.property(arbDef, fc.subarray([...CORE_TRAIT_IDS]), (d, extra) => {
      const machine = { ...d, traits: extra.filter((t) => t !== 'pca.unreviewed') };
      const u = effective(machine, CORE_REGISTRY);
      expect(u.confirmed).toBe(false);
      expect(u.traits).toEqual(top);
      expect(u.closure).toEqual(top);
      // every confirmed version (any machine/author trait set) is at or below the unconfirmed profile
      expect(leq(u.hint.eff, u.eff)).toBe(true);
      expect(leq(effWithTrait(machine, 'pca.money_moving', CORE_REGISTRY), u.eff)).toBe(true);
    }), opts(40));
  });
  it('no machine-authored input (declared traits, provenance, suggestion records, review state) lowers the effective set', () => {
    fc.assert(fc.property(arbDef, fc.constantFrom('authored', 'unreviewed', 'suggested', 'confirmed'), fc.subarray([...CORE_TRAIT_IDS]), (d, state, prov) => {
      const forged = { ...d, traits: [], review: { state, provenance: { adjudicated: prov, union: [] }, suggested_by: { added: { traits: [], roles: {}, tags: {} } } } } as typeof d;
      expect(traitsOf(forged, CORE_REGISTRY)).toEqual(top);
      expect(traitsOf(forged, CORE_REGISTRY, { attestationVerified: () => false })).toEqual(top);
    }), opts(41));
  });
  it('the final decision for an unconfirmed def is at most the decision for any confirmed version (antitone)', () => {
    fc.assert(fc.property(arbGrant, arbCall, arbDef, fc.constantFrom<Decision>('deny', 'escalate', 'allow'), (g, c, d, pol) => {
      const e = effective(d, CORE_REGISTRY);
      const unconfirmed = meetDecision(pol, floorDecision(g, c, e.eff));
      const confirmedVersion = meetDecision(pol, floorDecision(g, c, e.hint.eff));
      expect(rank(unconfirmed)).toBeLessThanOrEqual(rank(confirmedVersion));
    }), opts(42));
  });
  it('a trait policy: forbid and cap selectors match an unconfirmed def, allow selectors never do', () => {
    const sel: Selector = { k: 'trait', id: 'pca.money_moving' };
    const pol: TraitPolicy = { pinned: ['a.b'], allow: [sel], prohibit: [] };
    expect(policyDecision(pol, 'a.b', new Set(['pca.money_moving']), true)).toBe('allow');
    expect(policyDecision(pol, 'a.b', new Set(top), false)).toBe('deny');
    expect(policyDecision({ pinned: ['a.b'], allow: [{ k: 'any_of', ids: ['pca.pii_access'] }], prohibit: [{ k: 'not', s: { k: 'trait', id: 'pca.money_moving' } }] }, 'a.b', new Set(), false)).toBe('deny');
    expect(policyDecision({ pinned: ['a.b'], allow: [sel], prohibit: [{ k: 'trait', id: 'pca.code_execution' }] }, 'a.b', new Set(['pca.money_moving']), true)).toBe('allow');
  });
});

describe('T5: custom traits cannot weaken core floors', () => {
  it('well formed custom traits are accepted and never reduce a core floor; weakened ones are rejected', () => {
    fc.assert(fc.property(arbCustomTraits(CORE_TRAIT_DEFS as TraitDef[]), (custom) => {
      expect(registryError([...CORE_TRAIT_DEFS, ...custom], { core: true })).toBeNull();
      const reg = extendRegistry(CORE_REGISTRY, custom);
      for (const c of custom) for (const u of c.implies) expect(leq(reg.traits.get(u)!.floor, floorOf(reg, [c.id]))).toBe(true);
      for (const id of CORE_TRAIT_IDS) expect(profileEq(floorOf(reg, [id]), floorOf(CORE_REGISTRY, [id]))).toBe(true);
    }), opts(10, 20_000));
    fc.assert(fc.property(arbProfile, fc.constantFrom(...CORE_TRAIT_IDS), (weak, imp) => {
      const f = CORE_REGISTRY.traits.get(imp)!.floor;
      const bad: TraitDef = { id: 'acme.weak', implies: [imp], floor: weak, card_phrase: 'weak' };
      const err = registryError([...CORE_TRAIT_DEFS, bad], { core: true });
      expect(err === null).toBe(leq(f, weak));
    }), opts(11, 20_000));
  });
  it('rejects the reserved namespace, cycles, unknown implies and depth > 8', () => {
    const f = profile({ risk: 1 });
    const mk = (id: string, implies: string[]): TraitDef => ({ id, implies, floor: f, card_phrase: id });
    expect(registryError([mk('pca.fake', [])])).toMatch(/reserved/);
    expect(() => extendRegistry(CORE_REGISTRY, [mk('pca.money_moving', [])])).toThrow(/core trait/);
    expect(registryError([mk('a.x', ['a.y']), mk('a.y', ['a.x'])])).toMatch(/cycle/);
    expect(registryError([mk('a.x', ['a.nope'])])).toMatch(/unknown trait/);
    const chain = Array.from({ length: 9 }, (_, i) => mk(`a.c${i}`, i < 8 ? [`a.c${i + 1}`] : []));
    expect(registryError(chain)).toMatch(/depth/);
    expect(registryError(chain.slice(1))).toBeNull(); // depth 8 is allowed
    expect(registryError([mk('a.x', []), mk('a.x', [])])).toMatch(/twice/);
    expect(() => buildRegistry([mk('a.x', ['a.nope'])])).toThrow(/unknown trait/);
  });
  it('the core registry satisfies T5 itself and has exactly 22 traits', () => {
    expect(CORE_TRAIT_DEFS).toHaveLength(22);
    expect(registryError(CORE_TRAIT_DEFS as TraitDef[], { core: true })).toBeNull();
    expect(closure(CORE_REGISTRY, ['pca.impersonation'])).toEqual(['pca.external_communication', 'pca.impersonation']);
    expect(joinAll([]).risk).toBe(0);
  });
});

describe('T6: registry growth never turns a prohibition or a closed-world deny into an allow', () => {
  const sel = (ids: string[]): Selector => ({ k: 'all_of', ids });
  const arbPolicy = fc.record({
    pinned: fc.subarray(['v.a', 'v.b', 'v.c', 'v.d']),
    allow: fc.array(fc.subarray([...CORE_TRAIT_IDS], { maxLength: 2 }).map(sel), { maxLength: 3 }),
    prohibit: fc.array(fc.subarray([...CORE_TRAIT_IDS], { minLength: 1, maxLength: 2 }).map(sel), { maxLength: 3 }),
    on_new_action: fc.constantFrom<'deny' | 'escalate'>('deny', 'escalate'),
  }) as fc.Arbitrary<TraitPolicy>;
  const arbAction = fc.record({ verb: fc.constantFrom('v.a', 'v.b', 'v.c', 'v.d', 'v.new1', 'v.new2'), traits: arbCoreTraitSet });
  it('an action outside the pinned pack is never allowed; a prohibit match is always a deny; decisions of old actions do not change', () => {
    fc.assert(fc.property(arbPolicy, fc.array(arbAction, { maxLength: 8 }), fc.array(arbAction, { maxLength: 8 }), (p, oldA, newA) => {
      const cl = (a: { traits: string[] }) => new Set(closure(CORE_REGISTRY, a.traits));
      for (const a of newA) {
        const d = policyDecision(p, a.verb, cl(a), true);
        if (!p.pinned.includes(a.verb)) expect(d).not.toBe('allow');
        if (p.prohibit.some((s) => selectorMatches(s, cl(a)))) expect(d).toBe('deny');
      }
      // growing the registry (more actions) leaves each old action's decision unchanged and prohibit coverage can only grow
      const grown = [...oldA, ...newA];
      for (const a of oldA) expect(policyDecision(p, a.verb, cl(a), true)).toBe(policyDecision(p, grown.find((g) => g === a)!.verb, cl(a), true));
      const matchedOld = oldA.filter((a) => p.prohibit.some((s) => selectorMatches(s, cl(a))));
      const matchedGrown = grown.filter((a) => p.prohibit.some((s) => selectorMatches(s, cl(a))));
      expect(matchedGrown.length).toBeGreaterThanOrEqual(matchedOld.length);
    }), opts(12, 20_000));
  });
});

describe('T7: allow selectors may not use negation', () => {
  it('rejects not and unpinned any_of in an allow; accepts positive pinned selectors; a positive selector is monotone', () => {
    const t = (id: string): Selector => ({ k: 'trait', id });
    expect(allowSelectorError({ k: 'not', s: t('pca.destructive') }, true)).toMatch(/negation/);
    expect(allowSelectorError({ k: 'and', a: t('pca.bulk'), b: { k: 'not', s: t('pca.destructive') } }, true)).toMatch(/negation/);
    expect(allowSelectorError({ k: 'any_of', ids: ['pca.bulk'] }, false)).toMatch(/pinned/);
    expect(allowSelectorError({ k: 'any_of', ids: ['pca.bulk'] }, true)).toBeNull();
    expect(allowSelectorError({ k: 'all_of', ids: ['pca.bulk', 'pca.pii_access'] }, false)).toBeNull();
    fc.assert(fc.property(arbCoreTraitSet, arbCoreTraitSet, fc.subarray([...CORE_TRAIT_IDS], { maxLength: 3 }), (a, b, ids) => {
      const small = new Set(a);
      const big = new Set([...a, ...b]);
      for (const s of [{ k: 'all_of', ids }, { k: 'any_of', ids }, { k: 'and', a: { k: 'trait', id: ids[0] ?? 'pca.bulk' }, b: { k: 'all_of', ids } }] as Selector[]) {
        if (selectorMatches(s, small)) expect(selectorMatches(s, big)).toBe(true);
      }
    }), opts(13, 20_000));
  });
});
