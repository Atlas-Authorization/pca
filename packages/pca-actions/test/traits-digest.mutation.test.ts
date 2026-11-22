import { hashCanonical } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  ActionKitError, TRAITS_DIGEST_DOMAIN, buildRegistry, closure, extendRegistry, floorDecision, isContextKey, leq, packProof, packRoot, profile, profileError, registryError, traitsDigest,
  type GrantFacts, type Registry, type TraitDef,
} from '../src';

const mk = (id: string, implies: string[] = [], card_phrase: string = id): TraitDef => ({ id, implies, floor: profile(), card_phrase });
const thrown = (f: () => unknown): ActionKitError => {
  try {
    f();
  } catch (e) {
    return e as ActionKitError;
  }
  throw new Error('did not throw');
};
// each layer implies the two before it: linear with memoisation, exponential without
const layers = (n: number): TraitDef[] => Array.from({ length: n }, (_, k) => mk(`x.t${k}`, [k - 1, k - 2].filter((j) => j >= 0).map((j) => `x.t${j}`)));

describe('pack digest errors', () => {
  it('carries the exact code and message', () => {
    const dup = thrown(() => packRoot(['a', 'a']));
    expect([dup.code, dup.message]).toEqual(['duplicate_def', 'a pack lists a def digest twice']);
    const empty = thrown(() => packRoot([]));
    expect([empty.code, empty.message]).toEqual(['empty_pack', 'a pack has at least one def']);
    const miss = thrown(() => packProof(['a', 'b'], 'c'));
    expect([miss.code, miss.message]).toEqual(['not_in_pack', 'the digest is not in the pack']);
  });
});

describe('traitsDigest', () => {
  it('sorts traits by id and each implies list', () => {
    const reg = buildRegistry([mk('x.c', ['x.b', 'x.a']), mk('x.b'), mk('x.a')]);
    const f = profile();
    expect(traitsDigest(reg)).toBe(hashCanonical({
      d: TRAITS_DIGEST_DOMAIN,
      traits: [
        { id: 'x.a', implies: [], floor: f, card_phrase: 'x.a' },
        { id: 'x.b', implies: [], floor: f, card_phrase: 'x.b' },
        { id: 'x.c', implies: ['x.a', 'x.b'], floor: f, card_phrase: 'x.c' },
      ],
    }));
  });
});

describe('profile validation', () => {
  it('non-object profiles are rejected as such', () => {
    for (const p of ['x', 5, true]) expect(profileError(p)).toBe('profile must be an object');
  });
  it('set size cap is 64 entries', () => {
    expect(profileError({ ...profile(), caveats: Array(64).fill('window') })).toBe('profile.caveats must be sorted and distinct');
    expect(profileError({ ...profile(), caveats: Array(65).fill('window') })).toBe('profile.caveats must be an array of known caveats entries');
  });
  it('context keys must be strings', () => {
    expect(isContextKey(['session_taint_max:low'])).toBe(false);
    expect(isContextKey('session_taint_max:low')).toBe(true);
  });
  it('leq compares reversibility', () => {
    expect(leq(profile({ rev: 'irreversible' }), profile())).toBe(false);
    expect(leq(profile({ rev: 'rate_limited' }), profile({ rev: 'irreversible' }))).toBe(true);
  });
});

describe('registryError', () => {
  it('holds at most 512 traits', () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => mk(`x.t${i}`));
    expect(registryError(many(512))).toBeNull();
    expect(registryError(many(513))).toBe('a registry holds at most 512 traits');
  });
  it('rejects non-object traits and non-string ids', () => {
    for (const t of ['x', 5]) expect(registryError([t as unknown as TraitDef])).toBe('trait must be an object');
    expect(registryError([{ ...mk('x.a'), id: ['x.b'] } as unknown as TraitDef])).toBe("trait id 'x.b' is malformed");
  });
  it('implies: up to 8, strings only', () => {
    const base = Array.from({ length: 9 }, (_, i) => mk(`x.b${i}`));
    const top = (n: number) => mk('x.top', base.slice(0, n).map((t) => t.id));
    expect(registryError([...base, top(8)])).toBeNull();
    expect(registryError([...base, top(9)])).toBe("trait 'x.top': implies must be up to 8 distinct trait ids");
    expect(registryError([mk('x.a', [5 as unknown as string])])).toBe("trait 'x.a': implies must be up to 8 distinct trait ids");
  });
  it('card_phrase: string of 1..120 characters', () => {
    expect(registryError([mk('x.a', [], 'p'.repeat(120))])).toBeNull();
    const msg = "trait 'x.a': card_phrase must be a non-empty string up to 120 characters";
    expect(registryError([mk('x.a', [], 'p'.repeat(121))])).toBe(msg);
    expect(registryError([mk('x.a', [], '')])).toBe(msg);
    expect(registryError([mk('x.a', [], 5 as unknown as string)])).toBe(msg);
  });
  it('reports the depth of a deep diamond chain without re-walking shared nodes', () => {
    expect(registryError(layers(50).reverse())).toBe("trait 'x.t49': implies depth 50 exceeds 8");
  });
  it('reports a cycle', () => {
    expect(registryError([mk('x.a', ['x.b']), mk('x.b', ['x.a'])])).toBe("trait 'x.a': implies cycle");
  });
});

describe('extendRegistry', () => {
  it('a custom trait may not redefine a base trait, even outside pca.', () => {
    const base = buildRegistry([mk('x.a')]);
    expect(thrown(() => extendRegistry(base, [mk('x.a')])).message).toBe("custom trait 'x.a' may not redefine a core trait");
  });
});

describe('closure', () => {
  it('visits each trait once', () => {
    const defs = layers(50);
    const reg: Registry = { traits: new Map(defs.map((t) => [t.id, t])) };
    expect(closure(reg, ['x.t49'])).toEqual(defs.map((t) => t.id).sort());
  });
});

describe('floorDecision', () => {
  it('denies a missing grant instead of throwing', () => {
    expect(floorDecision(undefined as unknown as GrantFacts, { context: [] }, profile())).toBe('deny');
    expect(floorDecision(null as unknown as GrantFacts, { context: [] }, profile())).toBe('deny');
  });
});
