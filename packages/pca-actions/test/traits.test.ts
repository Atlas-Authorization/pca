// Exact-outcome tests for the registry, profile validation, closure and the pinned digests (the cross-language contract).
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  ActionKitError, BOTTOM, BUILTIN_DEFS, CORE_REGISTRY, CORE_TRAIT_DEFS, PACK_DIGEST_DOMAIN, buildRegistry, closure, defDigest, extendRegistry, floorDecision, floorOf, isContextKey, join, packRoot, profile,
  profileError, registryError, tablesDigest, traitsDigest, type GrantFacts, type Profile, type TraitDef,
} from '../src';
import { runs } from './runs';

const ok = (): Profile => profile({ risk: 1, rev: 'rate_limited', blast_ppm: 10, esc: 1, caveats: ['window'], context: ['revocable'], prules: ['array_bounded'] });
const mk = (id: string, implies: string[] = [], floor: Profile = profile()): TraitDef => ({ id, implies, floor, card_phrase: id });

describe('profile', () => {
  it('builds a canonical profile: sorted, distinct sets, defaults filled', () => {
    expect(profile()).toEqual({ risk: 0, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [] });
    expect(profile({ caveats: ['window', 'amount_cap', 'window'], context: ['revocable', 'idempotency'] })).toMatchObject({ caveats: ['amount_cap', 'window'], context: ['idempotency', 'revocable'] });
    expect(BOTTOM).toEqual(profile());
  });
  it('profileError names the first problem', () => {
    expect(profileError(ok())).toBeNull();
    expect(profileError([])).toBe('profile must be an object');
    expect(profileError(null)).toBe('profile must be an object');
    expect(profileError({ ...ok(), extra: 1 })).toBe("profile: unknown member 'extra'");
    for (const risk of [-1, 4, 1.5, '1']) expect(profileError({ ...ok(), risk })).toBe('profile.risk must be an integer in 0..3');
    expect(profileError({ ...ok(), rev: 'x' })).toBe('profile.rev is not a reversibility class');
    for (const blast_ppm of [-1, 1_000_001, 0.5]) expect(profileError({ ...ok(), blast_ppm })).toBe('profile.blast_ppm must be an integer in 0..1000000');
    for (const esc of [-1, 4, 2.5]) expect(profileError({ ...ok(), esc })).toBe('profile.esc must be an integer in 0..3');
    expect(profileError({ ...ok(), caveats: ['nope'] })).toBe('profile.caveats must be an array of known caveats entries');
    expect(profileError({ ...ok(), context: ['x'] })).toBe('profile.context must be an array of known context entries');
    expect(profileError({ ...ok(), prules: 'array_bounded' })).toBe('profile.prules must be an array of known prules entries');
    expect(profileError({ ...ok(), caveats: ['window', 'amount_cap'] })).toBe('profile.caveats must be sorted and distinct');
    expect(profileError({ ...ok(), caveats: ['window', 'window'] })).toBe('profile.caveats must be sorted and distinct');
    expect(profileError({ ...ok(), context: ['session_taint_max:low'] })).toBeNull();
    expect(profileError({ ...ok(), context: ['session_taint_max:Low'] })).toMatch(/context/);
    expect(profileError({ ...ok(), caveats: Array(65).fill('window') })).toMatch(/caveats/);
    expect(isContextKey('revocable')).toBe(true);
    expect(isContextKey('session_taint_max:high')).toBe(true);
    expect(isContextKey('session_taint_max:')).toBe(false);
    expect(isContextKey(5)).toBe(false);
  });
  it('the numeric components of join are maxima and rev is by rank', () => {
    const j = join(profile({ risk: 1, rev: 'irreversible', blast_ppm: 5, esc: 3 }), profile({ risk: 2, rev: 'rate_limited', blast_ppm: 9, esc: 1 }));
    expect(j).toMatchObject({ risk: 2, rev: 'irreversible', blast_ppm: 9, esc: 3 });
    expect(join(profile({ rev: 'rate_limited' }), profile({ rev: 'reversible' })).rev).toBe('rate_limited');
    expect(join(profile({ rev: 'reversible' }), profile({ rev: 'rate_limited' })).rev).toBe('rate_limited');
  });
});

describe('registryError and registries (exact messages)', () => {
  it('well formedness', () => {
    expect(registryError([])).toBeNull();
    expect(registryError(Array.from({ length: 513 }, (_, i) => mk(`a.t${i}`)))).toBe('a registry holds at most 512 traits');
    expect(registryError([null as never])).toBe('trait must be an object');
    expect(registryError([mk('Bad.id')])).toBe("trait id 'Bad.id' is malformed");
    expect(registryError([mk('noprefix')])).toBe("trait id 'noprefix' is malformed");
    expect(registryError([mk('pca.x')])).toBe("trait 'pca.x': the pca. namespace is reserved for core traits");
    expect(registryError([mk('pca.x')], { core: true })).toBeNull();
    expect(registryError([mk('a.x'), mk('a.x')])).toBe("trait 'a.x' is defined twice");
    expect(registryError([mk('a.x', ['a.y', 'a.y'])])).toBe("trait 'a.x': implies must be up to 8 distinct trait ids");
    expect(registryError([mk('a.x', Array.from({ length: 9 }, (_, i) => `a.i${i}`))])).toBe("trait 'a.x': implies must be up to 8 distinct trait ids");
    expect(registryError([{ ...mk('a.x'), floor: { ...ok(), esc: 9 } }])).toBe("trait 'a.x': profile.esc must be an integer in 0..3");
    expect(registryError([{ ...mk('a.x'), card_phrase: '' }])).toBe("trait 'a.x': card_phrase must be a non-empty string up to 120 characters");
    expect(registryError([{ ...mk('a.x'), card_phrase: 'x'.repeat(121) }])).toBe("trait 'a.x': card_phrase must be a non-empty string up to 120 characters");
    expect(registryError([mk('a.x', ['a.nope'])])).toBe("trait 'a.x' implies unknown trait 'a.nope'");
    expect(registryError([mk('a.x', ['a.y'], profile({ risk: 1 })), mk('a.y', [], profile({ risk: 2 }))])).toBe("trait 'a.x': floor is below the floor of implied 'a.y' (a trait may only extend what it implies)");
    expect(registryError([mk('a.x', ['a.y'], profile({ risk: 2 })), mk('a.y', [], profile({ risk: 2 }))])).toBeNull();
    expect(registryError([mk('a.x', ['a.y']), mk('a.y', ['a.x'])])).toBe("trait 'a.x': implies cycle");
    const chain = (n: number) => Array.from({ length: n }, (_, i) => mk(`a.c${i}`, i < n - 1 ? [`a.c${i + 1}`] : []));
    expect(registryError(chain(9))).toBe("trait 'a.c0': implies depth 9 exceeds 8");
    expect(registryError(chain(8))).toBeNull();
    expect(registryError([mk('a.x', ['a.x'])])).toBe("trait 'a.x': implies cycle");
  });
  it('buildRegistry and extendRegistry throw typed errors', () => {
    try { buildRegistry([mk('a.x', ['a.y'])]); expect(true).toBe(false); } catch (e) { expect(e).toBeInstanceOf(ActionKitError); expect((e as ActionKitError).code).toBe('bad_registry'); expect((e as Error).message).toBe("trait 'a.x' implies unknown trait 'a.y'"); }
    expect(() => extendRegistry(CORE_REGISTRY, [mk('pca.money_moving')])).toThrow("custom trait 'pca.money_moving' may not redefine a core trait");
    expect(() => extendRegistry(CORE_REGISTRY, [mk('pca.brand_new')])).toThrow("custom trait 'pca.brand_new' may not redefine a core trait");
    expect(() => extendRegistry(CORE_REGISTRY, [mk('a.x', ['a.nope'])])).toThrow("trait 'a.x' implies unknown trait 'a.nope'");
    const ext = extendRegistry(CORE_REGISTRY, [mk('acme.k', ['pca.bulk'], profile({ ...CORE_REGISTRY.traits.get('pca.bulk')!.floor, esc: 3 }))]);
    expect(ext.traits.size).toBe(23);
    expect(CORE_REGISTRY.traits.size).toBe(22);
  });
  it('closure and floors', () => {
    try { closure(CORE_REGISTRY, ['pca.nope']); expect(true).toBe(false); } catch (e) { expect((e as ActionKitError).code).toBe('unknown_trait'); expect((e as Error).message).toBe("unknown trait 'pca.nope'"); }
    expect(closure(CORE_REGISTRY, [])).toEqual([]);
    expect(closure(CORE_REGISTRY, ['pca.impersonation', 'pca.bulk'])).toEqual(['pca.bulk', 'pca.external_communication', 'pca.impersonation']);
    expect(floorOf(CORE_REGISTRY, ['pca.destructive'])).toEqual({ risk: 2, rev: 'rate_limited', blast_ppm: 0, esc: 1, caveats: ['resource_scope'], context: [], prules: ['id_not_wildcard'] });
  });
  it('the closure equals eight rounds of one-step implication (the model the Dafny proof reasons about)', () => {
    fc.assert(fc.property(fc.array(fc.subarray([0, 1, 2, 3, 4, 5, 6, 7], { maxLength: 3 }), { minLength: 8, maxLength: 8 }), fc.subarray([0, 1, 2, 3, 4, 5, 6, 7]), (impl, start) => {
      // acyclic by construction: trait i may only imply traits with a larger index
      const defs = impl.map((s, i) => mk(`a.t${i}`, s.filter((j) => j > i).map((j) => `a.t${j}`)));
      const reg = buildRegistry(defs);
      let cur = new Set(start);
      for (let k = 0; k < 8; k++) { const next = new Set(cur); for (const i of cur) for (const j of impl[i]!.filter((x) => x > i)) next.add(j); cur = next; }
      expect(closure(reg, start.map((i) => `a.t${i}`))).toEqual([...cur].map((i) => `a.t${i}`).sort());
    }), { seed: 41, numRuns: runs(5000) });
  });
  it('the core table is exactly the 22 spec traits with the spec floors', () => {
    expect(CORE_TRAIT_DEFS.map((t) => t.id)).toEqual([
      'pca.money_moving', 'pca.destructive', 'pca.irreversible', 'pca.external_communication', 'pca.data_export', 'pca.privilege_change', 'pca.code_execution', 'pca.credential_access',
      'pca.bulk', 'pca.pii_access', 'pca.public_exposure', 'pca.persistence', 'pca.infra_mutation', 'pca.cost_incurring', 'pca.legal_binding', 'pca.impersonation', 'pca.network_egress',
      'pca.financial_data_read', 'pca.regulated_data', 'pca.scheduled', 'pca.unreviewed', 'pca.agent_spawning',
    ]);
    const f = (id: string) => CORE_REGISTRY.traits.get(id)!.floor;
    expect(f('pca.money_moving')).toEqual({ risk: 3, rev: 'rate_limited', blast_ppm: 700_000, esc: 2, caveats: ['amount_cap', 'count_cap', 'window'], context: ['idempotency'], prules: ['money_amount_bounded', 'money_has_currency', 'pay_has_idempotency'] });
    expect(f('pca.privilege_change')).toMatchObject({ risk: 3, esc: 3, caveats: ['resource_scope', 'short_expiry'] });
    expect(f('pca.code_execution')).toMatchObject({ risk: 3, rev: 'irreversible', esc: 2, context: ['sandbox_attested'] });
    expect(f('pca.legal_binding')).toMatchObject({ risk: 3, rev: 'irreversible', esc: 3 });
    expect(f('pca.unreviewed')).toEqual({ risk: 3, rev: 'irreversible', blast_ppm: 1_000_000, esc: 2, caveats: ['approval_ref', 'resource_scope'], context: ['dry_run_first'], prules: [] });
    expect(f('pca.impersonation')).toMatchObject({ risk: 2, rev: 'irreversible', esc: 1, caveats: ['rate_cap', 'recipient_scope'] });
    expect(CORE_REGISTRY.traits.get('pca.impersonation')!.implies).toEqual(['pca.external_communication']);
  });
});

describe('floorDecision boundaries', () => {
  const g = (o: Partial<GrantFacts> = {}): GrantFacts => ({ caveats: ['window'], max_esc: 2, preauth_esc: 1, ...o });
  const call = { context: ['revocable'] };
  const p = (o: Partial<Profile> = {}) => profile({ caveats: ['window'], context: ['revocable'], esc: 1, ...o });
  it('the tier equal to the limit is not above it', () => {
    expect(floorDecision(g(), call, p({ esc: 2 }))).toBe('escalate'); // 2 > preauth 1, 2 <= max 2
    expect(floorDecision(g(), call, p({ esc: 3 }))).toBe('deny');
    expect(floorDecision(g(), call, p({ esc: 1 }))).toBe('allow');
    expect(floorDecision(g({ preauth_esc: 0 }), call, p({ esc: 1 }))).toBe('escalate');
    expect(floorDecision(g({ max_esc: 0, preauth_esc: 0 }), call, p({ esc: 0 }))).toBe('allow');
  });
  it('a caveat or context key the profile needs but the grant or call lacks escalates', () => {
    expect(floorDecision(g({ caveats: [] }), call, p())).toBe('escalate');
    expect(floorDecision(g(), { context: [] }, p())).toBe('escalate');
    expect(floorDecision(g({ caveats: ['window', 'amount_cap'] }), { context: ['revocable', 'idempotency'] }, p())).toBe('allow');
    expect(floorDecision(g(), call, p({ caveats: [], context: [] }))).toBe('allow');
  });
});

describe('pinned digests (the cross-language contract)', () => {
  it('trait registry, tables, a def and the builtin pack root', () => {
    expect(traitsDigest(CORE_REGISTRY)).toBe('W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM');
    expect(tablesDigest()).toBe('I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU');
    expect(defDigest(BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!)).toBe('Xo7ApENRzJyi5iakmamfXyLK2S7-jBcDWk2dwARzONE');
    expect(packRoot(BUILTIN_DEFS.map(defDigest))).toBe('8uXEEHRmTzanUZ1baT1PFO7u2E4NQdTrtjoZUVO-CHo');
    expect(PACK_DIGEST_DOMAIN).toBe('atlas-pca/action-pack/v1');
  });
  it('the registry digest is order independent and changes with any floor', () => {
    const defs = [...CORE_TRAIT_DEFS].reverse();
    expect(traitsDigest(buildRegistry(defs as TraitDef[], { core: true }))).toBe(traitsDigest(CORE_REGISTRY));
    const changed = CORE_TRAIT_DEFS.map((t) => (t.id === 'pca.bulk' ? { ...t, floor: { ...t.floor, risk: 3 } } : t));
    expect(traitsDigest(buildRegistry(changed as TraitDef[], { core: true }))).not.toBe(traitsDigest(CORE_REGISTRY));
    const phrase = CORE_TRAIT_DEFS.map((t) => (t.id === 'pca.bulk' ? { ...t, card_phrase: 'x' } : t));
    expect(traitsDigest(buildRegistry(phrase as TraitDef[], { core: true }))).not.toBe(traitsDigest(CORE_REGISTRY));
  });
});
