// arb.ts - fast-check generators shared by the property tests (every generated def is valid by construction).
import fc from 'fast-check';
import {
  BLAST_RADII, CAVEAT_KINDS, CONTEXT_KEYS, CORE_TRAIT_IDS, EFFECTS, PARAM_RULE_IDS, REVERSIBILITY, profile,
  type ActionDef, type ParamDef, type Profile, type TraitDef, type TraitId,
} from '../src';

export const arbProfile: fc.Arbitrary<Profile> = fc
  .record({
    risk: fc.integer({ min: 0, max: 3 }),
    rev: fc.constantFrom(...REVERSIBILITY),
    blast_ppm: fc.oneof(fc.integer({ min: 0, max: 1_000_000 }), fc.constantFrom(0, 50_000, 300_000, 700_000, 1_000_000)),
    esc: fc.integer({ min: 0, max: 3 }),
    caveats: fc.subarray([...CAVEAT_KINDS]),
    context: fc.subarray([...CONTEXT_KEYS]),
    prules: fc.subarray([...PARAM_RULE_IDS]),
  })
  .map((p) => profile(p));

export const arbCoreTraitSet: fc.Arbitrary<TraitId[]> = fc.subarray([...CORE_TRAIT_IDS]);

/** A custom trait over a base set of ids: either well formed (floor >= join of implies' floors) or deliberately weakened. */
export function arbCustomTraits(base: readonly TraitDef[]): fc.Arbitrary<TraitDef[]> {
  return fc.array(fc.tuple(arbProfile, fc.subarray(base.map((t) => t.id), { maxLength: 3 })), { maxLength: 4 }).map((rows) => {
    const out: TraitDef[] = [];
    rows.forEach(([own, implies], i) => {
      const all = [...base, ...out];
      const floor = implies.reduce((acc, id) => {
        const f = all.find((t) => t.id === id)!.floor;
        return profile({
          risk: Math.max(acc.risk, f.risk), rev: acc.rev === 'irreversible' || f.rev === 'irreversible' ? 'irreversible' : acc.rev === 'rate_limited' || f.rev === 'rate_limited' ? 'rate_limited' : 'reversible',
          blast_ppm: Math.max(acc.blast_ppm, f.blast_ppm), esc: Math.max(acc.esc, f.esc),
          caveats: [...acc.caveats, ...f.caveats], context: [...acc.context, ...f.context], prules: [...acc.prules, ...f.prules],
        });
      }, own);
      out.push({ id: `acme.t${i}`, implies, floor, card_phrase: `custom ${i}` });
    });
    return out;
  });
}

const arbParam: fc.Arbitrary<ParamDef> = fc.oneof(
  fc.record({ type: fc.constant('integer' as const), min: fc.constant(0), max: fc.integer({ min: 1, max: 1_000_000 }), role: fc.constantFrom(undefined, 'money.amount', 'count.limit') }).map((p) => clean(p) as unknown as ParamDef),
  fc.record({ type: fc.constant('string' as const), max_len: fc.constantFrom(16, 256, 4096), role: fc.constantFrom(undefined, 'contact.email', 'party.payee', 'credential.secret', 'text.message', 'path.fs'), tags: fc.subarray(['pii', 'phi', 'secret', 'free_text_outbound']) }).map((p) => clean(p) as unknown as ParamDef),
  fc.record({ type: fc.constant('array' as const), items: fc.constant('string'), max_items: fc.constantFrom(undefined, 8, 64) }).map((p) => clean(p) as unknown as ParamDef),
  fc.constant({ type: 'boolean' } as ParamDef),
);

function clean<T extends Record<string, unknown>>(o: T): T {
  for (const k of Object.keys(o)) if (o[k] === undefined) delete o[k];
  if (Array.isArray(o.tags) && o.tags.length === 0) delete o.tags;
  return o;
}

export const arbDef: fc.Arbitrary<ActionDef> = fc
  .record({
    n: fc.integer({ min: 0, max: 9999 }),
    effects: fc.subarray([...EFFECTS], { minLength: 1 }),
    scope: fc.constantFrom('one' as const, 'set' as const, 'tenant' as const, 'global' as const),
    id: fc.constantFrom<ActionDef['resource']['id']>('*', { exact: 'a1' }, { prefix: 'x_', class: 'alnum', len: [4, 24] }),
    params: fc.tuple(arbParam, arbParam, arbParam).chain(([a, b, c]) => fc.subarray([a, b, c])),
    reversibility: fc.constantFrom(undefined, ...REVERSIBILITY),
    blast: fc.option(fc.record({ radius: fc.constantFrom(...BLAST_RADII), ppm: fc.option(fc.integer({ min: 0, max: 1_000_000 }), { nil: undefined }) }), { nil: undefined }),
    context: fc.subarray([...CONTEXT_KEYS], { maxLength: 3 }),
    traits: fc.subarray([...CORE_TRAIT_IDS], { maxLength: 4 }),
    state: fc.constantFrom('authored' as const, 'unreviewed' as const, 'suggested' as const, 'confirmed' as const),
  })
  .map((r) => {
    const params: Record<string, ParamDef> = {};
    r.params.forEach((p, i) => (params[`p${i}`] = p));
    const blast = r.blast === undefined ? undefined : clean({ radius: r.blast.radius, ppm: r.blast.ppm });
    return clean({
      v: 1, kind: 'pca-action-def', verb: `t${r.n}.res.act`, title: 'Do a thing', effects: r.effects,
      resource: { type: 'x.res', id: r.id, scope: r.scope }, params,
      reversibility: r.reversibility, blast, context: r.context, traits: r.traits, review: { state: r.state },
    } as Record<string, unknown>) as unknown as ActionDef;
  });
