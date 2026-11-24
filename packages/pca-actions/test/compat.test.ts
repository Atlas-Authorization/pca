import { CATALOG_REVERSIBILITY_SCORE, catalogRisk } from '@atlasauth/pca';
import { DEFAULT_CATALOG } from '@atlasauth/pca/ext/research';
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_DEFS, CORE_REGISTRY, LEGACY_CATALOG, LEGACY_ONTOLOGY_EFFECT, REV_RANK, RESOLUTIONS, blastOfFloat, effectClass, effective, facadeSpecs, fromCatalog, fromCatalogSpec, legacyOperationsClass,
  normalizeReversibility, unitTagOf, validateDef, type CatalogSpecLike,
} from '../src';

describe('the four reversibility vocabularies convert totally and fail closed', () => {
  it('maps every old word', () => {
    expect(['reversible', 'rate_limited', 'costly', 'irreversible', 'read', 'external_send'].map(normalizeReversibility))
      .toEqual(['reversible', 'rate_limited', 'rate_limited', 'irreversible', 'reversible', 'irreversible']);
    expect([undefined, null, 'weird', 7, {}].map(normalizeReversibility)).toEqual(Array(5).fill('irreversible'));
    expect((['reversible', 'rate_limited', 'irreversible'] as const).map(legacyOperationsClass)).toEqual(['reversible', 'costly', 'irreversible']);
  });
});

describe('the facade catalog is derived from the built-in defs; it differs from the recorded old catalog only by the settled resolutions', () => {
  it('the shipped catalog rows are exactly the derivation (the generated file never drifts)', () => {
    expect(DEFAULT_CATALOG.all()).toStrictEqual(facadeSpecs(BUILTIN_DEFS, CORE_REGISTRY, { reviewed: true }));
  });
  it('class: equal to the old catalog except where a resolution settled to the stricter class; blast: equal to the old preset', () => {
    const settled = new Set(RESOLUTIONS.filter((r) => r.field === 'reversibility' || r.field === 'traits').map((r) => r.verb));
    for (const [verb, legacy] of Object.entries(LEGACY_CATALOG)) {
      const spec = DEFAULT_CATALOG.get(verb)!;
      if (settled.has(verb)) expect(REV_RANK[spec.reversibility as keyof typeof REV_RANK], verb).toBeGreaterThan(REV_RANK[legacy.reversibility]);
      else expect(spec.reversibility, verb).toBe(legacy.reversibility);
      expect(spec.blastRadius, verb).toBe(legacy.blastRadius);
      // catalogRisk prices from the same rows: the class score, and the blast (a money verb without a kappa is the worst case)
      const r = catalogRisk(verb, {}, {} as never);
      expect(r.reversibility, verb).toBe(CATALOG_REVERSIBILITY_SCORE[spec.reversibility]);
      expect(r.blastRadius, verb).toBe(spec.amountField !== undefined ? 1 : legacy.blastRadius);
    }
  });
});

describe('the eight models agree on the built-ins (ActionDef is the single source)', () => {
  it('a built-in def is never weaker than the old catalog and is exactly the old ontology class where one exists', () => {
    expect(Object.keys(LEGACY_CATALOG).sort()).toEqual(BUILTIN_DEFS.map((d) => d.verb).sort());
    for (const d of BUILTIN_DEFS) {
      const e = effective(d, CORE_REGISTRY);
      expect(REV_RANK[e.eff.rev], d.verb).toBeGreaterThanOrEqual(REV_RANK[LEGACY_CATALOG[d.verb]!.reversibility]);
    }
    for (const [verb, cls] of Object.entries(LEGACY_ONTOLOGY_EFFECT)) expect(effectClass(BUILTIN_DEFS.find((d) => d.verb === verb)!), verb).toBe(cls);
  });
  it('the formerly disagreeing money verbs are settled to the stricter class and keep both names', () => {
    const by = (v: string) => BUILTIN_DEFS.find((d) => d.verb === v)!;
    expect(by('stripe.refund').reversibility).toBe('irreversible');
    expect(by('stripe.charge').reversibility).toBe('irreversible');
    expect(by('stripe.charge').aliases).toEqual(expect.arrayContaining(['charge_customer']));
    expect(by('stripe.refund').aliases).toEqual(expect.arrayContaining(['refund', 'issue_refund', 'reimburse']));
  });
  it('every resolution names a built-in verb or the wildcard', () => {
    const verbs = new Set(BUILTIN_DEFS.map((d) => d.verb));
    for (const r of RESOLUTIONS) expect(r.verb === '*' || verbs.has(r.verb), r.verb).toBe(true);
  });
});

describe('catalog shim', () => {
  const spec = (over: Partial<CatalogSpecLike>): CatalogSpecLike => ({ connector: 'acme', action: 'sync', verb: 'acme.sync', reversibility: 'reversible', blastRadius: 0.2, description: 'Sync things', ...over });
  it('converts a money entry to a bounded money.amount parameter with a key', () => {
    const d = fromCatalogSpec(spec({ action: 'payout', verb: 'acme.payout', amountField: 'amount', reversibility: 'irreversible', blastRadius: 0.9 }));
    expect(validateDef(d)).toBeNull();
    expect(d.effects).toEqual(['pay']);
    expect(d.params.amount).toMatchObject({ role: 'money.amount', unit: { kind: 'money', ccy: 'USD', exp: 2 }, min: 0 });
    expect(d.idempotency).toEqual({ mode: 'key_param', param: 'idempotency_key' });
    expect(d.blast).toEqual({ radius: 'global', ppm: 900_000 });
    expect(d.review.state).toBe('authored');
  });
  it('infers effects conservatively from the name and never calls an unknown write a read', () => {
    const eff = (action: string) => fromCatalogSpec(spec({ action, verb: `acme.${action}` })).effects;
    expect(eff('read')).toEqual(['read']);
    expect(eff('list_things')).toEqual(['read']);
    expect(eff('delete_event')).toEqual(['delete']);
    expect(eff('send')).toEqual(['send']);
    expect(eff('post_message')).toEqual(['send']);
    expect(eff('frobnicate')).toEqual(['update']);
    expect(fromCatalog([spec({}), spec({ action: 'x', verb: 'acme.x', resource: '*' })])).toHaveLength(2);
  });
  it('blast floats map to the smallest covering radius, rounding to integer ppm', () => {
    expect(blastOfFloat(0.05)).toEqual({ radius: 'one', ppm: 50_000 });
    expect(blastOfFloat(0.2)).toEqual({ radius: 'bounded', ppm: 200_000 });
    expect(blastOfFloat(0.5)).toEqual({ radius: 'tenant', ppm: 500_000 });
    expect(blastOfFloat(0.9)).toEqual({ radius: 'global', ppm: 900_000 });
    expect(blastOfFloat(1)).toEqual({ radius: 'global', ppm: 1_000_000 });
    expect(blastOfFloat(NaN)).toEqual({ radius: 'global', ppm: 1_000_000 });
    expect(blastOfFloat(-3)).toEqual({ radius: 'one', ppm: 0 });
  });
  it('unit tags are the schema unit entries and the envelope tags', () => {
    expect(unitTagOf({ kind: 'money', ccy: 'USD', exp: 2 })).toEqual({ kind: 'money', currency: 'USD', exponent: 2 });
    expect(unitTagOf({ kind: 'money', ccy: { from: 'c' }, exp: 2 })).toBeNull();
    expect(unitTagOf({ kind: 'bytes' })).toEqual({ kind: 'bytes' });
  });
});
