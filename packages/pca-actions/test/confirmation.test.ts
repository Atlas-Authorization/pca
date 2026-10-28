// Unconfirmed means maximally dangerous (rule 22 side): a v2 verb counts as human-confirmed only with a valid signed confirmation
// by a PINNED reviewer key. Every other verb must carry every trait of the registry and floors at least the floor of that set; a
// schema that claims fewer traits for it is refused. Forged / unpinned / stale / mis-roled confirmations are all "unconfirmed".
import { generateKeyPair, b64u } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_DEFS, CORE_REGISTRY, RULE22_ENGINE, extendRegistry, floorOf, schemaFloorError, signReview, toSchemaDoc, toSchemaVerb, topTraits, traitsDigest, factsDigest, schemaVerbFloorError, verbConfirmationError, defDigest,
  type ActionDef, type ReviewerPins,
} from '../src';
import { TEST_PINS, TEST_REVIEWER, TEST_TS, confirmed, testReview } from './reviewed';

const refund = BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!;
const meta = { site: 'https://pay.example', aud: 'pay', version: '1' };
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const docOf = (defs: ActionDef[], opts = testReview()) => toSchemaDoc(defs, CORE_REGISTRY, meta, opts) as unknown as { verbs: Record<string, any>[]; [k: string]: unknown };
const top = topTraits(CORE_REGISTRY);

describe('what a schema built from a def carries', () => {
  it('an unconfirmed def becomes a verb with EVERY trait and the top floors, and no confirmation', () => {
    const v = toSchemaVerb(refund, CORE_REGISTRY).verb;
    expect(v.traits).toEqual(top);
    expect(v.confirmation).toBeUndefined();
    expect(v.floors).toMatchObject({ risk: 3, rev: 'irreversible', blast_ppm: 1_000_000, esc: 3 });
    expect(schemaFloorError({ verbs: [v] }, undefined)).toBeNull();
    expect(schemaFloorError({ verbs: [v] }, TEST_PINS)).toBeNull();
  });
  it('a confirmed def carries its real traits and the signed confirmation', () => {
    const v = toSchemaVerb(confirmed(refund), CORE_REGISTRY, testReview()).verb;
    expect(v.traits).toEqual(['pca.irreversible', 'pca.money_moving']);
    expect(v.confirmation?.reviewer_kid).toBe(TEST_REVIEWER.kid);
    expect(v.floors!.esc).toBe(2);
    expect(schemaFloorError({ verbs: [v] }, TEST_PINS)).toBeNull();
  });
});

describe('rule 22 integrity: a verb without a valid confirmation is refused if it carries fewer traits', () => {
  const honest = () => docOf([confirmed(refund)]);
  const err = (doc: { verbs: unknown[] }, pins: ReviewerPins | undefined = TEST_PINS) => schemaFloorError(doc as never, pins);
  it('the control: the honest confirmed document passes with the reviewer pinned', () => {
    expect(err(honest())).toBeNull();
    expect(RULE22_ENGINE.schemaError(honest(), TEST_PINS)).toBeNull();
  });
  it('the same document is refused when no reviewer is pinned (nothing is confirmed)', () => {
    expect(schemaFloorError(honest() as never, undefined)).toMatch(/^stripe\.refund: schema_traits_forged: unconfirmed action must carry every trait/);
    expect(err(honest(), { keys: [] })).toMatch(/schema_traits_forged: unconfirmed/);
    expect(RULE22_ENGINE.schemaError(honest())).toMatch(/schema_traits_forged: unconfirmed/);
  });
  it('dropping the confirmation from a document that claims the reviewed traits is refused', () => {
    const d = honest();
    delete d.verbs[0]!.confirmation;
    expect(err(d)).toMatch(/schema_traits_forged: unconfirmed/);
  });
  it('an unconfirmed def whose schema claims low machine traits and floors is refused', () => {
    const d = docOf([refund]);
    d.verbs[0]!.traits = ['pca.money_moving', 'pca.irreversible'];
    d.verbs[0]!.floors = { ...floorOf(CORE_REGISTRY, d.verbs[0]!.traits) };
    expect(err(d)).toMatch(/schema_traits_forged: unconfirmed/);
    // all the traits but floors lowered
    const e = docOf([refund]);
    e.verbs[0]!.floors = { ...e.verbs[0]!.floors, esc: 0, risk: 0 };
    expect(err(e)).toMatch(/schema_floor_forged/);
  });
  it('an unconfirmed verb missing a single trait is refused, naming it', () => {
    for (const t of top) {
      const d = docOf([refund]);
      d.verbs[0]!.traits = d.verbs[0]!.traits.filter((x: string) => x !== t);
      expect(err(d), t).toMatch(/schema_traits_forged: (missing implied trait|unconfirmed action must carry every trait)/);
    }
  });

  const tamper = (f: (c: Record<string, any>, v: Record<string, any>) => void) => {
    const d = honest();
    f(d.verbs[0]!.confirmation, d.verbs[0]!);
    return err(d);
  };
  it('a forged signature, a stale def digest, a stale registry digest and an altered trait list are all unconfirmed', () => {
    expect(tamper((c) => { c.sig = 'A'.repeat(86); })).toMatch(/schema_traits_forged: unconfirmed/);
    expect(tamper((c, v) => { v.def = 'B'.repeat(43); })).toMatch(/schema_traits_forged: unconfirmed/);
    expect(tamper((c) => { c.traits_digest = 'C'.repeat(43); })).toMatch(/schema_traits_forged: unconfirmed/);
    expect(tamper((c) => { c.final_traits = ['pca.bulk', ...c.final_traits].sort(); })).toMatch(/schema_traits_forged: unconfirmed/);
    expect(tamper((c) => { c.dismissed = [{ trait: 'pca.destructive', reason: 'x' }]; })).toMatch(/schema_traits_forged: unconfirmed/);
    expect(tamper((c) => { c.ts += 1; })).toMatch(/schema_traits_forged: unconfirmed/);
    expect(tamper((c) => { c.reviewer_kid = 'someone-else'; })).toMatch(/schema_traits_forged: unconfirmed/);
  });
  it('a confirmation by an unpinned key, a machine key or a key outside its validity window is unconfirmed', () => {
    const other = generateKeyPair();
    const v = docOf([confirmed(refund)]).verbs[0] as never;
    const sign = (kid: string, secret: Uint8Array, ts = TEST_TS) => signReview({ def_digest: defDigest(refund), traits_digest: traitsDigest(CORE_REGISTRY), facts_digest: factsDigest(toSchemaVerb(refund, CORE_REGISTRY).verb), final_traits: [], dismissed: [], reviewer_kid: kid, ts }, secret);
    const withConf = (c: unknown) => ({ ...(v as object), confirmation: c });
    const pk = (k: { publicKey: Uint8Array }) => b64u(k.publicKey);
    // sanity: the same body signed by the pinned reviewer is fine
    expect(verbConfirmationError(withConf(sign(TEST_REVIEWER.kid, TEST_REVIEWER.secret)) as never, CORE_REGISTRY, TEST_PINS)).toBeNull();
    expect(verbConfirmationError(withConf(sign('rev-x', other.secretKey)) as never, CORE_REGISTRY, TEST_PINS)).toMatch(/no pinned key/);
    const machine: ReviewerPins = { keys: [{ kid: 'imp', pk: pk(other), roles: ['importer'] }] };
    expect(verbConfirmationError(withConf(sign('imp', other.secretKey)) as never, CORE_REGISTRY, machine)).toMatch(/does not hold the reviewer role/);
    const late: ReviewerPins = { keys: [{ ...TEST_PINS.keys[0]!, not_after: TEST_TS - 1 }] };
    expect(verbConfirmationError(withConf(sign(TEST_REVIEWER.kid, TEST_REVIEWER.secret)) as never, CORE_REGISTRY, late)).toMatch(/outside the key validity/);
    expect(verbConfirmationError(withConf(undefined) as never, CORE_REGISTRY, TEST_PINS)).toBe('no confirmation');
  });
  it('a confirmation lifted from another action does not transfer (it covers a different def digest)', () => {
    const other = BUILTIN_DEFS.find((d) => d.verb === 'stripe.charge')!;
    const stolen = docOf([confirmed(other)]).verbs[0]!.confirmation;
    const d = docOf([refund]);
    d.verbs[0]!.confirmation = stolen;
    d.verbs[0]!.traits = ['pca.irreversible', 'pca.money_moving'];
    d.verbs[0]!.floors = floorOf(CORE_REGISTRY, d.verbs[0]!.traits);
    expect(err(d)).toMatch(/schema_traits_forged: unconfirmed/);
  });
  it('custom traits are part of the top: an unconfirmed verb must carry them too', () => {
    const custom = { id: 'acme.strict', implies: ['pca.money_moving'], floor: { ...CORE_REGISTRY.traits.get('pca.money_moving')!.floor, esc: 3 }, card_phrase: 'is stricter than money movement' };
    const reg = extendRegistry(CORE_REGISTRY, [custom]);
    const doc = toSchemaDoc([refund], reg, meta, {}) as unknown as { verbs: Record<string, any>[] };
    expect(doc.verbs[0]!.traits).toContain('acme.strict');
    expect(schemaFloorError(doc as never, TEST_PINS)).toBeNull();
    doc.verbs[0]!.traits = doc.verbs[0]!.traits.filter((t: string) => t !== 'acme.strict');
    expect(schemaFloorError(doc as never, TEST_PINS)).toMatch(/schema_traits_forged: unconfirmed/);
  });
});

describe('the confirmation applies only to the facts the reviewer saw', () => {
  const v0 = () => clone(toSchemaVerb(confirmed(refund), CORE_REGISTRY, testReview()).verb) as unknown as Record<string, any>;
  it('the facts digest ignores traits, floors, def and confirmation, and nothing else', () => {
    const v = v0();
    const d = factsDigest(v);
    expect(factsDigest({ ...v, traits: [], floors: {}, def: 'x', confirmation: undefined })).toBe(d);
    expect(factsDigest({ ...v, description: 'x' })).not.toBe(d);
    expect(factsDigest({ ...v, verb: 'stripe.other' })).not.toBe(d);
  });
  it('editing any fact after confirmation, or claiming another definition digest, makes the verb unconfirmed (top required)', () => {
    expect(verbConfirmationError(v0() as never, CORE_REGISTRY, TEST_PINS)).toBeNull();
    for (const f of [(v: any) => { v.params['action.params.amount'].max = 1; }, (v: any) => { v.description = 'x'; }, (v: any) => { v.reversibility = 'reversible'; }, (v: any) => { v.effects = ['pay', 'update']; }]) {
      const v = v0();
      f(v);
      expect(verbConfirmationError(v as never, CORE_REGISTRY, TEST_PINS)).toMatch(/facts differ/);
      expect(schemaVerbFloorError(v as never, CORE_REGISTRY, TEST_PINS)).toMatch(/unconfirmed action must carry every trait/);
    }
    const charge = clone(toSchemaVerb(BUILTIN_DEFS.find((d) => d.verb === 'stripe.charge')!, CORE_REGISTRY).verb) as unknown as Record<string, any>;
    charge.def = v0().def;
    charge.confirmation = v0().confirmation;
    expect(verbConfirmationError(charge as never, CORE_REGISTRY, TEST_PINS)).toMatch(/facts differ/);
  });
});

describe('the decision half sees the floors of the verified document', () => {
  const grant = { caveats: ['amount_cap', 'count_cap', 'window'], max_esc: 3, preauth_esc: 2 };
  it('a confirmed verb is allowed with a grant that provides its floors; the same def unconfirmed is not', () => {
    const ctx = ['fresh_revocation', 'idempotency'];
    expect(RULE22_ENGINE.decide({ doc: docOf([confirmed(refund)]), verb: 'stripe.refund', grant, context: ctx })).toBe('allow');
    expect(RULE22_ENGINE.decide({ doc: docOf([refund]), verb: 'stripe.refund', grant, context: ctx })).toBe('escalate');
    // and with the strictest grant it needs a step-up the grant does not pre-authorize
    expect(RULE22_ENGINE.decide({ doc: docOf([refund]), verb: 'stripe.refund', grant: { ...grant, max_esc: 2 }, context: ctx })).toBe('deny');
  });
});
