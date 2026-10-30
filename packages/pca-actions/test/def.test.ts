import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_DEFS, CORE_REGISTRY, defDigest, effective, idMatches, idPatternContains, idPatternError, normalize, packProof, packRoot, prulesViolations, hintTraits, topTraits, traitsOf, validateDef, verifyPackProof,
  traitsDigest, type ActionDef, type IdPattern,
} from '../src';
import { arbDef } from './arb';
import { runs } from './runs';
import { TEST_PINS, TEST_REVIEWER, confirmed, eff, testReview } from './reviewed';

const base = (): ActionDef => ({
  v: 1, kind: 'pca-action-def', verb: 'acme.invoice.send', title: 'Send an invoice', effects: ['send'],
  resource: { type: 'acme.invoice', id: { prefix: 'inv_', class: 'alnum', len: [8, 32] }, scope: 'one' },
  params: {
    invoice: { type: 'string', role: 'id.acme.invoice', max_len: 64 },
    to: { type: 'string', role: 'contact.email', format: 'email', tags: ['pii'], max_len: 254 },
    note: { type: 'string', max_len: 500 },
  },
  review: { state: 'authored' },
});

describe('validateDef', () => {
  it('accepts the base def, every builtin and every generated def', () => {
    expect(validateDef(base())).toBeNull();
    for (const d of BUILTIN_DEFS) expect(validateDef(d), d.verb).toBeNull();
    fc.assert(fc.property(arbDef, (d) => validateDef(d) === null), { seed: 21, numRuns: runs(5000) });
  });
  const mut = (f: (d: Record<string, any>) => void): unknown => { const d = JSON.parse(JSON.stringify(base())); f(d); return d; };
  const cases: [string, unknown, RegExp][] = [
    ['unknown member', mut((d) => { d.extra = 1; }), /unknown member 'extra'/],
    ['wrong version', mut((d) => { d.v = 2; }), /version/],
    ['bad verb (one segment)', mut((d) => { d.verb = 'send'; }), /verb must be/],
    ['bad verb (uppercase)', mut((d) => { d.verb = 'Acme.invoice.send'; }), /verb must be/],
    ['empty effects', mut((d) => { d.effects = []; }), /effects/],
    ['unknown effect', mut((d) => { d.effects = ['teleport']; }), /effects/],
    ['float in default', mut((d) => { d.params.note.default = 1.5; }), /safe integers/],
    ['negative zero', mut((d) => { d.params.note.default = -0; }), /safe integers/],
    ['unsafe integer', mut((d) => { d.params.note.default = 2 ** 60; }), /safe integers/],
    ['lone surrogate', mut((d) => { d.title = 'bad \ud800'; }), /lone surrogate/],
    ['non-NFC', mut((d) => { d.title = 'é'; }), /NFC/],
    ['reserved param name', mut((d) => { d.params['constructor'] = { type: 'boolean' }; }), /reserved/],
    ['param depth 4', mut((d) => { d.params['a.b.c.d'] = { type: 'boolean' }; }), /malformed/],
    ['param is parent of another', mut((d) => { d.params['a'] = { type: 'boolean' }; d.params['a.b'] = { type: 'boolean' }; }), /parent/],
    ['role mismatch (money on string)', mut((d) => { d.params.note.role = 'money.amount'; }), /requires an integer/],
    ['unknown role', mut((d) => { d.params.note.role = 'nope'; }), /unknown role/],
    ['unknown format', mut((d) => { d.params.note.format = 'wat'; }), /format/],
    ['unit on a string', mut((d) => { d.params.note.unit = { kind: 'count' }; }), /integer/],
    ['currency ref to missing param', mut((d) => { d.params.n = { type: 'integer', unit: { kind: 'money', ccy: { from: 'zzz' }, exp: 2 } }; }), /ccy.from/],
    ['min > max', mut((d) => { d.params.n = { type: 'integer', min: 5, max: 1 }; }), /min > max/],
    ['idempotency key_param without param', mut((d) => { d.idempotency = { mode: 'key_param' }; }), /idempotency/],
    ['idempotency param undeclared', mut((d) => { d.idempotency = { mode: 'key_param', param: 'nope' }; }), /idempotency/],
    ['reversibility.by undeclared', mut((d) => { d.reversibility = { by: 'nope', map: { x: 'reversible' } }; }), /reversibility.by/],
    ['blast ppm too big', mut((d) => { d.blast = { radius: 'one', ppm: 2_000_000 }; }), /blast.ppm/],
    ['resource id regex-ish object', mut((d) => { d.resource.id = { regex: '.*' }; }), /resource.id/],
    ['uuid with prefix', mut((d) => { d.resource.id = { prefix: 'x', class: 'uuid', len: [36, 36] }; }), /uuid/],
    ['duplicate aliases', mut((d) => { d.aliases = ['a', 'a']; }), /aliases/],
    ['alias equals verb', mut((d) => { d.aliases = ['acme.invoice.send']; }), /aliases/],
    ['unknown binding kind', mut((d) => { d.bindings = { smtp: { host: 'x' } }; }), /bindings/],
    ['review state', mut((d) => { d.review = { state: 'maybe' }; }), /review/],
    ['missing review', mut((d) => { delete d.review; }), /review/],
    ['too many params', mut((d) => { for (let i = 0; i < 70; i++) d.params['q' + i] = { type: 'boolean' }; }), /parameters/],
    ['not an object', [], /object/],
  ];
  for (const [name, doc, re] of cases) it(`rejects: ${name}`, () => expect(validateDef(doc)).toMatch(re));
});

describe('normalize and defDigest', () => {
  it('two authoring forms of one action have one digest', () => {
    const a = base();
    const b: ActionDef = JSON.parse(JSON.stringify(base()));
    b.effects = ['send'];
    b.params = { note: a.params.note!, to: { ...a.params.to!, tags: ['pii'], required: true }, invoice: a.params.invoice! }; // key order + explicit default
    b.traits = [];
    b.aliases = [];
    b.blast = { radius: 'one' }; // the scope default made explicit
    b.reversibility = 'irreversible'; // the fail-closed default made explicit
    b.idempotency = { mode: 'none' };
    expect(defDigest(a)).toBe(defDigest(b));
    expect(normalize(a)).toEqual(normalize(b));
  });
  it('the digest changes for every semantic change and ignores review, examples, source and since', () => {
    const a = base();
    const d0 = defDigest(a);
    expect(defDigest({ ...a, review: { state: 'unreviewed' } })).toBe(d0);
    expect(defDigest({ ...a, since: '0.5.0', source: { kind: 'openapi', uri: 'u', spec_digest: 'x', licence: 'MIT' }, examples: [{ params: {}, expect: 'deny' }] })).toBe(d0);
    expect(defDigest({ ...a, effects: ['send', 'create'] })).not.toBe(d0);
    expect(defDigest({ ...a, title: 'Send invoice' })).not.toBe(d0);
    expect(defDigest({ ...a, traits: ['pca.bulk'] })).not.toBe(d0);
    expect(defDigest({ ...a, blast: { radius: 'tenant' } })).not.toBe(d0);
    expect(defDigest({ ...a, params: { ...a.params, note: { type: 'string', max_len: 501 } } })).not.toBe(d0);
    expect(defDigest({ ...a, aliases: ['x.y'] })).not.toBe(d0);
  });
  it('the digest is a pinned 43 character base64url value (cross-language contract)', () => {
    expect(defDigest(base())).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(traitsDigest(CORE_REGISTRY)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
  it('digests are stable under normalization for generated defs', () => {
    fc.assert(fc.property(arbDef, (d) => {
      const n = normalize(d);
      expect(normalize(n as unknown as ActionDef)).toEqual(n); // idempotent on the normalized form
      expect(defDigest(d)).toBe(defDigest(JSON.parse(JSON.stringify(d))));
    }), { seed: 22, numRuns: runs(5000) });
  });
  it('derives the sensitivity floor from role and tags and raises, never lowers', () => {
    const a = base();
    expect(normalize(a).params.to!.sensitivity).toBe('material');
    expect(normalize(a).params.note!.sensitivity).toBe('free');
    const s: ActionDef = { ...a, params: { ...a.params, note: { type: 'string', max_len: 5, sensitivity: 'critical' }, to: { ...a.params.to!, sensitivity: 'free' } } };
    expect(normalize(s).params.note!.sensitivity).toBe('critical');
    expect(normalize(s).params.to!.sensitivity).toBe('material');
    expect(normalize({ ...a, params: { k: { type: 'string', max_len: 9, role: 'credential.secret' } } }).params.k!.sensitivity).toBe('critical');
  });
});

describe('trait implication and effective profile (exact outcomes)', () => {
  it('send + pii + irreversible default => external_communication, pii_access, irreversible (the hello-world invoice)', () => {
    const e = eff(base());
    expect(e.traits).toEqual(['pca.external_communication', 'pca.irreversible', 'pca.pii_access']);
    expect(e.eff).toEqual({
      risk: 2, rev: 'irreversible', blast_ppm: 50_000, esc: 1,
      caveats: ['rate_cap', 'recipient_scope', 'resource_scope'], context: ['fresh_revocation'], prules: ['recipient_param_declared'],
    });
    expect(prulesViolations(base(), e.eff.prules)).toEqual([]);
  });
  it('a stripe refund is cosign-tier, bounded and money-moving', () => {
    const e = eff(BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!);
    expect(e.traits).toEqual(['pca.irreversible', 'pca.money_moving']);
    expect(e.eff.esc).toBe(2);
    expect(e.eff.risk).toBe(3);
    // the reviewed declaration (the old catalog's 0.9 money preset, kept exactly) joined with the 700k money floor
    expect(e.eff.blast_ppm).toBe(900_000);
    expect(e.eff.caveats).toEqual(['amount_cap', 'count_cap', 'window']);
  });
  it('a declared value below its floor is clamped and flagged', () => {
    const d: ActionDef = { ...base(), effects: ['pay'], reversibility: 'reversible', blast: { radius: 'one' } };
    const e = eff(d);
    expect(e.eff.rev).toBe('rate_limited');
    expect(e.eff.blast_ppm).toBe(700_000);
    expect(e.clamps).toEqual([{ field: 'rev', declared: 'reversible', floor: 'rate_limited' }, { field: 'blast_ppm', declared: 50_000, floor: 700_000 }]);
  });
  it('without a valid signed confirmation the effective traits are the TOP of the registry, whatever the def says', () => {
    const a = base();
    const top = topTraits(CORE_REGISTRY);
    expect(top).toEqual(expect.arrayContaining(['pca.money_moving', 'pca.destructive', 'pca.irreversible', 'pca.external_communication', 'pca.code_execution', 'pca.privilege_change', 'pca.data_export', 'pca.financial_data_read', 'pca.credential_access', 'pca.public_exposure', 'pca.bulk', 'pca.unreviewed']));
    for (const state of ['authored', 'unreviewed', 'suggested', 'confirmed'] as const) {
      expect(traitsOf({ ...a, review: { state } }, CORE_REGISTRY), state).toEqual(top);
      expect(traitsOf({ ...a, review: { state } }, CORE_REGISTRY, { attestationVerified: () => false }), state).toEqual(top);
    }
    // a read-only def whose machine traits are empty is still the top
    const quiet: ActionDef = { ...a, effects: ['read'], traits: [] };
    expect(hintTraits(quiet)).not.toContain('pca.money_moving');
    const e = effective(quiet, CORE_REGISTRY);
    expect(e.confirmed).toBe(false);
    expect(e.traits).toEqual(top);
    expect(e.closure).toEqual(top);
    expect(e.eff).toMatchObject({ risk: 3, rev: 'irreversible', blast_ppm: 1_000_000, esc: 3 });
    expect(e.eff.caveats).toEqual(expect.arrayContaining(['approval_ref', 'resource_scope', 'amount_cap', 'recipient_scope']));
    expect(e.eff.context).toEqual(expect.arrayContaining(['dry_run_first', 'sandbox_attested', 'idempotency']));
  });
  it('only a signed confirmation sets the traits, to exactly the declared set plus what the signed facts imply', () => {
    const a = base();
    const c = confirmed(a);
    const opts = testReview();
    expect(traitsOf(c, CORE_REGISTRY, opts)).toEqual(['pca.external_communication', 'pca.irreversible', 'pca.pii_access']);
    expect(traitsOf(c, CORE_REGISTRY, opts)).not.toContain('pca.unreviewed');
    // changing the def after signing makes the attestation stale: back to the top
    expect(traitsOf({ ...c, title: 'Another title that changes the digest' }, CORE_REGISTRY, opts)).toEqual(topTraits(CORE_REGISTRY));
    expect(TEST_PINS.keys[0]!.kid).toBe(TEST_REVIEWER.kid);
  });
  it('implies bulk from scope or an unbounded array, credential_access from a secret role, network_egress from url.target', () => {
    const a = base();
    expect(hintTraits({ ...a, resource: { ...a.resource, scope: 'tenant' } })).toContain('pca.bulk');
    expect(hintTraits({ ...a, params: { l: { type: 'array', items: 'string' } } })).toContain('pca.bulk');
    expect(hintTraits({ ...a, params: { l: { type: 'array', items: 'string', max_items: 3 } } })).not.toContain('pca.bulk');
    expect(hintTraits({ ...a, effects: ['read'], params: { k: { type: 'string', max_len: 8, role: 'credential.key' } } })).toContain('pca.credential_access');
    expect(hintTraits({ ...a, effects: ['read'], params: { u: { type: 'string', max_len: 8, role: 'url.target' } } })).toContain('pca.network_egress');
    expect(hintTraits({ ...a, effects: ['read'], params: { m: { type: 'integer', role: 'money.fee' } } })).toContain('pca.financial_data_read');
  });
  it('prules: each rule has a violating and a satisfying def', () => {
    const a = base();
    const pay: ActionDef = { ...a, effects: ['pay'], resource: { type: 'x.y', id: { exact: 'k' }, scope: 'one' }, params: { amount: { type: 'integer', role: 'money.amount' } } };
    expect(prulesViolations(pay)).toEqual(expect.arrayContaining(['money_has_currency', 'money_amount_bounded', 'pay_has_idempotency', 'recipient_param_declared']));
    const ok: ActionDef = { ...pay, idempotency: { mode: 'natural' }, params: { amount: { type: 'integer', role: 'money.amount', min: 1, max: 9, unit: { kind: 'money', ccy: 'EUR', exp: 2 } } } };
    expect(prulesViolations(ok, ['money_has_currency', 'money_amount_bounded', 'pay_has_idempotency'])).toEqual([]);
    const dyn: ActionDef = { ...ok, params: { amount: { type: 'integer', role: 'money.amount', min: 1, max: 9, unit: { kind: 'money', ccy: { from: 'ccy' }, exp: 2 } }, ccy: { type: 'string', role: 'money.currency', format: 'iso_currency', max_len: 3 } } };
    expect(prulesViolations(dyn, ['money_has_currency'])).toEqual([]);
    expect(prulesViolations({ ...dyn, params: { ...dyn.params, ccy: { type: 'string', role: 'money.currency', max_len: 3 } } }, ['money_has_currency'])).toEqual(['money_has_currency']);
    expect(prulesViolations({ ...a, effects: ['delete'], resource: { type: 'x.y', id: '*', scope: 'one' } }, ['id_not_wildcard'])).toEqual(['id_not_wildcard']);
    expect(prulesViolations({ ...a, effects: ['delete'], resource: { type: 'x.y', id: '*', scope: 'set' } }, ['id_not_wildcard'])).toEqual([]);
    expect(prulesViolations({ ...a, params: { l: { type: 'array', items: 'string' } } }, ['array_bounded'])).toEqual(['array_bounded']);
    expect(prulesViolations({ ...a, params: { k: { type: 'string', max_len: 4, role: 'credential.token' } } }, ['secret_not_logged'])).toEqual(['secret_not_logged']);
    expect(prulesViolations({ ...a, params: { k: { type: 'string', max_len: 4, role: 'credential.token', tags: ['secret'] } } }, ['secret_not_logged'])).toEqual([]);
    expect(prulesViolations({ ...a, effects: ['export'], resource: { type: 'x.y', id: '*', scope: 'set' } }, ['export_bounded'])).toEqual(['export_bounded']);
    expect(prulesViolations({ ...a, effects: ['export'], resource: { type: 'x.y', id: '*', scope: 'set' }, params: { n: { type: 'integer', role: 'count.limit', min: 1, max: 100 } } }, ['export_bounded'])).toEqual([]);
  });
});

describe('resource id patterns', () => {
  it('validates, matches and decides containment', () => {
    expect(idPatternError('*')).toBeNull();
    expect(idPatternError({ prefix: 'inv_', class: 'alnum', len: [8, 32] })).toBeNull();
    expect(idPatternError({ prefix: 'inv_', class: 'alnum', len: [9, 8] })).toMatch(/min > max/);
    expect(idPatternError({ prefix: 'bad prefix', class: 'alnum', len: [1, 2] })).toMatch(/prefix/);
    const inv: IdPattern = { prefix: 'inv_', class: 'alnum', len: [8, 32] };
    expect(idMatches(inv, 'inv_abc12345')).toBe(true);
    expect(idMatches(inv, 'inv_ab')).toBe(false);
    expect(idMatches(inv, 'xnv_abc12345')).toBe(false);
    expect(idMatches(inv, 'inv_abc-2345')).toBe(false);
    expect(idMatches({ prefix: '', class: 'uuid', len: [36, 36] }, '123e4567-e89b-12d3-a456-426614174000')).toBe(true);
    expect(idMatches({ prefix: '', class: 'uuid', len: [36, 36] }, '123E4567-e89b-12d3-a456-426614174000')).toBe(false);
    expect(idPatternContains('*', inv)).toBe(true);
    expect(idPatternContains(inv, '*')).toBe(false);
    expect(idPatternContains({ prefix: '', class: 'alnum', len: [1, 128] }, inv)).toBe(false); // '_' is not alnum
    expect(idPatternContains({ prefix: '', class: 'any_safe', len: [1, 128] }, inv)).toBe(true);
    expect(idPatternContains({ prefix: 'inv_', class: 'alnum', len: [8, 64] }, { prefix: 'inv_', class: 'digits', len: [10, 20] })).toBe(true);
    expect(idPatternContains({ prefix: 'inv_', class: 'alnum', len: [8, 16] }, { prefix: 'inv_', class: 'digits', len: [10, 20] })).toBe(false);
    expect(idPatternContains(inv, { prefix: 'inv_ab', class: 'alnum', len: [6, 26] })).toBe(true);
    expect(idPatternContains(inv, { exact: 'inv_abc12345' })).toBe(true);
    expect(idPatternContains({ exact: 'a' }, { exact: 'a' })).toBe(true);
    expect(idPatternContains({ exact: 'a' }, inv)).toBe(false);
  });
  it('containment implies match-set inclusion (sampled)', () => {
    const classes = ['digits', 'hex', 'alnum', 'slug', 'any_safe'] as const;
    const arbPat = fc.record({ prefix: fc.constantFrom('', 'a', 'a_', 'ab'), class: fc.constantFrom(...classes), len: fc.tuple(fc.integer({ min: 1, max: 6 }), fc.integer({ min: 0, max: 4 })).map(([a, b]) => [a, a + b] as [number, number]) });
    const arbId = fc.string({ unit: fc.constantFrom(...'ab01_-.xZ'.split('')), maxLength: 12 });
    fc.assert(fc.property(arbPat, arbPat, arbId, (outer, inner, id) => {
      if (idPatternContains(outer, inner) && idMatches(inner, id)) expect(idMatches(outer, id)).toBe(true);
    }), { seed: 23, numRuns: runs(50_000) });
  });
});

describe('pack root and inclusion proofs', () => {
  it('roots are order independent, proofs verify, and a wrong digest or root does not', () => {
    const ds = BUILTIN_DEFS.map(defDigest);
    const root = packRoot(ds);
    expect(packRoot([...ds].reverse())).toBe(root);
    for (const d of ds) expect(verifyPackProof(root, packProof(ds, d), d)).toBe(true);
    expect(verifyPackProof(root, packProof(ds, ds[0]!), ds[1]!)).toBe(false);
    expect(verifyPackProof(packRoot(ds.slice(1)), packProof(ds, ds[0]!), ds[0]!)).toBe(false);
    expect(() => packRoot([ds[0]!, ds[0]!])).toThrow(/twice/);
    expect(() => packRoot([])).toThrow(/at least one/);
    expect(() => packProof(ds, 'nope')).toThrow(/not in the pack/);
  });
});

describe('audience: resource satisfies recipient_param_declared', () => {
  const noRecipient = (): ActionDef => ({ ...base(), params: { invoice: base().params.invoice! }, effects: ['send'] });
  it('a send with no recipient param violates the rule unless the resource is the audience', () => {
    expect(prulesViolations(noRecipient(), ['recipient_param_declared'])).toEqual(['recipient_param_declared']);
    expect(prulesViolations({ ...noRecipient(), audience: 'resource' }, ['recipient_param_declared'])).toEqual([]);
  });
  it('audience is validated, digested, and only the value resource exists', () => {
    expect(validateDef({ ...noRecipient(), audience: 'resource' })).toBeNull();
    expect(validateDef({ ...noRecipient(), audience: 'everyone' })).toMatch(/audience/);
    expect(defDigest({ ...noRecipient(), audience: 'resource' })).not.toBe(defDigest(noRecipient()));
  });
});
