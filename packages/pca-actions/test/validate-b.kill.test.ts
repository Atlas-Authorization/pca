import { describe, expect, it } from 'vitest';
import { MAX_TITLE_BYTES, isReadOnly, validateDef } from '../src';

type Obj = Record<string, unknown>;

const base = (): Obj => ({
  v: 1, kind: 'pca-action-def', verb: 'acme.invoice.send', title: 'Send an invoice', effects: ['send'],
  resource: { type: 'acme.invoice', id: { prefix: 'inv_', class: 'alnum', len: [8, 32] }, scope: 'one' },
  params: {
    invoice: { type: 'string', role: 'id.acme.invoice', max_len: 64 },
    to: { type: 'string', role: 'contact.email', format: 'email', tags: ['pii'], max_len: 254 },
    note: { type: 'string', max_len: 500 },
  },
  review: { state: 'authored' },
});
const err = (patch: Obj): string | null => validateDef({ ...base(), ...patch });
const without = (o: Obj, key: string): Obj => Object.fromEntries(Object.entries(o).filter(([k]) => k !== key));
// not a plain object (an array) yet carries the given members: shape checks that only look at keys cannot tell it apart
const arrayWith = (o: Obj): Obj => Object.assign([] as unknown[], o);
const traitIds = (n: number): string[] => Array.from({ length: n }, (_, i) => `a.t${i}`);

describe('validateDef: base', () => {
  it('accepts the base def', () => {
    expect(validateDef(base())).toBeNull();
  });
});

describe('validateDef: review provenance', () => {
  const MSG = (k: string): string => `review.provenance.${k} must be a list of at most 32 distinct trait ids`;
  const prov = (p: unknown): string | null => err({ review: { state: 'authored', provenance: p } });
  it('must be an object', () => {
    expect(prov('x')).toBe('review.provenance must be an object');
    expect(prov([])).toBe('review.provenance must be an object');
  });
  it('knows union and adjudicated only', () => {
    expect(prov({ union: ['a.b'] })).toBeNull();
    expect(prov({ adjudicated: ['a.b'] })).toBeNull();
    expect(prov({ other: [] })).toBe("review.provenance: unknown member 'other'");
  });
  it('each list is a bounded list of distinct trait ids', () => {
    expect(prov({ union: 'x' })).toBe(MSG('union'));
    expect(prov({ adjudicated: traitIds(33) })).toBe(MSG('adjudicated'));
    expect(prov({ adjudicated: traitIds(32) })).toBeNull();
    expect(prov({ union: ['a.b', 'BAD'] })).toBe(MSG('union'));
    expect(prov({ union: [['a.b']] })).toBe(MSG('union'));
    expect(prov({ union: ['Xa.b'] })).toBe(MSG('union'));
    expect(prov({ union: ['a.b!'] })).toBe(MSG('union'));
    expect(prov({ union: ['a.b.c'] })).toBeNull();
    expect(prov({ union: ['a.b', 'a.b'] })).toBe(MSG('union'));
  });
});

describe('validateDef: review attestation', () => {
  const att = (patch: Obj = {}): Obj => ({
    def_digest: 'd', traits_digest: 't', facts_digest: 'f', final_traits: [], dismissed: [], reviewer_kid: 'k', ts: 0, sig: 's', ...patch,
  });
  const rev = (a: unknown): string | null => err({ review: { state: 'authored', attestation: a } });
  const REQ = 'review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required';
  const DIS = 'review.attestation.dismissed must be {trait, reason} entries';
  const dis = (...entries: unknown[]): string | null => rev(att({ dismissed: entries }));
  it('accepts a full attestation and one without a sig', () => {
    expect(rev(att())).toBeNull();
    expect(rev(without(att(), 'sig'))).toBeNull();
    expect(rev(att({ final_traits: ['a.b'], dismissed: [{ trait: 'a.c', reason: 'r' }] }))).toBeNull();
  });
  it('must be an object with known members only', () => {
    expect(rev('x')).toBe('review.attestation must be an object');
    expect(rev(att({ zz: 1 }))).toBe("review.attestation: unknown member 'zz'");
  });
  it('requires each of its fields', () => {
    for (const k of ['def_digest', 'traits_digest', 'facts_digest', 'reviewer_kid', 'ts']) expect(rev(without(att(), k)), k).toBe(REQ);
    expect(rev(att({ ts: -1 }))).toBe(REQ);
    expect(rev(att({ ts: 'x' }))).toBe(REQ);
  });
  it('final_traits are distinct trait ids', () => {
    expect(rev(att({ final_traits: ['bad'] }))).toBe('review.attestation.final_traits must be distinct trait ids');
  });
  it('dismissed entries are exactly {trait, reason}', () => {
    expect(dis({ trait: 'a.b', reason: 'r' })).toBeNull();
    expect(rev(att({ dismissed: 'x' }))).toBe(DIS);
    expect(rev(att({ dismissed: traitIds(33).map((trait) => ({ trait, reason: 'r' })) }))).toBe(DIS);
    expect(rev(att({ dismissed: traitIds(32).map((trait) => ({ trait, reason: 'r' })) }))).toBeNull();
    expect(dis('x')).toBe(DIS);
    expect(dis({ trait: 'a.b' })).toBe(DIS);
    expect(dis(arrayWith({ trait: 'a.b', reason: 'r' }))).toBe(DIS);
    expect(dis({ trait: 'a.b', reason: 'r', extra: 1 })).toBe(DIS);
    expect(dis({ trait: ['a.b'], reason: 'r' })).toBe(DIS);
    expect(dis({ trait: 'BAD', reason: 'r' })).toBe(DIS);
    expect(dis({ trait: 'a.b', reason: '' })).toBe(DIS);
    expect(dis({ trait: 'a.b', reason: 'r' }, { trait: 'BAD', reason: 'r' })).toBe(DIS);
  });
  it('sig is a non-empty string when present', () => {
    expect(rev(att({ sig: '' }))).toBe('review.attestation.sig must be a string');
    expect(rev(att({ sig: 5 }))).toBe('review.attestation.sig must be a string');
  });
});

describe('validateDef: head members', () => {
  it('kind, title and scope refusals carry their own text', () => {
    expect(err({ kind: 'x' })).toBe("kind must be 'pca-action-def'");
    expect(err({ title: '' })).toBe(`title must be a non-empty string up to ${MAX_TITLE_BYTES} bytes`);
    expect(err({ title: 'a'.repeat(MAX_TITLE_BYTES + 1) })).toBe(`title must be a non-empty string up to ${MAX_TITLE_BYTES} bytes`);
    expect(err({ title: 'a'.repeat(MAX_TITLE_BYTES) })).toBeNull();
    const r = base().resource as Obj;
    expect(err({ resource: { ...r, scope: 'galaxy' } })).toBe('resource.scope is not a scope');
  });
  it('aliases are verb-shaped, within the byte bound and not the verb', () => {
    const MSG = 'aliases must be distinct verb-shaped names other than the verb';
    const a = (n: number): string => ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32), 'd'.repeat(n)].join('.');
    expect(err({ aliases: ['acme.invoice.mail'] })).toBeNull();
    expect(err({ aliases: ['Bad'] })).toBe(MSG);
    expect(err({ aliases: [a(29)] })).toBeNull();
    expect(err({ aliases: [a(30)] })).toBe(MSG);
    expect(err({ aliases: ['acme.invoice.send'] })).toBe(MSG);
    const names = (n: number): string[] => Array.from({ length: n }, (_, i) => `a${i}`);
    expect(err({ aliases: names(16) })).toBeNull();
    expect(err({ aliases: names(17) })).toBe(MSG);
    // not strings, though each prints as an alias-shaped name
    expect(err({ aliases: [true] })).toBe(MSG);
    expect(err({ aliases: [['mail']] })).toBe(MSG);
  });
});

describe('validateDef: reversibility', () => {
  const MAP = 'reversibility.map must map values to reversibility classes';
  const rv = (o: Obj): string | null => err({ reversibility: { by: 'note', map: { x: 'reversible' }, ...o } });
  const entries = (n: number): Obj => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, 'reversible']));
  it('class and unknown class', () => {
    expect(err({ reversibility: 'irreversible' })).toBeNull();
    expect(err({ reversibility: 'bogus' })).toBe('unknown reversibility class');
  });
  it('object form shape', () => {
    const SHAPE = 'reversibility must be a class or {by, map, default?}';
    expect(err({ reversibility: 5 })).toBe(SHAPE);
    expect(rv({ extra: 1 })).toBe(SHAPE);
    expect(rv({})).toBeNull();
    expect(rv({ default: 'irreversible' })).toBeNull();
    expect(rv({ default: 'bogus' })).toBe('reversibility.default is not a class');
    expect(rv({ by: 'zzz' })).toBe('reversibility.by must name a declared parameter');
    expect(rv({ by: 5 })).toBe('reversibility.by must name a declared parameter');
  });
  it('map', () => {
    expect(rv({ map: ['reversible'] })).toBe(MAP);
    expect(rv({ map: {} })).toBe(MAP);
    expect(rv({ map: entries(257) })).toBe(MAP);
    expect(rv({ map: entries(256) })).toBeNull();
    expect(rv({ map: { x: 'bogus' } })).toBe(MAP);
    expect(rv({ map: { a: 'reversible', b: 'bogus' } })).toBe(MAP);
    expect(rv({ map: { '': 'reversible' } })).toBe(MAP);
    expect(rv({ map: { ['k'.repeat(129)]: 'reversible' } })).toBe(MAP);
  });
});

describe('validateDef: blast, side effects, idempotency', () => {
  const BLAST = 'blast must be {radius, ppm?}';
  const PPM = 'blast.ppm must be an integer in 0..1000000';
  const SIDE = 'side_effects must be {target, kind} entries';
  const IDEM = 'idempotency must be {mode, param?}';
  const IDEM_PARAM = 'idempotency.param is required for key_param (a declared parameter) and forbidden otherwise';
  const se = (...e: unknown[]): string | null => err({ side_effects: e });
  it('blast', () => {
    expect(err({ blast: { radius: 'one' } })).toBeNull();
    expect(err({ blast: 5 })).toBe(BLAST);
    expect(err({ blast: arrayWith({ radius: 'one' }) })).toBe(BLAST);
    expect(err({ blast: { radius: 'one', extra: 1 } })).toBe(BLAST);
    expect(err({ blast: { radius: 'galaxy' } })).toBe(BLAST);
    expect(err({ blast: { radius: 'one', ppm: 0 } })).toBeNull();
    expect(err({ blast: { radius: 'one', ppm: 1000000 } })).toBeNull();
    expect(err({ blast: { radius: 'one', ppm: 1000001 } })).toBe(PPM);
    expect(err({ blast: { radius: 'one', ppm: -1 } })).toBe(PPM);
    expect(err({ blast: { radius: 'one', ppm: '5' } })).toBe(PPM);
  });
  it('side effects', () => {
    const ok = { kind: 'send', target: 't' };
    expect(se(ok)).toBeNull();
    expect(err({ side_effects: 'x' })).toBe(SIDE);
    expect(err({ side_effects: Array.from({ length: 17 }, () => ok) })).toBe(SIDE);
    expect(err({ side_effects: Array.from({ length: 16 }, () => ok) })).toBeNull();
    expect(se(ok, { kind: 'teleport', target: 't' })).toBe(SIDE);
    expect(se('x')).toBe(SIDE);
    expect(se(arrayWith(ok))).toBe(SIDE);
    expect(se({ ...ok, extra: 1 })).toBe(SIDE);
    expect(se({ kind: 'send', target: '' })).toBe(SIDE);
    expect(se({ kind: 'teleport', target: 't' })).toBe(SIDE);
  });
  it('idempotency', () => {
    expect(err({ idempotency: { mode: 'none' } })).toBeNull();
    expect(err({ idempotency: { mode: 'key_param', param: 'note' } })).toBeNull();
    expect(err({ idempotency: 5 })).toBe(IDEM);
    expect(err({ idempotency: arrayWith({ mode: 'natural' }) })).toBe(IDEM);
    expect(err({ idempotency: { mode: 'natural', extra: 1 } })).toBe(IDEM);
    expect(err({ idempotency: { mode: 'bogus' } })).toBe(IDEM);
    expect(err({ idempotency: { mode: 'key_param' } })).toBe(IDEM_PARAM);
    expect(err({ idempotency: { mode: 'key_param', param: 'zzz' } })).toBe(IDEM_PARAM);
    expect(err({ idempotency: { mode: 'natural', param: 'note' } })).toBe(IDEM_PARAM);
  });
});

describe('validateDef: compensates, bindings, examples, source, since', () => {
  const EX = 'examples must be an array of up to 32 entries';
  const ONE = 'example must be {params, under?, expect}';
  const ex = (e: unknown): string | null => err({ examples: [e] });
  const SRC = 'source must be {kind, uri, spec_digest, licence, imported_at?}';
  const source = (patch: Obj = {}): Obj => ({ kind: 'k', uri: 'u', spec_digest: 'd', licence: 'l', ...patch });
  const src = (s: unknown): string | null => err({ source: s });
  it('compensates names a verb', () => {
    expect(err({ compensates: 'acme.invoice.void' })).toBeNull();
    expect(err({ compensates: 5 })).toBe('compensates must be a verb');
    expect(err({ compensates: ['acme.invoice.void'] })).toBe('compensates must be a verb');
    expect(err({ compensates: 'Bad' })).toBe('compensates must be a verb');
  });
  it('a sound bindings member does not end validation', () => {
    expect(err({ bindings: { mcp: { tool: 't' } } })).toBeNull();
    expect(err({ bindings: { mcp: { tool: 't' } }, since: 5 })).toBe('since must be a string');
  });
  it('examples', () => {
    const good = { params: {}, expect: 'allow' };
    expect(ex(good)).toBeNull();
    expect(ex({ params: {}, under: {}, expect: 'deny' })).toBeNull();
    expect(err({ examples: 'x' })).toBe(EX);
    expect(err({ examples: Array.from({ length: 33 }, () => good) })).toBe(EX);
    expect(err({ examples: Array.from({ length: 32 }, () => good) })).toBeNull();
    expect(ex('x')).toBe(ONE);
    expect(ex(arrayWith(good))).toBe(ONE);
    expect(ex({ ...good, extra: 1 })).toBe(ONE);
    expect(ex({ params: [], expect: 'allow' })).toBe(ONE);
    expect(ex({ params: {}, expect: 'maybe' })).toBe(ONE);
    expect(err({ examples: [good, { params: {}, expect: 'maybe' }] })).toBe(ONE);
  });
  it('source', () => {
    expect(src(source())).toBeNull();
    expect(src(source({ imported_at: 0 }))).toBeNull();
    expect(src(source({ imported_at: 5 }))).toBeNull();
    expect(src(source({ imported_at: -1 }))).toBe(SRC);
    expect(src(source({ imported_at: '5' }))).toBe(SRC);
    expect(src('x')).toBe(SRC);
    expect(src(arrayWith(source()))).toBe(SRC);
    expect(src(source({ extra: 1 }))).toBe(SRC);
    for (const k of ['kind', 'uri', 'spec_digest', 'licence']) {
      expect(src(source({ [k]: '' })), k).toBe(SRC);
      expect(src(without(source(), k)), k).toBe(SRC);
    }
  });
  it('since is a string', () => {
    expect(err({ since: '1.0' })).toBeNull();
    expect(err({ since: 5 })).toBe('since must be a string');
    expect(err({ since: '' })).toBe('since must be a string');
  });
});

describe('validateDef: members the first pass missed', () => {
  it('names an unknown review member', () => {
    expect(err({ review: { state: 'authored', zz: 1 } })).toBe("review: unknown member 'zz'");
  });
  it('description is a non-empty string when present', () => {
    expect(err({ description: 'd' })).toBeNull();
    expect(err({ description: '' })).toBe('description must be a string');
    expect(err({ description: 5 })).toBe('description must be a string');
  });
  it('resource shape and type', () => {
    const r = base().resource as Obj;
    const SHAPE = 'resource must be {type, id, scope}';
    expect(err({ resource: 5 })).toBe(SHAPE);
    expect(err({ resource: without(r, 'scope') })).toBe(SHAPE);
    expect(err({ resource: { ...r, extra: 1 } })).toBe(SHAPE);
    expect(err({ resource: { ...r, type: 'BAD' } })).toBe('resource.type is malformed');
    expect(err({ resource: { ...r, type: 5 } })).toBe('resource.type is malformed');
  });
  it('context keys are distinct and known', () => {
    expect(err({ context: ['dry_run_first', 'session_taint_max:web'] })).toBeNull();
    expect(err({ context: 'x' })).toBe('context must be distinct known context keys');
    expect(err({ context: ['zzz'] })).toBe('context must be distinct known context keys');
    expect(err({ context: ['dry_run_first', 'dry_run_first'] })).toBe('context must be distinct known context keys');
  });
  it('a member that throws is reported as a malformed def', () => {
    const d = base();
    Object.defineProperty(d, 'since', { enumerable: true, get: (): never => { throw new Error('boom'); } });
    expect(validateDef(d)).toBe('malformed def: boom');
  });
  it('isReadOnly needs at least one effect and only reads', () => {
    expect(isReadOnly([])).toBe(false);
    expect(isReadOnly(['read'])).toBe(true);
    expect(isReadOnly(['read', 'send'])).toBe(false);
  });
});
