/**
 * Mutation-kill tests for prohibitions.ts: exact validation messages and limits, the monitor-state invariants,
 * canonical state / digest, every invariant form (boundaries, windows, reasons), the strict state transition (ledger
 * pruning/merging/overflow, latches, hash chain), safety evidence (build, sign, verify: every refusal reason), the
 * composition rule and the atomic check-and-advance kernel.
 */
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import type { ActionContext } from './predicates';
import {
  advanceState,
  advanceStateStrict,
  canonicalState,
  checkAndAdvance,
  checkProhibitions,
  composeAuthority,
  CONSTITUTION_SIG_DOMAIN,
  CONSTITUTION_VERSION,
  constitutionId,
  emptyState,
  EVIDENCE_VERSION,
  evidenceDigest,
  MAX_DEADLINE,
  MAX_INVARIANTS,
  MAX_LEDGER,
  proveSafety,
  safetyBindingId,
  SAFETY_EVIDENCE_SIG_DOMAIN,
  signConstitution,
  signSafetyEvidence,
  STATE_CHAIN_DOMAIN,
  STATE_DIGEST_DOMAIN,
  stateDigest,
  stateProblem,
  tickState,
  validateConstitution,
  validateInvariant,
  validateWhen,
  verifyConstitution,
  verifySafetyEvidence,
  verifySignedSafetyEvidence,
  whenAffirmative,
  whenMatches,
  type Constitution,
  type Invariant,
  type MonitorState,
  type ProhibitionEvidence,
  type SignedConstitution,
} from './prohibitions';
import { verifiedCoreOptIn } from './verified-core-mode';

const K = generateKeyPair();
const PRIN = encodeKey(K.publicKey);
const K2 = generateKeyPair();
const NOW = 1_700_000_000_000;
const SIGNER = generateKeyPair();
const SIGNER_PUB = encodeKey(SIGNER.publicKey);

const W = (verb: string | string[], extra: Record<string, unknown> = {}) => ({ verb, ...extra });
const act = (verb: string, resource = '/r', params?: Record<string, unknown>, extra: Record<string, unknown> = {}): ActionContext =>
  ({ action: { verb, resource, ...(params ? { params } : {}) }, ...extra }) as ActionContext;
const cons = (invariants: Invariant[]): Constitution => ({ version: CONSTITUTION_VERSION, principal: PRIN, invariants });
const st = (over: Partial<MonitorState> = {}): MonitorState => ({ ...emptyState(NOW), ...over });
const inv = (o: Record<string, unknown>): Invariant => o as unknown as Invariant;

describe('validateWhen', () => {
  it('shape / verb / resource / where', () => {
    for (const bad of [null, undefined, 'x', 5, []]) expect(validateWhen(bad, 'L')).toBe('L: not an object');
    expect(validateWhen({ verb: 'x' }, 'L')).toBeNull();
    expect(validateWhen({ verb: ['x', 'y'] }, 'L')).toBeNull();
    for (const v of ['', [], [''], ['x', ''], [5], ['x', 5], undefined, null, 5, {}]) expect(validateWhen({ verb: v }, 'L'), JSON.stringify(v)).toBe('L: bad verb');
    expect(validateWhen({ verb: 'x', resource: '/a' }, 'L')).toBeNull();
    expect(validateWhen({ verb: 'x', resource: '' }, 'L')).toBeNull();
    expect(validateWhen({ verb: 'x', resource: undefined }, 'L')).toBeNull();
    for (const r of [5, null, [], {}]) expect(validateWhen({ verb: 'x', resource: r }, 'L')).toBe('L: bad resource');
    expect(validateWhen({ verb: 'x', where: [] }, 'L')).toBeNull();
    expect(validateWhen({ verb: 'x', where: undefined }, 'L')).toBeNull();
    for (const w of [{}, 'x', 5, null]) expect(validateWhen({ verb: 'x', where: w }, 'L')).toBe('L: where not an array');
    expect(validateWhen({ verb: 'x', where: [5] }, 'L')).toBe('L: condition not an object');
    expect(validateWhen({ verb: 'x', where: [{ field: 'a', op: 'eq' }, { field: '', op: 'eq' }] }, 'L')).toBe('L: condition.field missing');
    expect(validateWhen({ verb: 'x', where: [{ field: 'a', op: 'eq' }] }, 'other')).toBeNull();
  });
  it('re: resources must be safe and <= 200 chars (the label is carried)', () => {
    expect(validateWhen({ verb: 'x', resource: 're:/a/[a-z]+' }, 'P')).toBeNull();
    expect(validateWhen({ verb: 'x', resource: 're:' }, 'P')).toBeNull();
    expect(validateWhen({ verb: 'x', resource: 're:' + 'a'.repeat(200) }, 'P')).toBeNull();
    expect(validateWhen({ verb: 'x', resource: 're:' + 'a'.repeat(201) }, 'P')).toBe('P: unsafe regex resource');
    expect(validateWhen({ verb: 'x', resource: 're:(a+)+' }, 'P')).toBe('P: unsafe regex resource');
    expect(validateWhen({ verb: 'x', resource: 're:\\1' }, 'P')).toBe('P: unsafe regex resource');
    expect(validateWhen({ verb: 'x', resource: 're:(' }, 'P')).toBe('P: unsafe regex resource');
    expect(validateWhen({ verb: 'x', resource: 're:a{' }, 'P')).toBe('P: unsafe regex resource');
    // only the exact "re:" prefix selects regex handling
    expect(validateWhen({ verb: 'x', resource: 'Re:(' }, 'P')).toBeNull();
    expect(validateWhen({ verb: 'x', resource: 'xre:(' }, 'P')).toBeNull();
    expect(validateWhen({ verb: 'x', resource: 're(' }, 'P')).toBeNull();
  });
});

describe('condition validation (via validateWhen)', () => {
  const v = (c: unknown) => validateWhen({ verb: 'x', where: [c] }, 'W');
  it('leaf', () => {
    expect(v({ field: 'a', op: 'eq', value: 1 })).toBeNull();
    for (const op of ['eq', 'ne', 'in', 'nin', 'lt', 'lte', 'gt', 'gte', 'prefix', 'exists', 'like', 'matches', 'is_a', 'member_of']) expect(v({ field: 'a', op })).toBeNull();
    for (const f of [undefined, '', 5, null, {}]) expect(v({ field: f, op: 'eq' })).toBe('W: condition.field missing');
    expect(v({ field: 'a', op: 'zz' })).toBe('W: unknown condition op zz');
    expect(v({ field: 'a' })).toBe('W: unknown condition op undefined');
    expect(v({ field: 'a', op: 5 })).toBe('W: unknown condition op 5');
    expect(v({ field: 'a', op: 'EQ' })).toBe('W: unknown condition op EQ');
    expect(v({ field: 'a', op: 'toString' })).toBe('W: unknown condition op toString');
    expect(v({ field: 'a', op: 'eq', ref: 'b' })).toBeNull();
    expect(v({ field: 'a', op: 'eq', ref: undefined })).toBeNull();
    for (const r of ['', 5, null, {}]) expect(v({ field: 'a', op: 'eq', ref: r })).toBe('W: bad condition.ref');
    expect(v({ field: 'a', op: 'member_of', collection: 'c' })).toBeNull();
    expect(v({ field: 'a', op: 'member_of', collection: undefined })).toBeNull();
    for (const col of ['', 5, null, {}]) expect(v({ field: 'a', op: 'member_of', collection: col })).toBe('W: bad condition.collection');
    // `collection` is only validated for member_of
    expect(v({ field: 'a', op: 'eq', collection: 5 })).toBeNull();
    // field is checked before op, op before ref, ref before collection
    expect(v({ field: '', op: 'zz', ref: '' })).toBe('W: condition.field missing');
    expect(v({ field: 'a', op: 'zz', ref: '' })).toBe('W: unknown condition op zz');
    expect(v({ field: 'a', op: 'member_of', ref: '', collection: 5 })).toBe('W: bad condition.ref');
  });
  it('groups: children validated recursively; empty / non-array rejected; `not` takes one condition', () => {
    const L = { field: 'a', op: 'eq' };
    expect(v({ all_of: [L, L] })).toBeNull();
    expect(v({ any_of: [L] })).toBeNull();
    expect(v({ not: L })).toBeNull();
    expect(v({ all_of: [] })).toBe('W: condition.all_of must be a non-empty array');
    expect(v({ any_of: [] })).toBe('W: condition.any_of must be a non-empty array');
    expect(v({ all_of: 'x' })).toBe('W: condition.all_of must be a non-empty array');
    expect(v({ any_of: {} })).toBe('W: condition.any_of must be a non-empty array');
    expect(v({ all_of: undefined })).toBe('W: condition.all_of must be a non-empty array');
    expect(v({ not: 5 })).toBe('W: condition not an object');
    expect(v({ not: { field: '', op: 'eq' } })).toBe('W: condition.field missing');
    expect(v({ all_of: [L, { not: 5 }] })).toBe('W: condition not an object');
    expect(v({ any_of: [L, { all_of: [] }] })).toBe('W: condition.all_of must be a non-empty array');
    // when several group keys are present: not wins, then all_of, then any_of
    expect(v({ not: L, all_of: [] })).toBeNull();
    expect(v({ all_of: [L], any_of: [] })).toBeNull();
    expect(v({ all_of: [], any_of: [L] })).toBe('W: condition.all_of must be a non-empty array');
    expect(v({ any_of: [L], field: '' })).toBeNull();
  });
  it('nesting depth: 32 levels allowed, 33 refused', () => {
    const nest = (n: number): unknown => {
      let c: unknown = { field: 'a', op: 'eq' };
      for (let i = 0; i < n; i++) c = { not: c };
      return c;
    };
    expect(v(nest(32))).toBeNull();
    expect(v(nest(33))).toBe('W: condition nesting too deep');
    const nestAll = (n: number): unknown => {
      let c: unknown = { field: 'a', op: 'eq' };
      for (let i = 0; i < n; i++) c = { all_of: [c] };
      return c;
    };
    expect(v(nestAll(32))).toBeNull();
    expect(v(nestAll(33))).toBe('W: condition nesting too deep');
    expect(v(nestAll(40))).toBe('W: condition nesting too deep');
  });
});

describe('validateInvariant', () => {
  const ok = (o: Record<string, unknown>) => validateInvariant(o);
  it('id rules', () => {
    for (const bad of [null, undefined, 5, 'x', []]) expect(validateInvariant(bad)).toEqual(['invariant not an object']);
    for (const id of [undefined, '', 5, null]) expect(ok({ id, kind: 'never', when: W('x') })).toEqual(['<no id>: missing id']);
    expect(ok({ id: 'a'.repeat(128), kind: 'never', when: W('x') })).toEqual([]);
    expect(ok({ id: 'a'.repeat(129), kind: 'never', when: W('x') })).toEqual([`${'a'.repeat(129)}: id too long`]);
    for (const f of ['__proto__', 'constructor', 'prototype']) expect(ok({ id: f, kind: 'never', when: W('x') })).toEqual([`${f}: forbidden id`]);
    expect(ok({ id: 'i', kind: 'nope' })).toEqual(['i: unknown invariant kind nope']);
    expect(ok({ id: 'i' })).toEqual(['i: unknown invariant kind undefined']);
  });
  it('never / never_unless', () => {
    expect(ok({ id: 'i', kind: 'never', when: W('x') })).toEqual([]);
    expect(ok({ id: 'i', kind: 'never', when: 5 })).toEqual(['i: when: not an object']);
    expect(ok({ id: 'i', kind: 'never' })).toEqual(['i: when: not an object']);
    expect(ok({ id: 'i', kind: 'never_unless', when: W('x'), unless: [{ field: 'a', op: 'eq' }] })).toEqual([]);
    expect(ok({ id: 'i', kind: 'never_unless', when: 5, unless: [] })).toEqual(['i: when: not an object']);
    expect(ok({ id: 'i', kind: 'never_unless', when: W('x'), unless: [] })).toEqual(['i: unless must be a non-empty array']);
    expect(ok({ id: 'i', kind: 'never_unless', when: W('x') })).toEqual(['i: unless must be a non-empty array']);
    expect(ok({ id: 'i', kind: 'never_unless', when: W('x'), unless: 'x' })).toEqual(['i: unless must be a non-empty array']);
    expect(ok({ id: 'i', kind: 'never_unless', when: W('x'), unless: [5] })).toEqual(['i: condition not an object']);
    expect(ok({ id: 'i', kind: 'never_unless', when: W('x'), unless: [{ field: 'a', op: 'eq' }, { field: 'a', op: 'zz' }] })).toEqual(['i: unknown condition op zz']);
  });
  it('cap', () => {
    const cap = (o: Record<string, unknown>) => ok({ id: 'i', kind: 'cap', when: W('x'), amount: 'action.params.n', max: 10, ...o });
    expect(cap({})).toEqual([]);
    expect(cap({ max: 0 })).toEqual([]);
    expect(cap({ max: 0.5 })).toEqual([]);
    expect(cap({ window_secs: 1 })).toEqual([]);
    expect(cap({ window_secs: 0.001 })).toEqual([]);
    expect(cap({ when: 5 })).toEqual(['i: when: not an object']);
    for (const a of [undefined, 5, '', 'params.n', 'action', 'actionX.n', 'subject.n']) expect(cap({ amount: a }), String(a)).toEqual(['i: amount must be an action.* path']);
    expect(cap({ amount: 'action.' })).toEqual([]);
    for (const m of [-1, -0.001, NaN, Infinity, -Infinity, '5', undefined, null]) expect(cap({ max: m })).toEqual(['i: max must be a finite number >= 0']);
    for (const w of [0, -1, NaN, Infinity, '5', null]) expect(cap({ window_secs: w })).toEqual(['i: bad window_secs']);
    // check order: when, amount, max, window
    expect(cap({ when: 5, amount: 5 })).toEqual(['i: when: not an object']);
    expect(cap({ amount: 5, max: -1 })).toEqual(['i: amount must be an action.* path']);
    expect(cap({ max: -1, window_secs: 0 })).toEqual(['i: max must be a finite number >= 0']);
  });
  it('rate', () => {
    const rate = (o: Record<string, unknown>) => ok({ id: 'i', kind: 'rate', when: W('x'), max: 5, window_secs: 60, ...o });
    expect(rate({})).toEqual([]);
    expect(rate({ max: 0 })).toEqual([]);
    expect(rate({ max: MAX_LEDGER })).toEqual([]);
    expect(MAX_LEDGER).toBe(10_000);
    for (const m of [-1, MAX_LEDGER + 1, 1.5, NaN, Infinity, '5', undefined, null]) expect(rate({ max: m })).toEqual(['i: max must be an integer in [0,10000]']);
    expect(rate({ window_secs: 0.5 })).toEqual([]);
    for (const w of [0, -1, NaN, Infinity, '5', undefined, null]) expect(rate({ window_secs: w })).toEqual(['i: window_secs must be > 0']);
    expect(rate({ when: 5 })).toEqual(['i: when: not an object']);
    expect(rate({ when: 5, max: -1 })).toEqual(['i: when: not an object']);
    expect(rate({ max: -1, window_secs: 0 })).toEqual(['i: max must be an integer in [0,10000]']);
  });
  it('never_after / require_prior', () => {
    expect(ok({ id: 'i', kind: 'never_after', after: W('a'), forbid: W('b') })).toEqual([]);
    expect(ok({ id: 'i', kind: 'never_after', after: 5, forbid: W('b') })).toEqual(['i: after: not an object']);
    expect(ok({ id: 'i', kind: 'never_after', after: W('a'), forbid: 5 })).toEqual(['i: forbid: not an object']);
    expect(ok({ id: 'i', kind: 'never_after', after: 5, forbid: 5 })).toEqual(['i: after: not an object']);
    expect(ok({ id: 'i', kind: 'never_after' })).toEqual(['i: after: not an object']);
    expect(ok({ id: 'i', kind: 'require_prior', when: W('a'), prior: W('b') })).toEqual([]);
    expect(ok({ id: 'i', kind: 'require_prior', when: 5, prior: W('b') })).toEqual(['i: when: not an object']);
    expect(ok({ id: 'i', kind: 'require_prior', when: W('a'), prior: 5 })).toEqual(['i: prior: not an object']);
    expect(ok({ id: 'i', kind: 'require_prior', when: 5, prior: 5 })).toEqual(['i: when: not an object']);
  });
  it('require_approval_over', () => {
    const ra = (o: Record<string, unknown>) => ok({ id: 'i', kind: 'require_approval_over', when: W('x'), amount: 'action.params.n', threshold: 100, approved: [{ field: 'a', op: 'eq' }], ...o });
    expect(ra({})).toEqual([]);
    expect(ra({ threshold: 0 })).toEqual([]);
    expect(ra({ when: 5 })).toEqual(['i: when: not an object']);
    for (const a of [undefined, 5, 'n', 'subject.n']) expect(ra({ amount: a })).toEqual(['i: amount must be an action.* path']);
    for (const t of [-1, NaN, Infinity, '5', undefined, null]) expect(ra({ threshold: t })).toEqual(['i: threshold must be a finite number >= 0']);
    expect(ra({ approved: [] })).toEqual(['i: approved must be a non-empty array']);
    expect(ra({ approved: undefined })).toEqual(['i: approved must be a non-empty array']);
    expect(ra({ approved: [5] })).toEqual(['i: condition not an object']);
    expect(ra({ amount: 5, threshold: -1 })).toEqual(['i: amount must be an action.* path']);
    expect(ra({ threshold: -1, approved: [] })).toEqual(['i: threshold must be a finite number >= 0']);
  });
});

describe('validateConstitution / sign / verify', () => {
  const nv = (id: string): Invariant => inv({ id, kind: 'never', when: W('zzz') });
  it('validateConstitution', () => {
    for (const bad of [null, undefined, 'x', 5, []]) expect(validateConstitution(bad)).toEqual(['constitution not an object']);
    expect(validateConstitution({ version: 1, principal: PRIN, invariants: [] })).toEqual([]);
    expect(validateConstitution({ version: 2, principal: PRIN, invariants: [] })).toEqual(['unsupported version 2']);
    expect(validateConstitution({ principal: PRIN, invariants: [] })).toEqual(['unsupported version undefined']);
    expect(validateConstitution({ version: 1, invariants: [] })).toEqual(['principal missing']);
    expect(validateConstitution({ version: 1, principal: '', invariants: [] })).toEqual(['principal missing']);
    expect(validateConstitution({ version: 1, principal: 5, invariants: [] })).toEqual(['principal missing']);
    expect(validateConstitution({ version: 1, principal: PRIN })).toEqual(['invariants not an array']);
    expect(validateConstitution({ version: 1, principal: PRIN, invariants: {} })).toEqual(['invariants not an array']);
    expect(validateConstitution({ version: 9, principal: '' })).toEqual(['unsupported version 9', 'principal missing', 'invariants not an array']);
    const many = (n: number) => Array.from({ length: n }, (_, i) => nv('i' + i));
    expect(MAX_INVARIANTS).toBe(256);
    expect(validateConstitution({ version: 1, principal: PRIN, invariants: many(256) })).toEqual([]);
    expect(validateConstitution({ version: 1, principal: PRIN, invariants: many(257) })).toEqual(['too many invariants']);
    expect(validateConstitution({ version: 1, principal: PRIN, invariants: [nv('a'), nv('a')] })).toEqual(['a: duplicate id']);
    expect(validateConstitution({ version: 1, principal: PRIN, invariants: [nv('a'), nv('b'), nv('b'), nv('a')] })).toEqual(['b: duplicate id', 'a: duplicate id']);
    expect(validateConstitution({ version: 1, principal: PRIN, invariants: [5, 5] })).toEqual(['invariant not an object', 'invariant not an object']);
    expect(validateConstitution({ version: 1, principal: PRIN, invariants: [{ id: 'a', kind: 'zz' }, { id: 'a', kind: 'zz' }] })).toEqual(['a: unknown invariant kind zz', 'a: unknown invariant kind zz', 'a: duplicate id']);
  });
  it('constitutionId = hashCanonical(body without id/sig)', () => {
    const c = cons([nv('a')]);
    expect(constitutionId(c)).toBe(hashCanonical(c));
    expect(constitutionId({ ...c, id: 'x', sig: 'y' } as Constitution)).toBe(constitutionId(c));
    expect(constitutionId({ ...c, issued_at: 1 })).not.toBe(constitutionId(c));
  });
  it('signConstitution: shape, domain-separated signature, refusal text', () => {
    const c = cons([nv('a')]);
    const sc = signConstitution(c, K.secretKey);
    expect(Object.keys(sc).sort()).toEqual(['id', 'invariants', 'principal', 'sig', 'version']);
    expect(sc.id).toBe(constitutionId(c));
    expect(CONSTITUTION_SIG_DOMAIN).toBe('atlas-pca/constitution/v1\0');
    expect(sc.sig).toBe(b64u(sign(K.secretKey, new Uint8Array([...utf8(CONSTITUTION_SIG_DOMAIN), ...sha256(utf8(sc.id))]))));
    expect(signConstitution({ ...sc, id: 'stale', sig: 'stale' } as Constitution, K.secretKey)).toEqual(sc);
    expect(() => signConstitution({ version: 4, principal: '', invariants: [] }, K.secretKey)).toThrow(new TypeError('signConstitution: unsupported version 4; principal missing'));
    expect(() => signConstitution({ version: 4, principal: '', invariants: [] }, K.secretKey)).toThrow(TypeError);
  });
  it('verifyConstitution: reasons in order', () => {
    const sc = signConstitution(cons([nv('a')]), K.secretKey);
    expect(verifyConstitution(sc)).toEqual({ ok: true });
    expect(verifyConstitution(sc, PRIN)).toEqual({ ok: true });
    expect(verifyConstitution(sc, encodeKey(K2.publicKey))).toEqual({ ok: false, reason: 'principal mismatch' });
    expect(verifyConstitution({ ...sc, version: 3 })).toEqual({ ok: false, reason: 'unsupported version 3' });
    expect(verifyConstitution({ ...sc, version: 3 }, encodeKey(K2.publicKey))).toEqual({ ok: false, reason: 'unsupported version 3' });
    expect(verifyConstitution({ ...sc, id: 'x' }, encodeKey(K2.publicKey))).toEqual({ ok: false, reason: 'principal mismatch' });
    expect(verifyConstitution({ ...sc, id: 'x' })).toEqual({ ok: false, reason: 'id does not match content' });
    expect(verifyConstitution({ ...sc, id: 5 as never })).toEqual({ ok: false, reason: 'id does not match content' });
    expect(verifyConstitution({ ...sc, invariants: [nv('b')] })).toEqual({ ok: false, reason: 'id does not match content' });
    expect(verifyConstitution({ ...sc, sig: 5 as never })).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyConstitution({ ...sc, sig: 'AAAA' })).toEqual({ ok: false, reason: 'bad signature' });
    const other = signConstitution(cons([nv('a')]), K2.secretKey);
    expect(verifyConstitution({ ...sc, sig: other.sig })).toEqual({ ok: false, reason: 'bad signature' });
    const bare = { ...sc, sig: b64u(sign(K.secretKey, sha256(utf8(sc.id)))) };
    expect(verifyConstitution(bare)).toEqual({ ok: false, reason: 'bad signature' });
    const wrongOrder = { ...sc, sig: b64u(sign(K.secretKey, new Uint8Array([...sha256(utf8(sc.id)), ...utf8(CONSTITUTION_SIG_DOMAIN)]))) };
    expect(verifyConstitution(wrongOrder)).toEqual({ ok: false, reason: 'bad signature' });
    const ext = { ...sc, extra: () => 1 } as unknown as SignedConstitution;
    expect(verifyConstitution(ext)).toEqual({ ok: false, reason: 'verification error (fail closed)' });
  });
});

describe('stateProblem', () => {
  const good = (): MonitorState => st();
  it('well-formed states', () => {
    expect(stateProblem(good())).toBeNull();
    expect(stateProblem({ ...good(), seq: 3, parent: 'abc' })).toBeNull();
    expect(stateProblem({ ...good(), ledger: { a: [{ t: NOW, amount: 0 }] }, latched: { a: NOW }, deadlines: { a: 1 } })).toBeNull();
  });
  it('top-level shape', () => {
    for (const bad of [null, undefined, 5, 'x', []]) expect(stateProblem(bad)).toBe('malformed monitor state');
    for (const now of [undefined, NaN, Infinity, '1', null]) expect(stateProblem({ ...good(), now })).toBe('malformed monitor state');
    for (const l of [undefined, null, [], 'x']) expect(stateProblem({ ...good(), ledger: l })).toBe('malformed monitor state');
    for (const l of [undefined, null, [], 'x']) expect(stateProblem({ ...good(), latched: l })).toBe('malformed monitor state');
  });
  it('seq / parent / chain link', () => {
    for (const seq of [-1, 1.5, NaN, '0', undefined, null, Infinity]) expect(stateProblem({ ...good(), seq })).toBe('malformed monitor state: seq');
    for (const parent of [5, undefined, {}, ['x']]) expect(stateProblem({ ...good(), parent })).toBe('malformed monitor state: parent');
    expect(stateProblem({ ...good(), seq: 0, parent: 'x' })).toBe('malformed monitor state: genesis has a parent');
    expect(stateProblem({ ...good(), seq: 1, parent: null })).toBe('malformed monitor state: missing chain link');
    expect(stateProblem({ ...good(), seq: 1, parent: '' })).toBeNull(); // an empty string is still a string
  });
  it('key count limits (1024 allowed, 1025 refused) for ledger, latched and deadlines', () => {
    const keys = (n: number, v: unknown) => Object.fromEntries(Array.from({ length: n }, (_, i) => ['k' + i, v]));
    expect(stateProblem({ ...good(), ledger: keys(1024, []) })).toBeNull();
    expect(stateProblem({ ...good(), ledger: keys(1025, []) })).toBe('malformed monitor state: too many keys');
    expect(stateProblem({ ...good(), latched: keys(1024, NOW) })).toBeNull();
    expect(stateProblem({ ...good(), latched: keys(1025, NOW) })).toBe('malformed monitor state: too many keys');
    expect(stateProblem({ ...good(), deadlines: keys(1024, 1) })).toBeNull();
    expect(stateProblem({ ...good(), deadlines: keys(1025, 1) })).toBe('malformed monitor state: too many deadline keys');
  });
  it('ledger keys and arrays', () => {
    for (const k of ['__proto__', 'constructor', 'prototype']) {
      const l = JSON.parse(`{"${k}":[]}`);
      expect(stateProblem({ ...good(), ledger: l })).toBe('malformed monitor state: bad ledger key');
    }
    expect(stateProblem({ ...good(), ledger: { ['k'.repeat(128)]: [] } })).toBeNull();
    expect(stateProblem({ ...good(), ledger: { ['k'.repeat(129)]: [] } })).toBe('malformed monitor state: bad ledger key');
    expect(stateProblem({ ...good(), ledger: { a: {} } })).toBe('malformed monitor state: bad ledger');
    expect(stateProblem({ ...good(), ledger: { a: null } })).toBe('malformed monitor state: bad ledger');
    expect(stateProblem({ ...good(), ledger: { a: 'x' } })).toBe('malformed monitor state: bad ledger');
    const big = (n: number) => Array.from({ length: n }, () => ({ t: 1, amount: 0 }));
    expect(stateProblem({ ...good(), ledger: { a: big(10_000) } })).toBeNull();
    expect(stateProblem({ ...good(), ledger: { a: big(10_001) } })).toBe('malformed monitor state: bad ledger');
  });
  it('ledger entries', () => {
    const e = (entry: unknown) => stateProblem({ ...good(), ledger: { a: [entry] } });
    expect(e({ t: 1, amount: 0 })).toBeNull();
    expect(e({ t: NOW, amount: 5 })).toBeNull();
    expect(e({ t: -5, amount: 5 })).toBeNull();
    for (const bad of [null, 5, 'x', [], undefined]) expect(e(bad)).toBe('malformed monitor state: bad ledger entry');
    expect(e({ t: NaN, amount: 1 })).toBe('malformed monitor state: bad ledger entry');
    expect(e({ t: '1', amount: 1 })).toBe('malformed monitor state: bad ledger entry');
    expect(e({ t: 1, amount: NaN })).toBe('malformed monitor state: bad ledger entry');
    expect(e({ t: 1, amount: Infinity })).toBe('malformed monitor state: bad ledger entry');
    expect(e({ t: 1, amount: '1' })).toBe('malformed monitor state: bad ledger entry');
    expect(e({ t: 1, amount: -0.001 })).toBe('malformed monitor state: bad ledger entry');
    expect(e({ t: 1 })).toBe('malformed monitor state: bad ledger entry');
    expect(e({ amount: 1 })).toBe('malformed monitor state: bad ledger entry');
    expect(e({ t: NOW + 1, amount: 1 })).toBe('malformed monitor state: ledger entry after now (clock regression)');
    expect(stateProblem({ ...good(), now: 10, ledger: { a: [{ t: 10, amount: 1 }] } })).toBeNull();
    expect(stateProblem({ ...good(), now: 10, ledger: { a: [{ t: 11, amount: 1 }] } })).toBe('malformed monitor state: ledger entry after now (clock regression)');
  });
  it('total entries across keys: 100000 allowed, 100001 refused', () => {
    const mk = (n: number) => Array.from({ length: n }, () => ({ t: 1, amount: 0 }));
    const ten: Record<string, Array<{ t: number; amount: number }>> = {};
    for (let i = 0; i < 10; i++) ten['k' + i] = mk(10_000);
    expect(stateProblem({ ...good(), ledger: ten })).toBeNull();
    expect(stateProblem({ ...good(), ledger: { ...ten, extra: mk(1) } })).toBe('malformed monitor state: too many entries');
  });
  it('latches', () => {
    for (const k of ['__proto__', 'constructor', 'prototype']) expect(stateProblem({ ...good(), latched: JSON.parse(`{"${k}":1}`) })).toBe('malformed monitor state: bad latch key');
    expect(stateProblem({ ...good(), latched: { ['k'.repeat(128)]: 1 } })).toBeNull();
    expect(stateProblem({ ...good(), latched: { ['k'.repeat(129)]: 1 } })).toBe('malformed monitor state: bad latch key');
    expect(stateProblem({ ...good(), latched: { a: NOW } })).toBeNull();
    expect(stateProblem({ ...good(), latched: { a: NOW + 1 } })).toBe('malformed monitor state: bad latch');
    for (const t of ['1', NaN, Infinity, null, undefined]) expect(stateProblem({ ...good(), latched: { a: t } })).toBe('malformed monitor state: bad latch');
  });
  it('deadlines', () => {
    for (const d of [null, 5, 'x', []]) expect(stateProblem({ ...good(), deadlines: d })).toBe('malformed monitor state: deadlines');
    expect(stateProblem({ ...good(), deadlines: {} })).toBeNull();
    for (const k of ['__proto__', 'constructor', 'prototype']) expect(stateProblem({ ...good(), deadlines: JSON.parse(`{"${k}":1}`) })).toBe('malformed monitor state: bad deadline key');
    expect(stateProblem({ ...good(), deadlines: { ['k'.repeat(128)]: 1 } })).toBeNull();
    expect(stateProblem({ ...good(), deadlines: { ['k'.repeat(129)]: 1 } })).toBe('malformed monitor state: bad deadline key');
    expect(stateProblem({ ...good(), deadlines: { a: 1 } })).toBeNull();
    expect(stateProblem({ ...good(), deadlines: { a: MAX_DEADLINE } })).toBeNull();
    for (const d of [0, -1, MAX_DEADLINE + 1, 1.5, NaN, Infinity, '1', null, undefined]) expect(stateProblem({ ...good(), deadlines: { a: d } })).toBe('malformed monitor state: bad deadline');
  });
  it('check order: ledger problems before latch problems before deadline problems', () => {
    expect(stateProblem({ ...good(), ledger: { a: 5 }, latched: { a: 'x' }, deadlines: 5 })).toBe('malformed monitor state: bad ledger');
    expect(stateProblem({ ...good(), latched: { a: 'x' }, deadlines: 5 })).toBe('malformed monitor state: bad latch');
    expect(stateProblem({ ...good(), seq: -1, ledger: 5 })).toBe('malformed monitor state');
    expect(stateProblem({ ...good(), seq: -1, parent: 5 })).toBe('malformed monitor state: seq');
    expect(stateProblem({ ...good(), seq: 0, parent: 5 })).toBe('malformed monitor state: parent');
  });
  it('never throws on hostile objects', () => {
    const hostile = new Proxy({}, { get() { throw new Error('boom'); }, getPrototypeOf() { throw new Error('boom'); } });
    expect(stateProblem(hostile)).toBe('malformed monitor state');
  });
});

describe('canonicalState / stateDigest / tickState', () => {
  it('canonical form: domain tag, projected fields, sorted ledger, empty arrays dropped, deadlines only when non-empty', () => {
    const s = st({
      seq: 2,
      parent: 'p',
      ledger: { b: [{ t: 5, amount: 2, extra: 'x' } as never, { t: 5, amount: 1 }, { t: 3, amount: 9 }], a: [] },
      latched: { z: 1, y: 2 },
    });
    const c = canonicalState(s);
    expect(c).toStrictEqual({
      d: STATE_DIGEST_DOMAIN,
      now: NOW,
      seq: 2,
      parent: 'p',
      ledger: { b: [{ t: 3, amount: 9 }, { t: 5, amount: 1 }, { t: 5, amount: 2 }] },
      latched: { z: 1, y: 2 },
    });
    expect('deadlines' in c).toBe(false);
    expect(STATE_DIGEST_DOMAIN).toBe('atlas-pca/monitor-state/v1');
    expect('deadlines' in canonicalState(st({ deadlines: {} }))).toBe(false);
    expect(canonicalState(st({ deadlines: { a: 3, b: 1 } })).deadlines).toEqual({ a: 3, b: 1 });
    // the input is not mutated
    expect(s.ledger['b']![0]).toEqual({ t: 5, amount: 2, extra: 'x' });
  });
  it('throws TypeError with the stateProblem text on a malformed state', () => {
    expect(() => canonicalState({ bad: 1 } as never)).toThrow(new TypeError('malformed monitor state'));
    expect(() => canonicalState({ ...st(), seq: 1 })).toThrow(new TypeError('malformed monitor state: missing chain link'));
    expect(() => stateDigest(null as never)).toThrow(TypeError);
  });
  it('digest = hashCanonical(canonical); order-independent in ledger entries; sensitive to every field', () => {
    const base = st({ seq: 1, parent: 'p', ledger: { a: [{ t: 1, amount: 2 }, { t: 1, amount: 1 }] }, latched: { l: 5 } });
    expect(stateDigest(base)).toBe(hashCanonical(canonicalState(base)));
    const permuted = { ...base, ledger: { a: [{ t: 1, amount: 1 }, { t: 1, amount: 2 }] } };
    expect(stateDigest(permuted)).toBe(stateDigest(base));
    expect(stateDigest({ ...base, ledger: { a: [{ t: 1, amount: 1 }, { t: 1, amount: 2 }], emptyOne: [] } })).toBe(stateDigest(base));
    const d0 = stateDigest(base);
    for (const alt of [
      { ...base, now: NOW + 1 },
      { ...base, seq: 2 },
      { ...base, parent: 'q' },
      { ...base, ledger: { a: [{ t: 1, amount: 2 }, { t: 2, amount: 1 }] } },
      { ...base, ledger: { a: [{ t: 1, amount: 2 }, { t: 1, amount: 3 }] } },
      { ...base, ledger: { b: base.ledger['a']! } },
      { ...base, latched: { l: 6 } },
      { ...base, latched: { m: 5 } },
      { ...base, deadlines: { x: 1 } },
    ]) expect(stateDigest(alt as MonitorState)).not.toBe(d0);
    expect(stateDigest({ ...base, deadlines: { x: 1 } })).not.toBe(stateDigest({ ...base, deadlines: { x: 2 } }));
    expect(stateDigest({ ...base, deadlines: {} })).toBe(d0);
  });
  it('sort order: by time, then amount', () => {
    const s = st({ ledger: { a: [{ t: 9, amount: 1 }, { t: 2, amount: 5 }, { t: 2, amount: 3 }, { t: 9, amount: 0 }, { t: 5, amount: 4 }] } });
    expect(canonicalState(s).ledger['a']).toEqual([
      { t: 2, amount: 3 },
      { t: 2, amount: 5 },
      { t: 5, amount: 4 },
      { t: 9, amount: 0 },
      { t: 9, amount: 1 },
    ]);
  });
  it('tickState', () => {
    const s = st({ seq: 1, parent: 'p' });
    const r = tickState(s, NOW + 5);
    expect(r).toStrictEqual({ ok: true, state: { ...s, now: NOW + 5 } });
    expect(tickState(s, NOW)).toStrictEqual({ ok: true, state: s });
    expect(tickState(s, NOW - 1)).toStrictEqual({ ok: false, reason: 'clock regression' });
    for (const bad of [NaN, Infinity, -Infinity, '5', undefined, null]) expect(tickState(s, bad as never)).toStrictEqual({ ok: false, reason: 'clock regression' });
    expect(tickState({ bad: 1 } as never, NOW)).toStrictEqual({ ok: false, reason: 'malformed monitor state' });
    expect(tickState({ ...s, seq: -1 }, NOW + 1)).toStrictEqual({ ok: false, reason: 'malformed monitor state' });
    expect(s.now).toBe(NOW);
  });
});

describe('whenMatches / whenAffirmative', () => {
  const amb = (v: string) => W(v, { where: [{ field: 'action.params.x', op: 'eq', value: 1 }] });
  it('verb and resource decide first; a non-matching verb/resource is a clean "no"', () => {
    expect(whenMatches(W('a'), act('a'))).toBe(true);
    expect(whenMatches(W('a'), act('b'))).toBe(false);
    expect(whenMatches(W(['a', 'b']), act('b'))).toBe(true);
    expect(whenMatches(W('*'), act('zzz'))).toBe(true);
    expect(whenMatches(W('a', { resource: '/r' }), act('a', '/r'))).toBe(true);
    expect(whenMatches(W('a', { resource: '/x' }), act('a', '/r'))).toBe(false);
    expect(whenMatches(W('a', { resource: '/r*' }), act('a', '/rzz'))).toBe(true);
    expect(whenMatches(W('a', { resource: 're:/[a-z]' }), act('a', '/q'))).toBe(true);
    expect(whenMatches(W('a', { resource: 're:/[a-z]' }), act('a', '/Q'))).toBe(false);
    // an ambiguous where condition does not rescue a verb mismatch
    expect(whenMatches(amb('a'), act('b', '/r', {}))).toBe(false);
  });
  it('where is CONSERVATIVE: only a cleanly-false condition prevents the match', () => {
    expect(whenMatches(amb('a'), act('a', '/r', { x: 1 }))).toBe(true);
    expect(whenMatches(amb('a'), act('a', '/r', { x: 2 }))).toBe(false);
    expect(whenMatches(amb('a'), act('a', '/r', {}))).toBe(true); // unresolvable => veto applies
    expect(whenMatches(amb('a'), act('a'))).toBe(true); // params unavailable
    const two = W('a', { where: [{ field: 'action.params.x', op: 'eq', value: 1 }, { field: 'action.params.y', op: 'eq', value: 1 }] });
    expect(whenMatches(two, act('a', '/r', { x: 1, y: 2 }))).toBe(false);
    expect(whenMatches(two, act('a', '/r', { x: 2, y: 1 }))).toBe(false);
    expect(whenMatches(two, act('a', '/r', { x: 1, y: 1 }))).toBe(true);
    expect(whenMatches(two, act('a', '/r', { x: 1 }))).toBe(true);
    const grp = W('a', { where: [{ not: { field: 'action.params.x', op: 'eq', value: 1 } }] });
    expect(whenMatches(grp, act('a', '/r', { x: 1 }))).toBe(false);
    expect(whenMatches(grp, act('a', '/r', { x: 2 }))).toBe(true);
    expect(whenMatches(grp, act('a', '/r', {}))).toBe(true);
    expect(whenMatches(W('a', { where: [] }), act('a'))).toBe(true);
  });
  it('malformed trigger / action => matched (veto)', () => {
    for (const w of [null, undefined, 5, {}, { verb: '' }, { verb: 'a', resource: 5 }, { verb: 'a', where: 'x' }, { verb: 'a', where: [{ field: '', op: 'eq' }] }, { verb: 'a', resource: 're:(a+)+' }]) {
      expect(whenMatches(w as never, act('zzz')), JSON.stringify(w)).toBe(true);
    }
    for (const a of [null, undefined, {}, { action: null }, { action: { verb: 5, resource: '/r' } }, { action: { verb: 'a', resource: 5 } }, { action: { verb: 'a' } }]) {
      expect(whenMatches(W('a'), a as never)).toBe(true);
    }
  });
  it('a regex resource with an OVERSIZED subject cannot be evaluated => the veto applies (verb still decides)', () => {
    const w = W('a', { resource: 're:b' });
    expect(whenMatches(w, act('a', 'a'.repeat(512)))).toBe(false); // evaluated: no match
    expect(whenMatches(w, act('a', 'a'.repeat(513)))).toBe(true); // not evaluable => veto
    expect(whenMatches(w, act('z', 'a'.repeat(513)))).toBe(false); // wrong verb still clears it
    // oversize only matters for re: resources
    expect(whenMatches(W('a', { resource: 'b' }), act('a', 'a'.repeat(513)))).toBe(false);
    expect(whenMatches(W('a', { resource: 'b*' }), act('a', 'a'.repeat(513)))).toBe(false);
    expect(whenMatches(W('a'), act('a', 'a'.repeat(513)))).toBe(true);
    // where conditions are still honoured for an oversized subject
    expect(whenMatches(W('a', { resource: 're:b', where: [{ field: 'action.params.x', op: 'eq', value: 1 }] }), act('a', 'a'.repeat(513), { x: 2 }))).toBe(false);
    expect(whenMatches(W('a', { resource: 're:b', where: [{ field: 'action.params.x', op: 'eq', value: 1 }] }), act('a', 'a'.repeat(513), { x: 1 }))).toBe(true);
  });
  it('whenAffirmative: plain permission semantics (unresolvable => not matched)', () => {
    expect(whenAffirmative(amb('a'), act('a', '/r', { x: 1 }))).toBe(true);
    expect(whenAffirmative(amb('a'), act('a', '/r', { x: 2 }))).toBe(false);
    expect(whenAffirmative(amb('a'), act('a', '/r', {}))).toBe(false);
    expect(whenAffirmative(W('a'), act('a'))).toBe(true);
    expect(whenAffirmative(W('b'), act('a'))).toBe(false);
    expect(whenAffirmative(null as never, act('a'))).toBe(false);
    expect(whenAffirmative({ verb: '' } as never, act('a'))).toBe(false);
    expect(whenAffirmative(W('a', { resource: 're:(a+)+' }), act('a', 'a'))).toBe(false);
    expect(whenAffirmative(W('a'), null as never)).toBe(false);
    expect(whenAffirmative(W('a'), {} as never)).toBe(false);
  });
  it('whenMatches never throws', () => {
    const hostile = { get verb(): string { throw new Error('boom'); } } as never;
    expect(whenMatches(hostile, act('a'))).toBe(true);
    expect(whenAffirmative(hostile, act('a'))).toBe(false);
  });
});

describe('invariant forms (checkProhibitions)', () => {
  const chk = (invs: Invariant[], a: ActionContext, s: MonitorState = st()) => checkProhibitions(a, cons(invs), s);

  it('never', () => {
    const n = inv({ id: 'n', kind: 'never', when: W('drop') });
    expect(chk([n], act('read'))).toStrictEqual({ ok: true, violated: [], reasons: [], evaluated: [{ id: 'n', kind: 'never', result: 'pass' }] });
    expect(chk([n], act('drop'))).toStrictEqual({
      ok: false,
      violated: ['n'],
      reasons: ['n: forbidden action'],
      evaluated: [{ id: 'n', kind: 'never', result: 'violated', reason: 'forbidden action' }],
    });
    expect(chk([inv({ ...n, description: 'no drops' })], act('drop')).reasons).toEqual(['n: no drops']);
    // empty description: the row has no reason and the summary falls back to "violated"
    const e = chk([inv({ ...n, description: '' })], act('drop'));
    expect(e.evaluated).toStrictEqual([{ id: 'n', kind: 'never', result: 'violated' }]);
    expect(e.reasons).toEqual(['n: violated']);
  });
  it('never_unless: exceptions must hold AFFIRMATIVELY', () => {
    const nu = inv({ id: 'u', kind: 'never_unless', when: W('deploy'), unless: [{ field: 'action.params.approved', op: 'eq', value: true }] });
    expect(chk([nu], act('read')).ok).toBe(true);
    expect(chk([nu], act('deploy', '/r', { approved: true })).ok).toBe(true);
    const bad = chk([nu], act('deploy', '/r', { approved: false }));
    expect(bad.ok).toBe(false);
    expect(bad.reasons).toEqual(['u: forbidden without required condition']);
    expect(chk([nu], act('deploy', '/r', {})).ok).toBe(false); // unresolvable => still forbidden
    expect(chk([nu], act('deploy')).ok).toBe(false);
    expect(chk([inv({ ...nu, description: 'need approval' })], act('deploy', '/r', {})).reasons).toEqual(['u: need approval']);
    const two = inv({ id: 'u', kind: 'never_unless', when: W('deploy'), unless: [{ field: 'action.params.a', op: 'eq', value: 1 }, { field: 'action.params.b', op: 'eq', value: 1 }] });
    expect(chk([two], act('deploy', '/r', { a: 1, b: 1 })).ok).toBe(true);
    expect(chk([two], act('deploy', '/r', { a: 1, b: 2 })).ok).toBe(false);
    expect(chk([two], act('deploy', '/r', { a: 2, b: 1 })).ok).toBe(false);
    // the trigger itself is conservative
    const amb = inv({ id: 'u', kind: 'never_unless', when: W('deploy', { where: [{ field: 'action.params.env', op: 'eq', value: 'prod' }] }), unless: [{ field: 'action.params.ok', op: 'eq', value: true }] });
    expect(chk([amb], act('deploy', '/r', { env: 'dev' })).ok).toBe(true);
    expect(chk([amb], act('deploy', '/r', { ok: false })).ok).toBe(false); // env unresolvable => trigger matched
  });
  it('cap: boundaries, reasons, windows', () => {
    const cap = (o: Record<string, unknown> = {}) => inv({ id: 'c', kind: 'cap', when: W('spend'), amount: 'action.params.amt', max: 10, ...o });
    const s = (entries: Array<{ t: number; amount: number }>) => st({ ledger: { c: entries } });
    expect(chk([cap()], act('read', '/r', { amt: 1000 })).ok).toBe(true);
    expect(chk([cap()], act('spend', '/r', { amt: 10 })).ok).toBe(true); // equal to max is fine
    expect(chk([cap()], act('spend', '/r', { amt: 10.5 })).reasons).toEqual(['c: cap exceeded: 0 + 10.5 > 10']);
    expect(chk([cap()], act('spend', '/r', { amt: 4 }), s([{ t: NOW, amount: 6 }])).ok).toBe(true);
    expect(chk([cap()], act('spend', '/r', { amt: 5 }), s([{ t: NOW, amount: 6 }])).reasons).toEqual(['c: cap exceeded: 6 + 5 > 10']);
    expect(chk([cap({ max: 0 })], act('spend', '/r', { amt: 0 })).ok).toBe(true);
    expect(chk([cap({ max: 0 })], act('spend', '/r', { amt: 0.1 })).ok).toBe(false);
    // unresolvable / invalid amounts fail closed
    for (const p of [{}, { amt: -1 }, { amt: '5' }, { amt: NaN }, { amt: Infinity }, { amt: null }, undefined]) {
      const r = chk([cap()], act('spend', '/r', p as never));
      expect(r.ok, JSON.stringify(p)).toBe(false);
      expect(r.reasons).toEqual(['c: amount unresolvable (fail closed)']);
    }
    expect(chk([cap({ description: 'budget' })], act('spend', '/r', { amt: 99 })).reasons).toEqual(['c: cap exceeded: 0 + 99 > 10']); // a description does not replace the computed cap reason
    expect(chk([cap({ description: 'budget' })], act('spend', '/r', {})).reasons).toEqual(['c: amount unresolvable (fail closed)']); // description does not mask this
    // other ledger ids are ignored; a missing ledger is empty
    expect(chk([cap()], act('spend', '/r', { amt: 5 }), st({ ledger: { other: [{ t: NOW, amount: 999 }] } })).ok).toBe(true);
    // windowed: entries with t > now - window*1000 count (lower bound exclusive)
    const win = cap({ window_secs: 10 });
    expect(chk([win], act('spend', '/r', { amt: 5 }), s([{ t: NOW - 10_000, amount: 99 }])).ok).toBe(true); // exactly at the bound: expired
    expect(chk([win], act('spend', '/r', { amt: 5 }), s([{ t: NOW - 9_999, amount: 99 }])).ok).toBe(false);
    expect(chk([win], act('spend', '/r', { amt: 5 }), s([{ t: NOW - 20_000, amount: 99 }])).ok).toBe(true);
    // lifetime (no window): everything counts
    expect(chk([cap()], act('spend', '/r', { amt: 5 }), s([{ t: 1, amount: 99 }])).ok).toBe(false);
    // an entry at exactly `now` counts
    expect(chk([win], act('spend', '/r', { amt: 5 }), s([{ t: NOW, amount: 99 }])).ok).toBe(false);
    // float sums are order-independent: sorted by (t, amount) before summing
    const f = [{ t: 1, amount: 1e16 }, { t: 1, amount: 1 }, { t: 1, amount: 1 }];
    expect(chk([cap({ max: 1 })], act('spend', '/r', { amt: 5 }), s(f)).reasons).toEqual(['c: cap exceeded: 10000000000000002 + 5 > 1']);
    const g = [{ t: 3, amount: 1e16 }, { t: 1, amount: 1 }, { t: 2, amount: 1 }];
    expect(chk([cap({ max: 1 })], act('spend', '/r', { amt: 5 }), s(g)).reasons).toEqual(['c: cap exceeded: 10000000000000002 + 5 > 1']);
    const h = [{ t: 1, amount: 1e16 }, { t: 1, amount: 1 }, { t: 0, amount: 1 }];
    expect(chk([cap({ max: 1 })], act('spend', '/r', { amt: 5 }), s(h)).reasons).toEqual(['c: cap exceeded: 10000000000000002 + 5 > 1']);
  });
  it('rate: at most `max` per window including this one', () => {
    const rate = (o: Record<string, unknown> = {}) => inv({ id: 'r', kind: 'rate', when: W('call'), max: 2, window_secs: 60, ...o });
    const s = (ts: number[]) => st({ ledger: { r: ts.map((t) => ({ t, amount: 1 })) } });
    expect(chk([rate()], act('call'), s([])).ok).toBe(true);
    expect(chk([rate()], act('call'), s([NOW - 1000])).ok).toBe(true); // this would be the 2nd
    const over = chk([rate()], act('call'), s([NOW - 1000, NOW - 2000]));
    expect(over.ok).toBe(false);
    expect(over.reasons).toEqual(['r: rate exceeded: 3 > 2 per 60s']);
    expect(chk([rate({ description: 'slow down' })], act('call'), s([NOW - 1, NOW - 2])).reasons).toEqual(['r: rate exceeded: 3 > 2 per 60s']); // a description does not replace the computed rate reason
    expect(chk([rate({ max: 0 })], act('call'), s([])).reasons).toEqual(['r: rate exceeded: 1 > 0 per 60s']);
    expect(chk([rate()], act('other'), s([NOW - 1, NOW - 2, NOW - 3])).ok).toBe(true);
    // window lower bound is exclusive
    expect(chk([rate()], act('call'), s([NOW - 60_000, NOW - 60_000])).ok).toBe(true);
    expect(chk([rate()], act('call'), s([NOW - 59_999, NOW - 59_999])).ok).toBe(false);
    expect(chk([rate()], act('call'), s([NOW, NOW])).ok).toBe(false);
    expect(chk([rate({ window_secs: 0.5 })], act('call'), s([NOW - 499, NOW - 498])).ok).toBe(false);
    expect(chk([rate({ window_secs: 0.5 })], act('call'), s([NOW - 500, NOW - 600])).ok).toBe(true);
  });
  it('never_after: forbidden once the trigger has been latched', () => {
    const na = inv({ id: 'na', kind: 'never_after', after: W('lock'), forbid: W('write') });
    expect(chk([na], act('write')).ok).toBe(true); // not latched
    expect(chk([na], act('write'), st({ latched: { na: NOW } })).reasons).toEqual(['na: forbidden after trigger']);
    expect(chk([na], act('read'), st({ latched: { na: NOW } })).ok).toBe(true);
    expect(chk([na], act('write'), st({ latched: { other: NOW } })).ok).toBe(true);
    expect(chk([inv({ ...na, description: 'frozen' })], act('write'), st({ latched: { na: NOW } })).reasons).toEqual(['na: frozen']);
    expect(chk([na], act('lock')).ok).toBe(true); // the trigger itself is allowed
  });
  it('require_prior: forbidden until the prerequisite was admitted', () => {
    const rp = inv({ id: 'rp', kind: 'require_prior', when: W('deploy'), prior: W('review') });
    expect(chk([rp], act('read')).ok).toBe(true);
    expect(chk([rp], act('deploy')).reasons).toEqual(['rp: required prior action not admitted']);
    expect(chk([rp], act('deploy'), st({ latched: { rp: NOW } })).ok).toBe(true);
    expect(chk([rp], act('deploy'), st({ latched: { other: NOW } })).ok).toBe(false);
    expect(chk([inv({ ...rp, description: 'review first' })], act('deploy')).reasons).toEqual(['rp: review first']);
  });
  it('require_approval_over: amount > threshold needs approval; unresolvable counts as over', () => {
    const ra = (o: Record<string, unknown> = {}) =>
      inv({ id: 'ra', kind: 'require_approval_over', when: W('pay'), amount: 'action.params.amt', threshold: 100, approved: [{ field: 'action.params.ok', op: 'eq', value: true }], ...o });
    expect(chk([ra()], act('read', '/r', { amt: 1e9 })).ok).toBe(true);
    expect(chk([ra()], act('pay', '/r', { amt: 100 })).ok).toBe(true); // equal to threshold: not over
    expect(chk([ra()], act('pay', '/r', { amt: 99.99 })).ok).toBe(true);
    expect(chk([ra()], act('pay', '/r', { amt: 0 })).ok).toBe(true);
    expect(chk([ra()], act('pay', '/r', { amt: 100.01 })).reasons).toEqual(['ra: approval required over 100']);
    expect(chk([ra()], act('pay', '/r', { amt: 100.01, ok: true })).ok).toBe(true);
    expect(chk([ra()], act('pay', '/r', { amt: 100.01, ok: false })).ok).toBe(false);
    for (const p of [{}, { amt: -1 }, { amt: '5' }, { amt: NaN }, { amt: Infinity }, { amt: null }]) {
      expect(chk([ra()], act('pay', '/r', p as never)).ok, JSON.stringify(p)).toBe(false);
      expect(chk([ra()], act('pay', '/r', { ...p, ok: true } as never)).ok, JSON.stringify(p)).toBe(true);
    }
    expect(chk([ra({ description: 'ask a human' })], act('pay', '/r', { amt: 500 })).reasons).toEqual(['ra: ask a human']);
    expect(chk([ra({ threshold: 0 })], act('pay', '/r', { amt: 0 })).ok).toBe(true);
    expect(chk([ra({ threshold: 0 })], act('pay', '/r', { amt: 0.001 })).ok).toBe(false);
    const two = ra({ approved: [{ field: 'action.params.a', op: 'eq', value: 1 }, { field: 'action.params.b', op: 'eq', value: 1 }] });
    expect(chk([two], act('pay', '/r', { amt: 500, a: 1, b: 1 })).ok).toBe(true);
    expect(chk([two], act('pay', '/r', { amt: 500, a: 1, b: 2 })).ok).toBe(false);
    expect(chk([two], act('pay', '/r', { amt: 500, a: 2, b: 1 })).ok).toBe(false);
  });
  it('every invariant is evaluated in constitution order; ids and kinds in the trace', () => {
    const invs = [
      inv({ id: 'a', kind: 'never', when: W('x') }),
      inv({ id: 'b', kind: 'never', when: W('y') }),
      inv({ id: 'c', kind: 'rate', when: W('x'), max: 5, window_secs: 10 }),
      inv({ id: 'd', kind: 'never', when: W('x'), description: 'D' }),
    ];
    const r = chk(invs, act('x'));
    expect(r.evaluated.map((e) => `${e.id}:${e.kind}:${e.result}`)).toEqual(['a:never:violated', 'b:never:pass', 'c:rate:pass', 'd:never:violated']);
    expect(r.violated).toEqual(['a', 'd']);
    expect(r.reasons).toEqual(['a: forbidden action', 'd: D']);
    expect(r.ok).toBe(false);
  });
  it('structural refusals (reasons carry no id prefix)', () => {
    const noInv = cons([]);
    expect(checkProhibitions(act('x'), { version: 3, principal: PRIN, invariants: [] }, st())).toStrictEqual({
      ok: false,
      violated: ['<constitution>'],
      reasons: ['unsupported version 3'],
      evaluated: [{ id: '<constitution>', kind: 'structural', result: 'violated', reason: 'unsupported version 3' }],
    });
    for (const a of [null, undefined, {}, { action: null }, { action: { verb: 1, resource: '/r' } }, { action: { verb: 'x' } }, { action: { verb: 'x', resource: 1 } }]) {
      expect(checkProhibitions(a as never, noInv, st())).toStrictEqual({
        ok: false,
        violated: ['<action>'],
        reasons: ['malformed action'],
        evaluated: [{ id: '<action>', kind: 'structural', result: 'violated', reason: 'malformed action' }],
      });
    }
    expect(checkProhibitions(act('x'), noInv, { bad: 1 } as never)).toStrictEqual({
      ok: false,
      violated: ['<state>'],
      reasons: ['malformed monitor state'],
      evaluated: [{ id: '<state>', kind: 'structural', result: 'violated', reason: 'malformed monitor state' }],
    });
    // constitution is checked first, then action, then state
    expect(checkProhibitions({} as never, { version: 3 } as never, { bad: 1 } as never).violated).toEqual(['<constitution>']);
    expect(checkProhibitions({} as never, noInv, { bad: 1 } as never).violated).toEqual(['<action>']);
    expect(checkProhibitions(act('x'), noInv, st())).toStrictEqual({ ok: true, violated: [], reasons: [], evaluated: [] });
  });
  it('an invariant that throws while being evaluated is a violation (fail closed), the rest still run', () => {
    let n = 0;
    const flaky = {
      id: 'f',
      kind: 'never',
      get when() {
        if (n++ > 0) throw new Error('boom');
        return W('x');
      },
    };
    const r = checkProhibitions(act('zzz'), cons([flaky as never, inv({ id: 'g', kind: 'never', when: W('zzz') })]), st());
    expect(r.evaluated).toStrictEqual([
      { id: 'f', kind: 'never', result: 'violated', reason: 'evaluation error (fail closed)' },
      { id: 'g', kind: 'never', result: 'violated', reason: 'forbidden action' },
    ]);
    expect(r.reasons).toEqual(['f: evaluation error (fail closed)', 'g: forbidden action']);
  });
  it('a throwing top level fails closed with <monitor>', () => {
    const hostile = new Proxy({}, { get() { throw new Error('boom'); } }) as never;
    const r = checkProhibitions(hostile, cons([]), st());
    expect(r.ok).toBe(false);
  });
});

describe('advanceStateStrict', () => {
  const cap = (o: Record<string, unknown> = {}) => inv({ id: 'c', kind: 'cap', when: W('spend'), amount: 'action.params.amt', max: 1e9, ...o });
  const rate = (o: Record<string, unknown> = {}) => inv({ id: 'r', kind: 'rate', when: W('call'), max: 100, window_secs: 60, ...o });
  const adv = (invs: Invariant[], a: ActionContext, s: MonitorState = st(), now?: number) => advanceStateStrict(a, cons(invs), s, now);
  const okState = (r: ReturnType<typeof advanceStateStrict>): MonitorState => {
    if (!r.ok) throw new Error('refused: ' + r.reason);
    return r.state;
  };

  it('refusals with exact reasons', () => {
    expect(adv([], act('x'), st(), NOW - 1)).toStrictEqual({ ok: false, reason: 'clock regression' });
    for (const bad of [NaN, Infinity, '5', null]) expect(adv([], act('x'), st(), bad as never)).toStrictEqual({ ok: false, reason: 'clock regression' });
    expect(advanceStateStrict(act('x'), { version: 2, principal: PRIN, invariants: [] }, st())).toStrictEqual({ ok: false, reason: 'unsupported version 2' });
    expect(adv([], act('x'), { bad: 1 } as never)).toStrictEqual({ ok: false, reason: 'malformed monitor state' });
    expect(adv([], {} as never)).toStrictEqual({ ok: false, reason: 'malformed action' });
    expect(adv([], { action: { verb: 1, resource: 'r' } } as never)).toStrictEqual({ ok: false, reason: 'malformed action' });
    expect(adv([], { action: { verb: 'x', resource: 1 } } as never)).toStrictEqual({ ok: false, reason: 'malformed action' });
    // order: constitution, state, clock, action
    expect(advanceStateStrict({} as never, { version: 2 } as never, { bad: 1 } as never, NOW - 5)).toStrictEqual({ ok: false, reason: 'unsupported version 2' });
    expect(advanceStateStrict({} as never, cons([]), { bad: 1 } as never, NOW - 5)).toStrictEqual({ ok: false, reason: 'malformed monitor state' });
    expect(advanceStateStrict({} as never, cons([]), st(), NOW - 5)).toStrictEqual({ ok: false, reason: 'clock regression' });
    expect(adv([cap()], act('spend', '/r', {}))).toStrictEqual({ ok: false, reason: 'c: amount unresolvable' });
    expect(adv([cap()], act('spend', '/r', { amt: -1 }))).toStrictEqual({ ok: false, reason: 'c: amount unresolvable' });
    // NaN is not canonicalizable: the action cannot be digested at all => fail closed
    expect(adv([cap()], act('spend', '/r', { amt: NaN }))).toStrictEqual({ ok: false, reason: 'advance error (fail closed)' });
    expect(adv([cap()], act('read', '/r', {})).ok).toBe(true); // not matching: no amount needed
  });
  it('the chain link, seq and time', () => {
    const s0 = st();
    const a = act('x');
    const r = okState(adv([], a, s0, NOW + 7));
    expect(r.seq).toBe(1);
    expect(r.now).toBe(NOW + 7);
    expect(r.parent).toBe(hashCanonical({ d: STATE_CHAIN_DOMAIN, state: stateDigest(s0), action: hashCanonical(a) }));
    expect(STATE_CHAIN_DOMAIN).toBe('atlas-pca/monitor-state-link/v1');
    expect(r.ledger).toStrictEqual({});
    expect(r.latched).toStrictEqual({});
    expect('deadlines' in r).toBe(false);
    expect(okState(adv([], a, s0)).now).toBe(NOW);
    const r2 = okState(adv([], a, r));
    expect(r2.seq).toBe(2);
    expect(r2.parent).toBe(hashCanonical({ d: STATE_CHAIN_DOMAIN, state: stateDigest(r), action: hashCanonical(a) }));
    expect(r2.parent).not.toBe(r.parent);
    expect(s0.seq).toBe(0); // input untouched
    // equal `now` is fine
    expect(adv([], a, s0, NOW).ok).toBe(true);
  });
  it('cap / rate contributions recorded; non-matching actions record nothing', () => {
    const invs = [cap(), rate()];
    let s = okState(adv(invs, act('spend', '/r', { amt: 3 })));
    expect(s.ledger).toStrictEqual({ c: [{ t: NOW, amount: 3 }] });
    s = okState(adv(invs, act('call'), s, NOW + 5));
    expect(s.ledger).toStrictEqual({ c: [{ t: NOW, amount: 3 }], r: [{ t: NOW + 5, amount: 1 }] });
    s = okState(adv(invs, act('other'), s, NOW + 6));
    expect(s.ledger).toStrictEqual({ c: [{ t: NOW, amount: 3 }], r: [{ t: NOW + 5, amount: 1 }] });
    s = okState(adv(invs, act('spend', '/r', { amt: 0 }), s, NOW + 7));
    expect(s.ledger['c']).toStrictEqual([{ t: NOW, amount: 3 }, { t: NOW + 7, amount: 0 }]);
    // entries come out sorted by (t, amount)
    const unsorted = st({ ledger: { c: [{ t: NOW, amount: 9 }, { t: NOW - 10, amount: 1 }] } });
    expect(okState(adv([cap()], act('spend', '/r', { amt: 2 }), unsorted)).ledger['c']).toStrictEqual([{ t: NOW - 10, amount: 1 }, { t: NOW, amount: 2 }, { t: NOW, amount: 9 }]);
  });
  it('windowed ledgers prune expired entries (lower bound exclusive); lifetime ledgers keep everything; empty ledgers are deleted', () => {
    const win = cap({ window_secs: 10 });
    const s = st({ ledger: { c: [{ t: NOW - 10_000, amount: 1 }, { t: NOW - 9_999, amount: 2 }, { t: NOW - 50_000, amount: 4 }] } });
    expect(okState(adv([win], act('spend', '/r', { amt: 8 }), s)).ledger['c']).toStrictEqual([{ t: NOW - 9_999, amount: 2 }, { t: NOW, amount: 8 }]);
    // pruning is relative to the NEW time
    expect(okState(adv([win], act('spend', '/r', { amt: 8 }), s, NOW + 5_000)).ledger['c']).toStrictEqual([{ t: NOW + 5_000, amount: 8 }]);
    // pruned to nothing and nothing added => key removed
    const gone = okState(adv([win], act('read'), s, NOW + 60_000));
    expect('c' in gone.ledger).toBe(false);
    expect(gone.ledger).toStrictEqual({});
    // lifetime keeps old entries
    const life = st({ ledger: { c: [{ t: 1, amount: 1 }] } });
    expect(okState(adv([cap()], act('read'), life, NOW + 10 ** 9)).ledger['c']).toStrictEqual([{ t: 1, amount: 1 }]);
    // an existing ledger for an id that is no longer a cap/rate invariant is dropped from the next state? (it is copied)
    const stray = st({ ledger: { stray: [{ t: 1, amount: 1 }] } });
    expect(okState(adv([cap()], act('read'), stray)).ledger).toStrictEqual({ stray: [{ t: 1, amount: 1 }] });
  });
  it('cap ledger overflow merges the OLDEST TWO entries (keeping the later time) so a cap is never under-counted', () => {
    const entries = Array.from({ length: MAX_LEDGER }, (_, i) => ({ t: i + 1, amount: 1 }));
    const s = st({ ledger: { c: entries } });
    const r = okState(adv([cap()], act('spend', '/r', { amt: 5 }), s));
    const l = r.ledger['c']!;
    expect(l.length).toBe(MAX_LEDGER);
    expect(l[0]).toStrictEqual({ t: 2, amount: 2 });
    expect(l[1]).toStrictEqual({ t: 3, amount: 1 });
    expect(l[l.length - 1]).toStrictEqual({ t: NOW, amount: 5 });
    expect(l.reduce((a, e) => a + e.amount, 0)).toBe(MAX_LEDGER + 5);
    // exactly at the limit nothing is merged
    const s2 = st({ ledger: { c: entries.slice(1) } });
    const r2 = okState(adv([cap()], act('spend', '/r', { amt: 5 }), s2));
    expect(r2.ledger['c']!.length).toBe(MAX_LEDGER);
    expect(r2.ledger['c']![0]).toStrictEqual({ t: 2, amount: 1 });
  });
  it('rate ledger overflow is refused (never silently dropped)', () => {
    const entries = Array.from({ length: MAX_LEDGER }, (_, i) => ({ t: NOW - 1 - i, amount: 1 }));
    const s = st({ ledger: { r: entries } });
    expect(adv([rate({ max: MAX_LEDGER, window_secs: 1e9 })], act('call'), s)).toStrictEqual({ ok: false, reason: 'r: rate ledger overflow' });
    // one fewer fits
    expect(adv([rate({ max: MAX_LEDGER, window_secs: 1e9 })], act('call'), st({ ledger: { r: entries.slice(1) } })).ok).toBe(true);
    // a non-matching action does not overflow
    expect(adv([rate({ max: MAX_LEDGER, window_secs: 1e9 })], act('other'), s).ok).toBe(true);
  });
  it('latches: never_after on a CONSERVATIVE match, require_prior on an AFFIRMATIVE match; first observation wins', () => {
    const amb = (v: string) => W(v, { where: [{ field: 'action.params.x', op: 'eq', value: 1 }] });
    const invs = [inv({ id: 'na', kind: 'never_after', after: amb('lock'), forbid: W('write') }), inv({ id: 'rp', kind: 'require_prior', when: W('deploy'), prior: amb('review') })];
    let s = okState(adv(invs, act('lock', '/r', {}), st(), NOW + 1)); // ambiguous trigger latches
    expect(s.latched).toStrictEqual({ na: NOW + 1 });
    s = okState(adv(invs, act('lock', '/r', {}), s, NOW + 9)); // (time moves on: later calls use later times) // already latched: unchanged
    expect(s.latched).toStrictEqual({ na: NOW + 1 });
    expect(okState(adv(invs, act('lock', '/r', { x: 2 }))).latched).toStrictEqual({}); // cleanly false
    expect(okState(adv(invs, act('review', '/r', {}))).latched).toStrictEqual({}); // ambiguous prerequisite does NOT latch
    expect(okState(adv(invs, act('review', '/r', { x: 2 }))).latched).toStrictEqual({});
    s = okState(adv(invs, act('review', '/r', { x: 1 }), s, NOW + 10));
    expect(s.latched).toStrictEqual({ na: NOW + 1, rp: NOW + 10 });
    s = okState(adv(invs, act('review', '/r', { x: 1 }), s, NOW + 11));
    expect(s.latched).toStrictEqual({ na: NOW + 1, rp: NOW + 10 });
    expect(okState(adv(invs, act('other'), st())).latched).toStrictEqual({});
  });
  it('resulting state invalid => refused (total ledger entries cap)', () => {
    const ledger: Record<string, Array<{ t: number; amount: number }>> = {};
    for (let i = 0; i < 10; i++) ledger['k' + i] = Array.from({ length: MAX_LEDGER }, () => ({ t: 1, amount: 0 }));
    const s = st({ ledger });
    const invs = [inv({ id: 'extra', kind: 'cap', when: W('spend'), amount: 'action.params.amt', max: 5 })];
    expect(adv(invs, act('spend', '/r', { amt: 1 }), s)).toStrictEqual({ ok: false, reason: 'resulting state invalid' });
    expect(adv(invs, act('read'), s).ok).toBe(true);
  });
  it('never throws: a throwing getter fails closed', () => {
    const mk = (limit: number) => {
      let n = 0;
      return { id: 'f', kind: 'never_after', forbid: W('y'), get after() { if (n++ >= limit) throw new Error('boom'); return W('x'); }, get reads() { return n; } };
    };
    const probe = mk(Infinity);
    expect(validateConstitution(cons([probe as never]))).toEqual([]);
    const reads = probe.reads;
    expect(reads).toBeGreaterThan(0);
    expect(advanceStateStrict(act('x'), cons([mk(reads) as never]), st())).toStrictEqual({ ok: false, reason: 'advance error (fail closed)' });
    expect(advanceStateStrict(act('x'), cons([mk(Infinity) as never]), st()).ok).toBe(true);
  });
  it('advanceState returns the NEW state on success and the SAME input object on failure', () => {
    const s = st();
    const good = advanceState(act('x'), cons([]), s);
    expect(good.seq).toBe(1);
    expect(good).not.toBe(s);
    expect(advanceState(act('x'), cons([]), s, NOW + 3).now).toBe(NOW + 3);
    expect(advanceState(act('x'), cons([]), s, NOW - 3)).toBe(s);
    expect(advanceState({} as never, cons([]), s)).toBe(s);
  });
});

describe('safety evidence', () => {
  const C = cons([inv({ id: 'n', kind: 'never', when: W('drop') }), inv({ id: 'r', kind: 'rate', when: W('call'), max: 2, window_secs: 60 })]);
  const A = act('call');
  const S = st();
  it('proveSafety: every field', () => {
    const e = proveSafety(A, C, S);
    expect(e).toStrictEqual({
      v: EVIDENCE_VERSION,
      constitution: constitutionId(C),
      action_digest: hashCanonical(A),
      state_digest: stateDigest(S),
      now: NOW,
      evaluated: [{ id: 'n', kind: 'never', result: 'pass' }, { id: 'r', kind: 'rate', result: 'pass' }],
      ok: true,
      violated: [],
    });
    expect(EVIDENCE_VERSION).toBe(1);
    const v = proveSafety(act('drop'), C, S);
    expect(v.ok).toBe(false);
    expect(v.violated).toEqual(['n']);
    expect(v.evaluated[0]).toStrictEqual({ id: 'n', kind: 'never', result: 'violated', reason: 'forbidden action' });
  });
  it('unbindable pieces make the evidence not-ok with the structural id appended once', () => {
    const badState = proveSafety(A, C, { bad: 1 } as never);
    expect(badState.state_digest).toBe('<unhashable>');
    expect(badState.ok).toBe(false);
    expect(badState.violated).toEqual(['<state>']); // already reported by the monitor: not duplicated
    expect(badState.now).toBe(0);
    const badCons = proveSafety(A, { version: 2 } as never, S);
    expect(badCons.violated).toEqual(['<constitution>']);
    expect(badCons.ok).toBe(false);
    const unhashable = act('call', '/r', { f: (() => 1) as never });
    const badAct = proveSafety(unhashable, C, S);
    expect(badAct.action_digest).toBe('<unhashable>');
    expect(badAct.ok).toBe(false);
    expect(badAct.violated).toEqual(['<action>']); // the monitor itself passed; the digest failed
    expect(badAct.evaluated.length).toBe(2);
    const both = proveSafety(unhashable, { version: 2 } as never, { bad: 1 } as never);
    expect(both.violated).toEqual(['<constitution>', '<action>', '<state>']);
    expect(proveSafety(A, C, { ...S, now: NaN } as never).now).toBe(0);
    // an uncanonicalizable constitution (extra function field) is flagged although the monitor accepts it
    const ext = { ...C, extra: () => 1 } as unknown as Constitution;
    const e = proveSafety(A, ext, S);
    expect(e.constitution).toBe('<unhashable>');
    expect(e.ok).toBe(false);
    expect(e.violated).toEqual(['<constitution>']);
  });
  it('evidenceDigest = hashCanonical(evidence)', () => {
    const e = proveSafety(A, C, S);
    expect(evidenceDigest(e)).toBe(hashCanonical(e));
    expect(evidenceDigest({ ...e, now: e.now + 1 })).not.toBe(evidenceDigest(e));
  });
  it('verifySafetyEvidence: honest evidence verifies; each tamper has its own reason; order of checks', () => {
    const e = proveSafety(A, C, S);
    expect(verifySafetyEvidence(e, A, C, S)).toEqual({ ok: true });
    expect(verifySafetyEvidence(null as never, A, C, S)).toEqual({ ok: false, reason: 'unsupported evidence version' });
    expect(verifySafetyEvidence({ ...e, v: 2 }, A, C, S)).toEqual({ ok: false, reason: 'unsupported evidence version' });
    expect(verifySafetyEvidence({ ...e, constitution: 'x' }, A, C, S)).toEqual({ ok: false, reason: 'constitution mismatch' });
    expect(verifySafetyEvidence({ ...e, action_digest: 'x' }, A, C, S)).toEqual({ ok: false, reason: 'action digest mismatch' });
    expect(verifySafetyEvidence({ ...e, state_digest: 'x' }, A, C, S)).toEqual({ ok: false, reason: 'state digest mismatch' });
    expect(verifySafetyEvidence({ ...e, now: e.now + 1 }, A, C, S)).toEqual({ ok: false, reason: 'evidence does not reproduce' });
    expect(verifySafetyEvidence({ ...e, evaluated: [] }, A, C, S)).toEqual({ ok: false, reason: 'evidence does not reproduce' });
    // constitution mismatch is reported before action mismatch before state mismatch
    expect(verifySafetyEvidence({ ...e, constitution: 'x', action_digest: 'y', state_digest: 'z' }, A, C, S).reason).toBe('constitution mismatch');
    expect(verifySafetyEvidence({ ...e, action_digest: 'y', state_digest: 'z' }, A, C, S).reason).toBe('action digest mismatch');
    // evidence for another action
    expect(verifySafetyEvidence(e, act('call', '/other'), C, S).reason).toBe('action digest mismatch');
    // violating evidence is reproduced but never accepted as an admit
    const v = proveSafety(act('drop'), C, S);
    expect(verifySafetyEvidence(v, act('drop'), C, S)).toEqual({ ok: false, reason: 'prohibition violated: n' });
    // forged "all clear" for a violating action does not reproduce
    expect(verifySafetyEvidence({ ...v, ok: true, violated: [], evaluated: e.evaluated }, act('drop'), C, S)).toEqual({ ok: false, reason: 'evidence does not reproduce' });
    const two = cons([inv({ id: 'a', kind: 'never', when: W('x') }), inv({ id: 'b', kind: 'never', when: W('x') })]);
    expect(verifySafetyEvidence(proveSafety(act('x'), two, S), act('x'), two, S)).toEqual({ ok: false, reason: 'prohibition violated: a,b' });
    // never throws
    expect(verifySafetyEvidence(e, A, C, new Proxy({}, { get() { throw new Error('boom'); } }) as never).ok).toBe(false);
  });
});

describe('signSafetyEvidence / safetyBindingId', () => {
  const C = cons([inv({ id: 'n', kind: 'never', when: W('drop') })]);
  const A = act('read');
  const S = st();
  const E = proveSafety(A, C, S);
  it('safetyBindingId commits to signer + evidence digest + the three digests under the domain', () => {
    expect(SAFETY_EVIDENCE_SIG_DOMAIN).toBe('atlas-pca/safety-evidence/v1\0');
    expect(safetyBindingId(E, SIGNER_PUB)).toBe(
      hashCanonical({ d: SAFETY_EVIDENCE_SIG_DOMAIN, signer: SIGNER_PUB, evidence: hashCanonical(E), constitution: E.constitution, action_digest: E.action_digest, state_digest: E.state_digest }),
    );
    expect(safetyBindingId(E, SIGNER_PUB)).not.toBe(safetyBindingId(E, encodeKey(K2.publicKey)));
    expect(safetyBindingId({ ...E, now: E.now + 1 }, SIGNER_PUB)).not.toBe(safetyBindingId(E, SIGNER_PUB));
  });
  it('signSafetyEvidence: shape, signature bytes, refusal messages', () => {
    const s = signSafetyEvidence(E, SIGNER.secretKey, SIGNER_PUB);
    expect(Object.keys(s).sort()).toEqual(['evidence', 'id', 'sig', 'signer']);
    expect(s.evidence).toBe(E);
    expect(s.signer).toBe(SIGNER_PUB);
    expect(s.id).toBe(safetyBindingId(E, SIGNER_PUB));
    expect(s.sig).toBe(b64u(sign(SIGNER.secretKey, new Uint8Array([...utf8(SAFETY_EVIDENCE_SIG_DOMAIN), ...sha256(utf8(s.id))]))));
    const unsupported = new TypeError('signSafetyEvidence: unsupported evidence');
    expect(() => signSafetyEvidence(null as never, SIGNER.secretKey, SIGNER_PUB)).toThrow(unsupported);
    expect(() => signSafetyEvidence({ ...E, v: 2 }, SIGNER.secretKey, SIGNER_PUB)).toThrow(unsupported);
    const unbound = new TypeError('signSafetyEvidence: unbound evidence');
    for (const f of ['constitution', 'action_digest', 'state_digest'] as const) {
      expect(() => signSafetyEvidence({ ...E, [f]: '<unhashable>' }, SIGNER.secretKey, SIGNER_PUB)).toThrow(unbound);
      expect(() => signSafetyEvidence({ ...E, [f]: '' }, SIGNER.secretKey, SIGNER_PUB)).toThrow(unbound);
      expect(() => signSafetyEvidence({ ...E, [f]: 5 as never }, SIGNER.secretKey, SIGNER_PUB)).toThrow(unbound);
      expect(() => signSafetyEvidence({ ...E, [f]: undefined as never }, SIGNER.secretKey, SIGNER_PUB)).toThrow(unbound);
    }
    const missing = new TypeError('signSafetyEvidence: signer missing');
    expect(() => signSafetyEvidence(E, SIGNER.secretKey, '')).toThrow(missing);
    expect(() => signSafetyEvidence(E, SIGNER.secretKey, undefined as never)).toThrow(missing);
    expect(() => signSafetyEvidence(E, SIGNER.secretKey, 5 as never)).toThrow(missing);
    // violation evidence may be signed (audit)
    const v = proveSafety(act('drop'), C, S);
    expect(() => signSafetyEvidence(v, SIGNER.secretKey, SIGNER_PUB)).not.toThrow();
  });
});

describe('verifySignedSafetyEvidence', () => {
  const C = cons([inv({ id: 'n', kind: 'never', when: W('drop') }), inv({ id: 'r', kind: 'rate', when: W('call'), max: 3, window_secs: 60 })]);
  const SC = signConstitution(C, K.secretKey);
  const A = act('call');
  const S = st();
  const E = proveSafety(A, C, S);
  const SIGNED = signSafetyEvidence(E, SIGNER.secretKey, SIGNER_PUB);
  const full = { signer: SIGNER_PUB, action: A, constitution: C, state: S };
  const vs = (signed: unknown, expected: unknown) => verifySignedSafetyEvidence(signed as never, expected as never);
  const no = (reason: string) => ({ ok: false, reason });

  it('accepts: full recomputation, and digest-only expectations', () => {
    expect(vs(SIGNED, full)).toEqual({ ok: true });
    expect(vs(SIGNED, { signer: [SIGNER_PUB, 'other'], actionDigest: E.action_digest, constitutionId: E.constitution, stateDigest: E.state_digest })).toEqual({ ok: true });
    expect(vs(SIGNED, { signer: SIGNER_PUB, action: A, actionDigest: hashCanonical(A), constitution: C, constitutionId: constitutionId(C), state: S, stateDigest: stateDigest(S) })).toEqual({ ok: true });
    expect(vs(SIGNED, { ...full, principal: PRIN, constitution: SC })).toEqual({ ok: true });
    expect(vs(SIGNED, { ...full, requireOk: true })).toEqual({ ok: true });
  });
  it('malformed input / version / signer pinning', () => {
    for (const bad of [null, undefined, 5, 'x', []]) expect(vs(bad, full)).toEqual(no('malformed input'));
    expect(vs({ ...SIGNED, evidence: null }, full)).toEqual(no('malformed input'));
    expect(vs({ ...SIGNED, evidence: [] }, full)).toEqual(no('malformed input'));
    expect(vs({ ...SIGNED, evidence: 5 }, full)).toEqual(no('malformed input'));
    for (const bad of [null, undefined, 5, 'x']) expect(vs(SIGNED, bad)).toEqual(no('malformed input'));
    expect(vs({ ...SIGNED, evidence: { ...E, v: 2 } }, full)).toEqual(no('unsupported evidence version'));
    for (const signer of [[], [''], [5], [SIGNER_PUB, ''], [SIGNER_PUB, 5], '', undefined, null, 5]) {
      expect(vs(SIGNED, { ...full, signer }), JSON.stringify(signer)).toEqual(no('no pinned signer'));
    }
    expect(vs(SIGNED, { ...full, signer: encodeKey(K2.publicKey) })).toEqual(no('signer not trusted'));
    expect(vs(SIGNED, { ...full, signer: [encodeKey(K2.publicKey)] })).toEqual(no('signer not trusted'));
    expect(vs({ ...SIGNED, signer: 5 }, full)).toEqual(no('signer not trusted'));
    expect(vs({ ...SIGNED, signer: undefined }, full)).toEqual(no('signer not trusted'));
  });
  it('expectations must bind action, constitution and state', () => {
    expect(vs(SIGNED, { signer: SIGNER_PUB, constitution: C, state: S })).toEqual(no('unbound: action not specified'));
    expect(vs(SIGNED, { signer: SIGNER_PUB, action: A, state: S })).toEqual(no('unbound: constitution not specified'));
    expect(vs(SIGNED, { signer: SIGNER_PUB, action: A, constitution: C })).toEqual(no('unbound: state not specified'));
    expect(vs(SIGNED, { signer: SIGNER_PUB })).toEqual(no('unbound: action not specified'));
    expect(vs(SIGNED, { signer: SIGNER_PUB, actionDigest: E.action_digest, constitution: C, state: S })).toEqual({ ok: true });
    expect(vs(SIGNED, { signer: SIGNER_PUB, action: A, constitutionId: E.constitution, stateDigest: E.state_digest })).toEqual({ ok: true });
    expect(vs(SIGNED, { signer: SIGNER_PUB, actionDigest: E.action_digest, constitutionId: E.constitution, state: S })).toEqual({ ok: true });
  });
  it('binding id and signature', () => {
    expect(vs({ ...SIGNED, id: 'x' }, full)).toEqual(no('binding id mismatch'));
    expect(vs({ ...SIGNED, id: 5 }, full)).toEqual(no('binding id mismatch'));
    expect(vs({ ...SIGNED, id: undefined }, full)).toEqual(no('binding id mismatch'));
    // re-attributing the evidence to another signer changes the binding id
    expect(vs({ ...SIGNED, signer: encodeKey(K2.publicKey) }, { ...full, signer: encodeKey(K2.publicKey) })).toEqual(no('binding id mismatch'));
    expect(vs({ ...SIGNED, sig: 5 }, full)).toEqual(no('bad signature'));
    expect(vs({ ...SIGNED, sig: undefined }, full)).toEqual(no('bad signature'));
    expect(vs({ ...SIGNED, sig: 'AAAA' }, full)).toEqual(no('bad signature'));
    const bare = { ...SIGNED, sig: b64u(sign(SIGNER.secretKey, sha256(utf8(SIGNED.id)))) };
    expect(vs(bare, full)).toEqual(no('bad signature'));
    const wrongDomain = { ...SIGNED, sig: b64u(sign(SIGNER.secretKey, new Uint8Array([...utf8('atlas-pca/constitution/v1\0'), ...sha256(utf8(SIGNED.id))]))) };
    expect(vs(wrongDomain, full)).toEqual(no('bad signature'));
    const swapped = { ...SIGNED, sig: b64u(sign(SIGNER.secretKey, new Uint8Array([...sha256(utf8(SIGNED.id)), ...utf8(SAFETY_EVIDENCE_SIG_DOMAIN)]))) };
    expect(vs(swapped, full)).toEqual(no('bad signature'));
    // tampered evidence: binding id no longer matches
    expect(vs({ ...SIGNED, evidence: { ...E, now: E.now + 1 } }, full)).toEqual(no('binding id mismatch'));
  });
  it('digest disagreements and binding to the expected action / constitution / state', () => {
    expect(vs(SIGNED, { ...full, actionDigest: 'other' })).toEqual(no('expected action and digest disagree'));
    expect(vs(SIGNED, { ...full, constitutionId: 'other' })).toEqual(no('expected constitution and id disagree'));
    expect(vs(SIGNED, { ...full, stateDigest: 'other' })).toEqual(no('expected state and digest disagree'));
    expect(vs(SIGNED, { ...full, action: act('call', '/elsewhere') })).toEqual(no('action digest mismatch (evidence bound to another action)'));
    expect(vs(SIGNED, { ...full, action: undefined, actionDigest: 'other' })).toEqual(no('action digest mismatch (evidence bound to another action)'));
    expect(vs(SIGNED, { ...full, constitution: cons([]) })).toEqual(no('constitution mismatch (evidence bound to another constitution)'));
    expect(vs(SIGNED, { ...full, constitution: undefined, constitutionId: 'other' })).toEqual(no('constitution mismatch (evidence bound to another constitution)'));
    expect(vs(SIGNED, { ...full, state: st({ seq: 1, parent: 'p' }) })).toEqual(no('state digest mismatch (evidence bound to another state)'));
    expect(vs(SIGNED, { ...full, state: undefined, stateDigest: 'other' })).toEqual(no('state digest mismatch (evidence bound to another state)'));
    // order: action, then principal pin, then constitution, then state
    expect(vs(SIGNED, { ...full, action: act('call', '/elsewhere'), constitution: cons([]), state: st({ now: NOW + 1 }) })).toEqual(no('action digest mismatch (evidence bound to another action)'));
    expect(vs(SIGNED, { ...full, constitution: cons([]), state: st({ now: NOW + 1 }) })).toEqual(no('constitution mismatch (evidence bound to another constitution)'));
  });
  it('principal pin: needs a signed constitution that verifies', () => {
    expect(vs(SIGNED, { ...full, principal: PRIN })).toEqual(no('principal pin requires a signed constitution')); // unsigned
    expect(vs(SIGNED, { signer: SIGNER_PUB, action: A, constitutionId: E.constitution, state: S, principal: PRIN })).toEqual(no('principal pin requires a signed constitution'));
    expect(vs(SIGNED, { ...full, constitution: { ...SC, sig: 5 } as never, principal: PRIN })).toEqual(no('principal pin requires a signed constitution'));
    expect(vs(SIGNED, { ...full, constitution: SC, principal: encodeKey(K2.publicKey) })).toEqual(no('constitution not authentic: principal mismatch'));
    expect(vs(SIGNED, { ...full, constitution: { ...SC, sig: 'AAAA' } as never, principal: PRIN })).toEqual(no('constitution not authentic: bad signature'));
    expect(vs(SIGNED, { ...full, constitution: SC, principal: PRIN })).toEqual({ ok: true });
  });
  it('internal consistency of the evidence', () => {
    const bind = (ev: unknown) => signSafetyEvidence(ev as ProhibitionEvidence, SIGNER.secretKey, SIGNER_PUB);
    const dig = { signer: SIGNER_PUB, actionDigest: E.action_digest, constitutionId: E.constitution, stateDigest: E.state_digest };
    expect(vs(bind({ ...E, evaluated: 'x' }), dig)).toEqual(no('malformed evidence'));
    expect(vs(bind({ ...E, violated: 'x' }), dig)).toEqual(no('malformed evidence'));
    expect(vs(bind({ ...E, evaluated: null }), dig)).toEqual(no('malformed evidence'));
    expect(vs(bind({ ...E, violated: null }), dig)).toEqual(no('malformed evidence'));
    // claims ok but a row is violated
    expect(vs(bind({ ...E, evaluated: [{ id: 'n', kind: 'never', result: 'violated' }] }), dig)).toEqual(no('evidence verdict inconsistent with rows'));
    // claims ok but lists a violation
    expect(vs(bind({ ...E, violated: ['n'] }), dig)).toEqual(no('evidence verdict inconsistent with rows'));
    // claims violation with all rows passing and nothing violated
    expect(vs(bind({ ...E, ok: false }), dig, )).toEqual(no('evidence verdict inconsistent with rows'));
    // a null row is not a pass
    expect(vs(bind({ ...E, evaluated: [null] }), dig)).toEqual(no('evidence verdict inconsistent with rows'));
    // a row with a non-'pass' result
    expect(vs(bind({ ...E, evaluated: [{ id: 'n', result: 'weird' }] }), dig)).toEqual(no('evidence verdict inconsistent with rows'));
  });
  it('coverage of every invariant when only the constitution (not action+state) is supplied', () => {
    const dig = { signer: SIGNER_PUB, actionDigest: E.action_digest, constitution: C, stateDigest: E.state_digest };
    expect(vs(SIGNED, dig)).toEqual({ ok: true });
    const missing = signSafetyEvidence({ ...E, evaluated: E.evaluated.slice(1) }, SIGNER.secretKey, SIGNER_PUB);
    expect(vs(missing, dig)).toEqual(no('evidence does not cover every invariant'));
    const extra = signSafetyEvidence({ ...E, evaluated: [...E.evaluated, { id: 'zz', kind: 'never', result: 'pass' }] }, SIGNER.secretKey, SIGNER_PUB);
    expect(vs(extra, dig)).toEqual(no('evidence does not cover every invariant'));
    const reordered = signSafetyEvidence({ ...E, evaluated: [...E.evaluated].reverse() }, SIGNER.secretKey, SIGNER_PUB);
    expect(vs(reordered, dig)).toEqual(no('evidence does not cover every invariant'));
    const renamed = signSafetyEvidence({ ...E, evaluated: [E.evaluated[0]!, { ...E.evaluated[1]!, id: 'other' }] }, SIGNER.secretKey, SIGNER_PUB);
    expect(vs(renamed, dig)).toEqual(no('evidence does not cover every invariant'));
    // coverage is only enforced for an ok claim, and only when a constitution object is given
    expect(vs(SIGNED, { signer: SIGNER_PUB, actionDigest: E.action_digest, constitutionId: E.constitution, stateDigest: E.state_digest })).toEqual({ ok: true });
  });
  it('full recomputation catches lies the rows alone cannot', () => {
    // evidence internally consistent and correctly bound, but not what the monitor would say
    const lie = signSafetyEvidence({ ...E, now: E.now + 1 }, SIGNER.secretKey, SIGNER_PUB);
    expect(vs(lie, full)).toEqual(no('evidence does not reproduce'));
    // an honest veto record: authentic, reproduces, but rejected unless requireOk:false
    const veto = proveSafety(act('drop'), C, S);
    const sv = signSafetyEvidence(veto, SIGNER.secretKey, SIGNER_PUB);
    const vfull = { ...full, action: act('drop') };
    expect(vs(sv, vfull)).toEqual(no('prohibition violated: n'));
    expect(vs(sv, { ...vfull, requireOk: false })).toEqual({ ok: true });
    expect(vs(sv, { ...vfull, requireOk: true })).toEqual(no('prohibition violated: n'));
    // veto evidence supplied with digests only: still rejected by default, authentic with requireOk:false
    const vdig = { signer: SIGNER_PUB, actionDigest: veto.action_digest, constitutionId: veto.constitution, stateDigest: veto.state_digest };
    expect(vs(sv, vdig)).toEqual(no('prohibition violated: n'));
    expect(vs(sv, { ...vdig, requireOk: false })).toEqual({ ok: true });
    // a forged "violated" record for an action that actually passes does not reproduce
    const forged = signSafetyEvidence({ ...veto, action_digest: E.action_digest }, SIGNER.secretKey, SIGNER_PUB);
    expect(vs(forged, { ...full, requireOk: false })).toEqual(no('evidence does not reproduce'));
    // a forged "all clear" for an action that violates
    const clear = signSafetyEvidence({ ...E, action_digest: veto.action_digest }, SIGNER.secretKey, SIGNER_PUB);
    expect(vs(clear, vfull)).toEqual(no('evidence does not reproduce'));
    expect(vs(clear, vfull)).toEqual(no('evidence does not reproduce'));
  });
  it('never throws', () => {
    expect(vs(SIGNED, { ...full, state: new Proxy({}, { get() { throw new Error('boom'); } }) })).toEqual(no('verification error (fail closed)'));
  });
});

describe('composeAuthority', () => {
  const C = cons([inv({ id: 'n', kind: 'never', when: W('drop') })]);
  it('allow = permitted AND prohibitions.ok; decidedBy names the layer that said no (prohibition wins)', () => {
    const ok = composeAuthority(true, act('read'), C, st());
    expect(ok.allow).toBe(true);
    expect(ok.decidedBy).toBe('none');
    expect(ok.permitted).toBe(true);
    expect(ok.prohibition.ok).toBe(true);
    const noPerm = composeAuthority(false, act('read'), C, st());
    expect(noPerm.allow).toBe(false);
    expect(noPerm.decidedBy).toBe('permission');
    expect(noPerm.permitted).toBe(false);
    expect(noPerm.prohibition.ok).toBe(true);
    const veto = composeAuthority(true, act('drop'), C, st());
    expect(veto.allow).toBe(false);
    expect(veto.decidedBy).toBe('prohibition');
    expect(veto.permitted).toBe(true);
    expect(veto.prohibition.violated).toEqual(['n']);
    const both = composeAuthority(false, act('drop'), C, st());
    expect(both.allow).toBe(false);
    expect(both.decidedBy).toBe('prohibition'); // the monitor runs even when not permitted; prohibitions win
    expect(both.permitted).toBe(false);
    expect(both.prohibition.violated).toEqual(['n']);
  });
  it('only a literal `true` is permission', () => {
    for (const p of [1, 'true', {}, [], 'yes', null, undefined]) {
      const r = composeAuthority(p as never, act('read'), C, st());
      expect(r.allow).toBe(false);
      expect(r.permitted).toBe(false);
      expect(r.decidedBy).toBe('permission');
    }
  });
});

describe('checkAndAdvance', () => {
  const C = cons([inv({ id: 'n', kind: 'never', when: W('drop') }), inv({ id: 'r', kind: 'rate', when: W('call'), max: 2, window_secs: 60 })]);
  it('allow: next state advanced, evidence over the PRE-state, no reason key', () => {
    const s0 = st();
    const r = checkAndAdvance(true, act('call'), C, s0);
    expect(r.allow).toBe(true);
    expect(r.decidedBy).toBe('none');
    expect('reason' in r).toBe(false);
    expect(r.next.seq).toBe(1);
    expect(r.next.ledger['r']).toStrictEqual([{ t: NOW, amount: 1 }]);
    expect(r.evidence.state_digest).toBe(stateDigest(s0));
    expect(r.evidence.ok).toBe(true);
    expect(r.prohibition.ok).toBe(true);
    const ref = advanceStateStrict(act('call'), C, s0);
    expect(ref.ok).toBe(true);
    expect(r.next).toStrictEqual((ref as { state: MonitorState }).state);
  });
  it('permission denied: decidedBy permission, state unchanged, no reason', () => {
    const s0 = st();
    const r = checkAndAdvance(false, act('call'), C, s0);
    expect(r.allow).toBe(false);
    expect(r.decidedBy).toBe('permission');
    expect(r.next).toBe(s0);
    expect('reason' in r).toBe(false);
    expect(r.evidence.ok).toBe(true);
  });
  it('prohibition: decidedBy prohibition (even when also not permitted), state unchanged', () => {
    const s0 = st();
    for (const permitted of [true, false]) {
      const r = checkAndAdvance(permitted, act('drop'), C, s0);
      expect(r.allow).toBe(false);
      expect(r.decidedBy).toBe('prohibition');
      expect(r.next).toBe(s0);
      expect(r.prohibition.violated).toEqual(['n']);
      expect(r.evidence.ok).toBe(false);
      expect('reason' in r).toBe(false);
    }
  });
  it('CAS on the head: seq checked first, then digest; reasons exact', () => {
    const s1 = (checkAndAdvance(true, act('call'), C, st()).next);
    const stale = checkAndAdvance(true, act('call'), C, s1, { expectedSeq: 0 });
    expect(stale.allow).toBe(false);
    expect(stale.decidedBy).toBe('state');
    expect(stale.reason).toBe('stale state head (seq)');
    expect(stale.next).toBe(s1);
    expect(checkAndAdvance(true, act('call'), C, s1, { expectedSeq: 1 }).allow).toBe(true);
    const d = stateDigest(s1);
    const staleD = checkAndAdvance(true, act('call'), C, s1, { expectedStateDigest: d + 'x' });
    expect(staleD.decidedBy).toBe('state');
    expect(staleD.reason).toBe('stale state head (digest)');
    expect(checkAndAdvance(true, act('call'), C, s1, { expectedStateDigest: d }).allow).toBe(true);
    expect(checkAndAdvance(true, act('call'), C, s1, { expectedSeq: 7, expectedStateDigest: d }).reason).toBe('stale state head (seq)');
    expect(checkAndAdvance(true, act('call'), C, s1, { expectedSeq: 1, expectedStateDigest: 'nope' }).reason).toBe('stale state head (digest)');
    // CAS wins over a permission denial
    expect(checkAndAdvance(false, act('call'), C, s1, { expectedSeq: 0 }).decidedBy).toBe('state');
    // a non-object state under CAS is stale
    expect(checkAndAdvance(true, act('call'), C, null as never, { expectedSeq: 0 }).reason).toBe('stale state head (seq)');
    // an undigestable state never matches an expected digest
    expect(checkAndAdvance(true, act('call'), C, { bad: 1 } as never, { expectedStateDigest: 'nope-not-a-digest' }).reason).toBe('stale state head (digest)');
    // refusals carry the pre-state evidence and verdict
    expect(stale.evidence.state_digest).toBe(stateDigest(s1));
    expect(stale.prohibition.ok).toBe(true);
  });
  it('an unattestable action (evidence not ok) is refused as prohibition, even though the monitor passes', () => {
    const unhash = act('call', '/r', { f: (() => 1) as never });
    const r = checkAndAdvance(true, unhash, C, st());
    expect(r.allow).toBe(false);
    expect(r.decidedBy).toBe('prohibition');
    expect(r.reason).toBe('evidence not attestable');
    expect(r.prohibition.ok).toBe(true);
  });
  it('an advance that cannot be recorded faithfully is refused with its reason', () => {
    const ledger: Record<string, Array<{ t: number; amount: number }>> = {};
    for (let i = 0; i < 10; i++) ledger['k' + i] = Array.from({ length: MAX_LEDGER }, () => ({ t: 1, amount: 0 }));
    const big = cons([inv({ id: 'extra', kind: 'cap', when: W('spend'), amount: 'action.params.amt', max: 5 })]);
    const r = checkAndAdvance(true, act('spend', '/r', { amt: 1 }), big, st({ ledger }));
    expect(r.allow).toBe(false);
    expect(r.decidedBy).toBe('state');
    expect(r.reason).toBe('advance failed: resulting state invalid');
    expect(r.prohibition.ok).toBe(true);
  });
  it('never throws: a throwing option getter fails closed', () => {
    const opts = { get expectedSeq(): number { throw new Error('boom'); } };
    const r = checkAndAdvance(true, act('call'), C, st(), opts as never);
    expect(r.allow).toBe(false);
    expect(r.decidedBy).toBe('state');
    expect(r.reason).toBe('check-and-advance error (fail closed)');
  });
});

describe('prohibitions: residual boundaries and late failures', () => {
  const A1 = (verb = 'x', resource = 'r', params?: Record<string, unknown>) => act(verb, resource, params);

  it('validateWhen: a verb list member must be a STRING (an array-like with a length is not one)', () => {
    expect(validateWhen({ verb: [{ length: 3 }] }, 'L')).toBe('L: bad verb');
    expect(validateWhen({ verb: [['a']] }, 'L')).toBe('L: bad verb');
    expect(validateWhen({ verb: ['ok', ['a']] }, 'L')).toBe('L: bad verb');
  });

  it('whenAffirmative refuses a structurally invalid trigger even where plain predicate matching would accept it', () => {
    // empty `ref` is invalid for the validator
    const badRef = { verb: 'x', where: [{ field: 'action.verb', op: 'eq', value: 'x', ref: '' }] };
    expect(validateWhen(badRef, 'L')).toBe('L: bad condition.ref');
    expect(whenAffirmative(badRef as never, A1())).toBe(false);
    // over-long regex resource
    const longRe = { verb: 'x', resource: 're:' + 'a'.repeat(201) };
    expect(validateWhen(longRe, 'L')).toBe('L: unsafe regex resource');
    expect(whenAffirmative(longRe as never, A1('x', 'a'))).toBe(false);
    // a valid one for contrast
    expect(whenAffirmative({ verb: 'x', where: [{ field: 'action.verb', op: 'eq', value: 'x' }] } as never, A1())).toBe(true);
  });

  it('checkProhibitions: a throwing action accessor is a <monitor> structural refusal', () => {
    const hostile = { get action(): never { throw new Error('boom'); } } as unknown as ActionContext;
    expect(checkProhibitions(hostile, cons([]), st())).toStrictEqual({
      ok: false,
      violated: ['<monitor>'],
      reasons: ['monitor error (fail closed)'],
      evaluated: [{ id: '<monitor>', kind: 'structural', result: 'violated', reason: 'monitor error (fail closed)' }],
    });
  });

  it('advanceStateStrict / advanceState tolerate a missing state or action without throwing', () => {
    expect(advanceStateStrict(act('x'), cons([]), undefined as never)).toStrictEqual({ ok: false, reason: 'malformed monitor state' });
    expect(advanceStateStrict(act('x'), cons([]), null as never)).toStrictEqual({ ok: false, reason: 'malformed monitor state' });
    expect(advanceState(act('x'), cons([]), undefined as never)).toBeUndefined();
    expect(advanceStateStrict(undefined as never, cons([]), st())).toStrictEqual({ ok: false, reason: 'malformed action' });
    expect(advanceStateStrict(null as never, cons([]), st())).toStrictEqual({ ok: false, reason: 'malformed action' });
  });

  it('advanceStateStrict: a cap amount that is found but not a finite number is refused', () => {
    const c = [inv({ id: 'c', kind: 'cap', when: W('spend'), amount: 'action.params.amt', max: 10 })];
    for (const amt of ['5', null, true, {}, [], 'Infinity']) {
      expect(advanceStateStrict(act('spend', '/r', { amt }), cons(c), st()), JSON.stringify(amt)).toStrictEqual({ ok: false, reason: 'c: amount unresolvable' });
    }
  });

  describe('verifySafetyEvidence / verifySignedSafetyEvidence', () => {
    const C = cons([inv({ id: 'n', kind: 'never', when: W('drop') }), inv({ id: 'm', kind: 'never', when: W('drop2') })]);
    const A = act('call');
    const S = st();
    const E = proveSafety(A, C, S);
    const vs = (signed: unknown, expected: unknown) => verifySignedSafetyEvidence(signed as never, expected as never);
    const sign1 = (ev: ProhibitionEvidence) => signSafetyEvidence(ev, SIGNER.secretKey, SIGNER_PUB);
    const SIGNED = sign1(E);
    const dig = { signer: SIGNER_PUB, actionDigest: E.action_digest, constitution: C, stateDigest: E.state_digest };

    it('verifySafetyEvidence fails closed with its own reason when the evidence cannot be read', () => {
      const ev = { ...E } as Record<string, unknown>;
      delete ev.constitution;
      Object.defineProperty(ev, 'constitution', { enumerable: true, get: () => { throw new Error('boom'); } });
      expect(verifySafetyEvidence(ev as never, A, C, S)).toStrictEqual({ ok: false, reason: 'verification error (fail closed)' });
    });

    it('the reason of a failed full recomputation is reported, not replaced', () => {
      // evidence readable until the full recomputation inside verifySafetyEvidence, which then throws
      const ev: Record<string, unknown> = { ...E };
      delete ev.constitution;
      let reads = 0;
      Object.defineProperty(ev, 'constitution', { enumerable: true, get: () => { if (reads++ >= 4) throw new Error('boom'); return E.constitution; } });
      const r = vs({ ...SIGNED, evidence: ev }, { signer: SIGNER_PUB, action: A, constitution: C, state: S });
      expect(r).toStrictEqual({ ok: false, reason: 'verification error (fail closed)' });
      // 5 reads on the hand-written encoder. With PCA_VERIFIED_CORE=wire the proved encoder reads the getter first and, on any
      // exception, the hand-written encoder runs once more to render its error (hash.ts canonicalizeStrict), so the throwing
      // read is repeated once: same outcome (the getter's error, then the fail-closed reason above), one more read.
      expect(reads).toBe(verifiedCoreOptIn('wire') ? 6 : 5);
    });

    it('action + state given with only a constitution ID (and the symmetric case) still verifies by digest', () => {
      expect(vs(SIGNED, { signer: SIGNER_PUB, action: A, constitutionId: E.constitution, state: S })).toEqual({ ok: true });
      expect(vs(SIGNED, { signer: SIGNER_PUB, action: A, constitution: C, stateDigest: E.state_digest })).toEqual({ ok: true });
    });

    it('coverage: evidence listing only a PREFIX of the invariants is refused', () => {
      const prefix = sign1({ ...E, evaluated: E.evaluated.slice(0, 1) });
      expect(vs(prefix, dig)).toEqual({ ok: false, reason: 'evidence does not cover every invariant' });
    });

    it('violation reasons list every violated id, comma-separated', () => {
      const bad = proveSafety(act('drop'), cons([inv({ id: 'n', kind: 'never', when: W('drop') }), inv({ id: 'm', kind: 'never', when: W('drop') })]), S);
      expect(bad.violated).toEqual(['n', 'm']);
      const sb = sign1(bad);
      const d = { signer: SIGNER_PUB, actionDigest: bad.action_digest, constitutionId: bad.constitution, stateDigest: bad.state_digest };
      expect(vs(sb, d)).toEqual({ ok: false, reason: 'prohibition violated: n,m' });
    });
  });
});
