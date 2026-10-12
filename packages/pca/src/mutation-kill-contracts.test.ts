/**
 * Mutation-kill tests for contracts.ts: exact validation messages and boundaries, signature domain/bytes, per-clause verdict
 * rows (reason present only on violation), bounded-liveness deadline arithmetic, latch/deadline overlay, CAS refusals,
 * state-invariant refusals and the permission composition.
 */
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import type { ActionContext } from './predicates';
import { emptyState, MAX_DEADLINE, stateDigest, type Invariant, type MonitorState, advanceStateStrict } from './prohibitions';
import {
  advanceContract,
  checkAndAdvanceContract,
  checkContract,
  contractFromConstitution,
  contractId,
  CONTRACT_SIG_DOMAIN,
  CONTRACT_VERSION,
  embeddedConstitution,
  MAX_CLAUSE_DEPTH,
  MAX_CLAUSES,
  signContract,
  validateClause,
  validateContract,
  verifyContract,
  type Clause,
  type Contract,
  type SignedContract,
} from './contracts';

const K = generateKeyPair();
const PRIN = encodeKey(K.publicKey);
const K2 = generateKeyPair();
const NOW = 1_700_000_000_000;

const act = (verb: string, resource = '/r', params?: Record<string, unknown>): ActionContext => ({
  action: { verb, resource, ...(params ? { params } : {}) },
});
const W = (verb: string | string[], extra: Record<string, unknown> = {}) => ({ verb, ...extra });
const contract = (clauses: Clause[], invariants: Invariant[] = []): Contract => ({ version: CONTRACT_VERSION, principal: PRIN, invariants, clauses });
const always = (id: string, verb: string, extra: Record<string, unknown> = {}): Clause => ({ id, kind: 'always', p: W(verb), ...extra }) as Clause;
const never = (id: string, verb: string, extra: Record<string, unknown> = {}): Clause => ({ id, kind: 'never', p: W(verb), ...extra }) as Clause;
const state0 = (): MonitorState => emptyState(NOW);

/** Step the contract; asserts success and returns the next state. */
const step = (c: Contract, s: MonitorState, a: ActionContext, opts = {}): MonitorState => {
  const r = advanceContract(s, a, c, opts);
  if (!r.ok) throw new Error('step refused: ' + JSON.stringify(r.reasons));
  return r.next;
};

describe('validateClause', () => {
  it('depth boundary: MAX_CLAUSE_DEPTH is allowed, one deeper is refused', () => {
    expect(MAX_CLAUSE_DEPTH).toBe(16);
    expect(validateClause(always('a', 'x'), new Set(), 16)).toEqual([]);
    expect(validateClause(always('a', 'x'), new Set(), 17)).toEqual(['clause nesting too deep']);
    expect(validateClause(null, new Set(), 17)).toEqual(['clause nesting too deep']);
  });
  it('and-nesting 16 deep is accepted, 17 deep refused with the depth message', () => {
    const nest = (n: number): Clause => {
      let c: Clause = always('leaf', 'x');
      for (let i = 0; i < n - 1; i++) c = { id: 'and' + i, kind: 'and', clauses: [c] };
      return c;
    };
    expect(validateClause(nest(16), new Set(), 1)).toEqual([]);
    expect(validateClause(nest(17), new Set(), 1)).toEqual(['clause nesting too deep']);
  });
  it('non-objects', () => {
    for (const bad of [null, undefined, 'x', 5, true, []]) expect(validateClause(bad, new Set(), 1)).toEqual(['clause not an object']);
  });
  it('missing / non-string / empty id', () => {
    for (const bad of [{}, { id: '' }, { id: 5 }, { id: null }, { id: ['a'] }]) {
      expect(validateClause({ ...bad, kind: 'always', p: W('x') }, new Set(), 1)).toEqual(['<no id>: missing clause id']);
    }
  });
  it('id length boundary (128) and forbidden ids', () => {
    const id128 = 'a'.repeat(128);
    expect(validateClause(always(id128, 'x'), new Set(), 1)).toEqual([]);
    expect(validateClause(always(id128 + 'a', 'x'), new Set(), 1)).toEqual([`${id128}a: id too long`]);
    for (const f of ['__proto__', 'constructor', 'prototype']) {
      expect(validateClause(always(f, 'x'), new Set(), 1)).toEqual([`${f}: forbidden id`]);
    }
    expect(validateClause(always('protot', 'x'), new Set(), 1)).toEqual([]);
  });
  it('duplicate ids: recorded in `seen`, second use refused; refused ids are not recorded', () => {
    const seen = new Set<string>();
    expect(validateClause(always('a', 'x'), seen, 1)).toEqual([]);
    expect([...seen]).toEqual(['a']);
    expect(validateClause(always('a', 'y'), seen, 1)).toEqual(['a: duplicate id']);
    const seen2 = new Set<string>();
    validateClause(always('b'.repeat(129), 'x'), seen2, 1);
    expect(seen2.size).toBe(0);
    const seen3 = new Set<string>(['pre']);
    expect(validateClause(never('pre', 'x'), seen3, 1)).toEqual(['pre: duplicate id']);
  });
  it('always / never: p must be a valid When, message carries id and label', () => {
    for (const kind of ['always', 'never']) {
      expect(validateClause({ id: 'c', kind, p: W('x') }, new Set(), 1)).toEqual([]);
      expect(validateClause({ id: 'c', kind, p: 'x' }, new Set(), 1)).toEqual(['c: p: not an object']);
      expect(validateClause({ id: 'c', kind, p: W('') }, new Set(), 1)).toEqual(['c: p: bad verb']);
      expect(validateClause({ id: 'c', kind }, new Set(), 1)).toEqual(['c: p: not an object']);
    }
  });
  it('precedes / requires_prior: p checked before q, each labelled', () => {
    for (const kind of ['precedes', 'requires_prior']) {
      expect(validateClause({ id: 'c', kind, p: W('x'), q: W('y') }, new Set(), 1)).toEqual([]);
      expect(validateClause({ id: 'c', kind, p: 1, q: W('y') }, new Set(), 1)).toEqual(['c: p: not an object']);
      expect(validateClause({ id: 'c', kind, p: W('x'), q: 1 }, new Set(), 1)).toEqual(['c: q: not an object']);
      expect(validateClause({ id: 'c', kind, p: 1, q: 1 }, new Set(), 1)).toEqual(['c: p: not an object']);
      expect(validateClause({ id: 'c', kind, p: W('x') }, new Set(), 1)).toEqual(['c: q: not an object']);
    }
  });
  it('responds_within: p, q, then `within` integer in [1, MAX_DEADLINE]', () => {
    const rw = (o: Record<string, unknown>) => validateClause({ id: 'c', kind: 'responds_within', p: W('x'), q: W('y'), within: 3, ...o }, new Set(), 1);
    expect(rw({})).toEqual([]);
    expect(rw({ p: 1 })).toEqual(['c: p: not an object']);
    expect(rw({ q: 1 })).toEqual(['c: q: not an object']);
    expect(rw({ p: 1, q: 1, within: 0 })).toEqual(['c: p: not an object']);
    expect(rw({ q: 1, within: 0 })).toEqual(['c: q: not an object']);
    const msg = ['c: within must be an integer in [1, MAX_DEADLINE]'];
    expect(rw({ within: 1 })).toEqual([]);
    expect(rw({ within: MAX_DEADLINE })).toEqual([]);
    expect(rw({ within: 0 })).toEqual(msg);
    expect(rw({ within: -1 })).toEqual(msg);
    expect(rw({ within: MAX_DEADLINE + 1 })).toEqual(msg);
    expect(rw({ within: 1.5 })).toEqual(msg);
    expect(rw({ within: NaN })).toEqual(msg);
    expect(rw({ within: Infinity })).toEqual(msg);
    expect(rw({ within: '3' })).toEqual(msg);
    expect(rw({ within: undefined })).toEqual(msg);
    expect(rw({ within: null })).toEqual(msg);
  });
  it('and: non-empty array of clauses; sub-errors concatenated in order; ids shared', () => {
    const seen = new Set<string>();
    expect(validateClause({ id: 'and', kind: 'and', clauses: [always('a', 'x'), never('b', 'y')] }, seen, 1)).toEqual([]);
    expect([...seen].sort()).toEqual(['a', 'and', 'b']);
    expect(validateClause({ id: 'and', kind: 'and', clauses: [] }, new Set(), 1)).toEqual(['and: and.clauses must be a non-empty array']);
    expect(validateClause({ id: 'and', kind: 'and' }, new Set(), 1)).toEqual(['and: and.clauses must be a non-empty array']);
    expect(validateClause({ id: 'and', kind: 'and', clauses: 'x' }, new Set(), 1)).toEqual(['and: and.clauses must be a non-empty array']);
    expect(validateClause({ id: 'and', kind: 'and', clauses: [{ id: 'a', kind: 'always', p: 1 }, { id: 'b', kind: 'never', p: 2 }, { id: 'and', kind: 'never', p: W('x') }] }, new Set(), 1)).toEqual([
      'a: p: not an object',
      'b: p: not an object',
      'and: duplicate id',
    ]);
  });
  it('unknown kinds', () => {
    expect(validateClause({ id: 'c', kind: 'eventually' }, new Set(), 1)).toEqual(['c: unknown clause kind eventually']);
    expect(validateClause({ id: 'c' }, new Set(), 1)).toEqual(['c: unknown clause kind undefined']);
    expect(validateClause({ id: 'c', kind: 5 }, new Set(), 1)).toEqual(['c: unknown clause kind 5']);
  });
});

describe('validateContract', () => {
  const inv = (id: string): Invariant => ({ id, kind: 'never', when: W('zzz') }) as Invariant;
  it('shape, version, principal', () => {
    for (const bad of [null, undefined, 'x', 5, []]) expect(validateContract(bad)).toEqual(['contract not an object']);
    expect(validateContract({ version: CONTRACT_VERSION, principal: PRIN })).toEqual([]);
    expect(validateContract({ version: 2, principal: PRIN })).toEqual(['unsupported version 2']);
    expect(validateContract({ principal: PRIN })).toEqual(['unsupported version undefined']);
    expect(validateContract({ version: '1', principal: PRIN })).toEqual(['unsupported version 1']);
    expect(validateContract({ version: 1 })).toEqual(['principal missing']);
    expect(validateContract({ version: 1, principal: '' })).toEqual(['principal missing']);
    expect(validateContract({ version: 1, principal: 5 })).toEqual(['principal missing']);
    expect(validateContract({ version: 0, principal: '' })).toEqual(['unsupported version 0', 'principal missing']);
  });
  it('invariants: array required (earlier problems kept), count boundary, per-invariant problems, duplicates', () => {
    expect(validateContract({ version: 1, principal: PRIN, invariants: 'x' })).toEqual(['invariants not an array']);
    expect(validateContract({ version: 2, principal: '', invariants: {} })).toEqual(['unsupported version 2', 'principal missing', 'invariants not an array']);
    const many = (n: number) => Array.from({ length: n }, (_, i) => inv('i' + i));
    expect(validateContract({ version: 1, principal: PRIN, invariants: many(256) })).toEqual([]);
    expect(validateContract({ version: 1, principal: PRIN, invariants: many(257) })).toEqual(['too many invariants']);
    expect(validateContract({ version: 1, principal: PRIN, invariants: [inv('a'), inv('a')] })).toEqual(['a: duplicate id']);
    expect(validateContract({ version: 1, principal: PRIN, invariants: [{ id: 'a', kind: 'nope' }] })).toEqual(['a: unknown invariant kind nope']);
    expect(validateContract({ version: 1, principal: PRIN, invariants: [5] })).toEqual(['invariant not an object']);
    // a non-object invariant has no id to collide with
    expect(validateContract({ version: 1, principal: PRIN, invariants: [5, 6] })).toEqual(['invariant not an object', 'invariant not an object']);
    // a non-string id is not tracked for duplicates
    expect(validateContract({ version: 1, principal: PRIN, invariants: [{ id: 5, kind: 'never', when: W('x') }, { id: 5, kind: 'never', when: W('x') }] })).toEqual(['<no id>: missing id', '<no id>: missing id']);
    expect(validateContract({ version: 1, principal: PRIN, invariants: [inv('a'), inv('b'), inv('a')] })).toEqual(['a: duplicate id']);
  });
  it('clauses: array required (earlier problems kept), count boundary incl. nested, ids disjoint from invariants', () => {
    expect(validateContract({ version: 1, principal: PRIN, clauses: 'x' })).toEqual(['clauses not an array']);
    expect(validateContract({ version: 3, principal: PRIN, clauses: {} })).toEqual(['unsupported version 3', 'clauses not an array']);
    expect(MAX_CLAUSES).toBe(256);
    const flat = (n: number) => Array.from({ length: n }, (_, i) => always('c' + i, 'x'));
    expect(validateContract({ version: 1, principal: PRIN, clauses: flat(256) })).toEqual([]);
    expect(validateContract({ version: 1, principal: PRIN, clauses: flat(257) })).toEqual(['too many clauses']);
    // nested clauses count, and the `and` counts itself: 1 + 255 = 256
    expect(validateContract({ version: 1, principal: PRIN, clauses: [{ id: 'A', kind: 'and', clauses: flat(255) }] })).toEqual([]);
    expect(validateContract({ version: 1, principal: PRIN, clauses: [{ id: 'A', kind: 'and', clauses: flat(256) }] })).toEqual(['too many clauses']);
    expect(validateContract({ version: 1, principal: PRIN, clauses: [{ id: 'A', kind: 'and', clauses: flat(128) }, { id: 'B', kind: 'and', clauses: flat(126).map((c, i) => ({ ...c, id: 'd' + i })) }] })).toEqual([]);
    // a clause may not reuse an invariant id; clause ids are unique across nesting
    expect(validateContract({ version: 1, principal: PRIN, invariants: [inv('x')], clauses: [always('x', 'y')] })).toEqual(['x: duplicate id']);
    expect(validateContract({ version: 1, principal: PRIN, clauses: [always('x', 'y'), never('x', 'y')] })).toEqual(['x: duplicate id']);
    expect(validateContract({ version: 1, principal: PRIN, clauses: [{ id: 'A', kind: 'and', clauses: [always('x', 'y')] }, never('x', 'y')] })).toEqual(['x: duplicate id']);
    // clause problems come after invariant problems
    expect(validateContract({ version: 1, principal: PRIN, invariants: [{ id: 'a', kind: 'zz' }], clauses: [{ id: 'b', kind: 'yy' }] })).toEqual(['a: unknown invariant kind zz', 'b: unknown clause kind yy']);
  });
  it('count: a clause that is not an object / and without array adds only itself', () => {
    expect(validateContract({ version: 1, principal: PRIN, clauses: [null, { id: 'a', kind: 'and', clauses: 'x' }] })).toEqual(['clause not an object', 'a: and.clauses must be a non-empty array']);
  });
});

describe('contract id, signature, verification', () => {
  const base = (): Contract => contract([always('a', 'read')]);
  it('contractId = hashCanonical of the body without id/sig; independent of id/sig', () => {
    const c = base();
    expect(contractId(c)).toBe(hashCanonical(c));
    const sc = signContract(c, K.secretKey);
    expect(sc.id).toBe(contractId(c));
    expect(contractId(sc)).toBe(sc.id);
    expect(contractId({ ...c, id: 'zzz', sig: 'yyy' } as Contract)).toBe(contractId(c));
    expect(contractId({ ...c, issued_at: 5 })).not.toBe(contractId(c));
  });
  it('signContract: output shape; signature is over CONTRACT_SIG_DOMAIN || sha256(id)', () => {
    const c = base();
    const sc = signContract(c, K.secretKey);
    expect(Object.keys(sc).sort()).toEqual(['clauses', 'id', 'invariants', 'principal', 'sig', 'version']);
    expect(sc.principal).toBe(PRIN);
    expect(sc.clauses).toEqual(c.clauses);
    expect(CONTRACT_SIG_DOMAIN).toBe('atlas-pca/contract/v1\0');
    const msg = new Uint8Array([...utf8(CONTRACT_SIG_DOMAIN), ...sha256(utf8(sc.id))]);
    expect(sc.sig).toBe(b64u(sign(K.secretKey, msg)));
    // re-signing an already signed contract strips the stale id/sig
    const again = signContract({ ...sc, id: 'stale', sig: 'stale' } as Contract, K.secretKey);
    expect(again).toEqual(sc);
  });
  it('signContract refuses a malformed contract with every problem, joined', () => {
    expect(() => signContract({ version: 9, principal: '' } as Contract, K.secretKey)).toThrow(new TypeError('signContract: unsupported version 9; principal missing'));
    expect(() => signContract({ version: 9, principal: '' } as Contract, K.secretKey)).toThrow(TypeError);
  });
  it('verifyContract: every outcome with its reason', () => {
    const sc = signContract(base(), K.secretKey);
    expect(verifyContract(sc)).toEqual({ ok: true });
    expect(verifyContract(sc, PRIN)).toEqual({ ok: true });
    expect(verifyContract(sc, encodeKey(K2.publicKey))).toEqual({ ok: false, reason: 'principal mismatch' });
    expect(verifyContract({ ...sc, version: 7 })).toEqual({ ok: false, reason: 'unsupported version 7' });
    // malformed + mismatched principal: structural problem wins
    expect(verifyContract({ ...sc, version: 7 }, encodeKey(K2.publicKey))).toEqual({ ok: false, reason: 'unsupported version 7' });
    // principal mismatch reported before id mismatch
    expect(verifyContract({ ...sc, id: 'x' }, encodeKey(K2.publicKey))).toEqual({ ok: false, reason: 'principal mismatch' });
    expect(verifyContract({ ...sc, id: 'x' })).toEqual({ ok: false, reason: 'id does not match content' });
    expect(verifyContract({ ...sc, id: 5 as unknown as string })).toEqual({ ok: false, reason: 'id does not match content' });
    expect(verifyContract({ ...sc, clauses: [always('a', 'write')] })).toEqual({ ok: false, reason: 'id does not match content' });
    expect(verifyContract({ ...sc, sig: 5 as unknown as string })).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyContract({ ...sc, sig: undefined as unknown as string })).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyContract({ ...sc, sig: 'AAAA' })).toEqual({ ok: false, reason: 'bad signature' });
    const other = signContract(base(), K2.secretKey);
    expect(other.id).toBe(sc.id); // signer is not part of the body: same body => same id
    expect(other.sig).not.toBe(sc.sig);
  });
  it('signature must use the contract domain (not bare sha256(id), not another domain)', () => {
    const c = base();
    const id = contractId(c);
    const mk = (msg: Uint8Array): SignedContract => ({ ...c, id, sig: b64u(sign(K.secretKey, msg)) });
    const good = new Uint8Array([...utf8(CONTRACT_SIG_DOMAIN), ...sha256(utf8(id))]);
    expect(verifyContract(mk(good))).toEqual({ ok: true });
    expect(verifyContract(mk(sha256(utf8(id))))).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyContract(mk(new Uint8Array([...utf8('atlas-pca/constitution/v1\0'), ...sha256(utf8(id))])))).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyContract(mk(new Uint8Array([...sha256(utf8(id)), ...utf8(CONTRACT_SIG_DOMAIN)])))).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyContract(mk(new Uint8Array([...utf8(CONTRACT_SIG_DOMAIN), ...utf8(id)])))).toEqual({ ok: false, reason: 'bad signature' });
    // signed by a different key than the embedded principal
    expect(verifyContract({ ...mk(good), sig: b64u(sign(K2.secretKey, good)) })).toEqual({ ok: false, reason: 'bad signature' });
  });
  it('verifyContract never throws: an uncanonicalizable body fails closed', () => {
    const sc = { ...signContract(base(), K.secretKey), extra: () => 1 } as unknown as SignedContract;
    expect(verifyContract(sc)).toEqual({ ok: false, reason: 'verification error (fail closed)' });
    expect(() => signContract({ ...base(), extra: () => 1 } as Contract, K.secretKey)).toThrow();
  });
});

describe('embeddedConstitution / contractFromConstitution', () => {
  it('embeddedConstitution', () => {
    const i: Invariant = { id: 'n', kind: 'never', when: W('x') };
    expect(embeddedConstitution({ version: 1, principal: 'P', invariants: [i] })).toEqual({ version: 1, principal: 'P', invariants: [i] });
    expect(embeddedConstitution({ version: 1, principal: 'P' })).toEqual({ version: 1, principal: 'P', invariants: [] });
    expect(embeddedConstitution({ version: 1, principal: 'P', invariants: 'x' as unknown as Invariant[] })).toEqual({ version: 1, principal: 'P', invariants: [] });
    expect(embeddedConstitution({ version: 5, principal: 'P' }).version).toBe(1);
  });
  it('contractFromConstitution', () => {
    const i: Invariant = { id: 'n', kind: 'never', when: W('x') };
    expect(contractFromConstitution({ version: 1, principal: 'P', invariants: [i] })).toEqual({ version: CONTRACT_VERSION, principal: 'P', invariants: [i], clauses: [] });
    expect(CONTRACT_VERSION).toBe(1);
  });
});

describe('checkContract: structural refusals', () => {
  it('malformed contract => <contract> with the first problem; checked before action and state', () => {
    const r = checkContract({} as ActionContext, { version: 5, principal: '' } as Contract, { bad: true } as unknown as MonitorState);
    expect(r).toStrictEqual({
      ok: false,
      violated: ['<contract>'],
      reasons: ['<contract>: unsupported version 5'],
      evaluated: [{ id: '<contract>', kind: 'structural', result: 'violated', reason: 'unsupported version 5' }],
    });
  });
  it('malformed action => <action>', () => {
    const c = contract([]);
    for (const a of [null, undefined, {}, { action: null }, { action: { verb: 1, resource: '/r' } }, { action: { verb: 'x' } }, { action: { verb: 'x', resource: 5 } }, { action: { resource: '/r' } }]) {
      expect(checkContract(a as unknown as ActionContext, c, state0())).toStrictEqual({
        ok: false,
        violated: ['<action>'],
        reasons: ['<action>: malformed action'],
        evaluated: [{ id: '<action>', kind: 'structural', result: 'violated', reason: 'malformed action' }],
      });
    }
    // action checked before state
    expect(checkContract(act('x') && ({} as ActionContext), c, { bad: 1 } as unknown as MonitorState).violated).toEqual(['<action>']);
  });
  it('malformed state => <state> with the stateProblem text', () => {
    const c = contract([]);
    expect(checkContract(act('x'), c, { bad: 1 } as unknown as MonitorState)).toStrictEqual({
      ok: false,
      violated: ['<state>'],
      reasons: ['<state>: malformed monitor state'],
      evaluated: [{ id: '<state>', kind: 'structural', result: 'violated', reason: 'malformed monitor state' }],
    });
    expect(checkContract(act('x'), c, null as unknown as MonitorState).violated).toEqual(['<state>']);
    expect(checkContract(act('x'), c, { ...state0(), seq: 1 }).reasons).toEqual(['<state>: malformed monitor state: missing chain link']);
  });
  it('an empty contract passes with an empty trace', () => {
    expect(checkContract(act('x'), contract([]), state0())).toStrictEqual({ ok: true, violated: [], reasons: [], evaluated: [] });
    expect(checkContract(act('x'), { version: 1, principal: PRIN }, state0())).toStrictEqual({ ok: true, violated: [], reasons: [], evaluated: [] });
  });
  it('never throws on hostile input (monitor error fails closed)', () => {
    const hostile = new Proxy({}, { get() { throw new Error('boom'); } }) as unknown as MonitorState;
    const r = checkContract(act('x'), contract([]), hostile);
    expect(r.ok).toBe(false);
    expect(r.violated.length).toBe(1);
  });
});

describe('checkContract: clause verdict rows', () => {
  it('always: pass row has no reason key; violation uses the default or the description', () => {
    const c = contract([always('A', 'read')]);
    expect(checkContract(act('read'), c, state0())).toStrictEqual({
      ok: true,
      violated: [],
      reasons: [],
      evaluated: [{ id: 'A', kind: 'always', result: 'pass' }],
    });
    expect(checkContract(act('write'), c, state0())).toStrictEqual({
      ok: false,
      violated: ['A'],
      reasons: ['A: always-invariant violated (action does not satisfy p)'],
      evaluated: [{ id: 'A', kind: 'always', result: 'violated', reason: 'always-invariant violated (action does not satisfy p)' }],
    });
    const d = contract([always('A', 'read', { description: 'must read' })]);
    expect(checkContract(act('write'), d, state0()).reasons).toEqual(['A: must read']);
  });
  it('always is AFFIRMATIVE: an unresolvable condition is a violation', () => {
    const c = contract([{ id: 'A', kind: 'always', p: W('read', { where: [{ field: 'action.params.amount', op: 'lt', value: 10 }] }) }]);
    expect(checkContract(act('read', '/r', { amount: 5 }), c, state0()).ok).toBe(true);
    expect(checkContract(act('read', '/r', { amount: 50 }), c, state0()).ok).toBe(false);
    expect(checkContract(act('read', '/r', {}), c, state0()).ok).toBe(false);
    expect(checkContract(act('read'), c, state0()).ok).toBe(false);
  });
  it('never: matched => violated; unresolvable trigger counts as matched (veto)', () => {
    const c = contract([never('N', 'drop')]);
    expect(checkContract(act('read'), c, state0()).evaluated).toStrictEqual([{ id: 'N', kind: 'never', result: 'pass' }]);
    expect(checkContract(act('drop'), c, state0())).toStrictEqual({
      ok: false,
      violated: ['N'],
      reasons: ['N: never-invariant violated (forbidden action)'],
      evaluated: [{ id: 'N', kind: 'never', result: 'violated', reason: 'never-invariant violated (forbidden action)' }],
    });
    expect(checkContract(act('drop'), contract([never('N', 'drop', { description: 'no drops' })]), state0()).reasons).toEqual(['N: no drops']);
    const amb = contract([{ id: 'N', kind: 'never', p: W('drop', { where: [{ field: 'action.params.x', op: 'eq', value: 1 }] }) }]);
    expect(checkContract(act('drop', '/r', { x: 2 }), amb, state0()).ok).toBe(true); // cleanly false
    expect(checkContract(act('drop', '/r', { x: 1 }), amb, state0()).ok).toBe(false);
    expect(checkContract(act('drop', '/r', {}), amb, state0()).ok).toBe(false); // ambiguous => veto
    expect(checkContract(act('drop'), amb, state0()).ok).toBe(false);
  });
  it('an EMPTY description is not a reason: the row has no reason and the summary says "violated"', () => {
    const r = checkContract(act('drop'), contract([never('N', 'drop', { description: '' })]), state0());
    expect(r.evaluated).toStrictEqual([{ id: 'N', kind: 'never', result: 'violated' }]);
    expect(r.reasons).toEqual(['N: violated']);
    const r2 = checkContract(act('write'), contract([always('A', 'read', { description: '' })]), state0());
    expect(r2.evaluated).toStrictEqual([{ id: 'A', kind: 'always', result: 'violated' }]);
    expect(r2.reasons).toEqual(['A: violated']);
  });
  it('precedes / requires_prior: q forbidden until p admitted; pass rows carry no reason', () => {
    for (const kind of ['precedes', 'requires_prior'] as const) {
      const c = contract([{ id: 'P', kind, p: W('review'), q: W('deploy') } as Clause]);
      expect(checkContract(act('other'), c, state0()).evaluated).toStrictEqual([{ id: 'P', kind, result: 'pass' }]);
      expect(checkContract(act('deploy'), c, state0())).toStrictEqual({
        ok: false,
        violated: ['P'],
        reasons: ['P: precedence violated (prerequisite p not yet admitted before q)'],
        evaluated: [{ id: 'P', kind, result: 'violated', reason: 'precedence violated (prerequisite p not yet admitted before q)' }],
      });
      const d = contract([{ id: 'P', kind, p: W('review'), q: W('deploy'), description: 'review first' } as Clause]);
      expect(checkContract(act('deploy'), d, state0()).reasons).toEqual(['P: review first']);
      // after the prerequisite is admitted, q is fine
      let s = step(c, state0(), act('review'));
      expect(s.latched).toEqual({ P: NOW });
      expect(checkContract(act('deploy'), c, s)).toStrictEqual({ ok: true, violated: [], reasons: [], evaluated: [{ id: 'P', kind, result: 'pass' }] });
      s = step(c, s, act('deploy'));
      expect(s.latched).toEqual({ P: NOW });
    }
  });
  it('precedence: q is matched CONSERVATIVELY, p AFFIRMATIVELY', () => {
    const amb = (v: string) => W(v, { where: [{ field: 'action.params.x', op: 'eq', value: 1 }] });
    const c = contract([{ id: 'P', kind: 'precedes', p: amb('review'), q: amb('deploy') }]);
    // ambiguous q still demands the prior
    expect(checkContract(act('deploy', '/r', {}), c, state0()).ok).toBe(false);
    // cleanly-false q does not
    expect(checkContract(act('deploy', '/r', { x: 2 }), c, state0()).ok).toBe(true);
    // ambiguous p does not latch
    expect(step(c, state0(), act('review', '/r', {})).latched).toEqual({});
    expect(step(c, state0(), act('review', '/r', { x: 2 })).latched).toEqual({});
    expect(step(c, state0(), act('review', '/r', { x: 1 })).latched).toEqual({ P: NOW });
  });
  it('responds_within trace row: pass without reason / violated with the default reason mentioning `within`', () => {
    const c = contract([{ id: 'R', kind: 'responds_within', p: W('open'), q: W('close'), within: 2 }]);
    expect(checkContract(act('open'), c, state0()).evaluated).toStrictEqual([{ id: 'R', kind: 'responds_within', result: 'pass' }]);
    const s1 = step(c, state0(), act('open'));
    const s2 = step(c, s1, act('x'));
    const r = checkContract(act('y'), c, s2);
    expect(r).toStrictEqual({
      ok: false,
      violated: ['R'],
      reasons: ['R: bounded-liveness deadline missed (no q within 2 actions of p)'],
      evaluated: [{ id: 'R', kind: 'responds_within', result: 'violated', reason: 'bounded-liveness deadline missed (no q within 2 actions of p)' }],
    });
    const d = contract([{ id: 'R', kind: 'responds_within', p: W('open'), q: W('close'), within: 2, description: 'close it' }]);
    expect(checkContract(act('y'), d, s2).reasons).toEqual(['R: close it']);
  });
  it('and: only the children appear (no row for the and), in order; ok rolls up; first failing reason wins', () => {
    const c = contract([{ id: 'AND', kind: 'and', clauses: [always('a1', 'read'), never('n1', 'read'), never('n2', 'read', { description: 'second' })] }]);
    const r = checkContract(act('read'), c, state0());
    expect(r.evaluated.map((e) => e.id)).toEqual(['a1', 'n1', 'n2']);
    expect(r.violated).toEqual(['n1', 'n2']);
    expect(r.ok).toBe(false);
    expect(r.evaluated[0]).toStrictEqual({ id: 'a1', kind: 'always', result: 'pass' });
    const ok = checkContract(act('read'), contract([{ id: 'AND', kind: 'and', clauses: [always('a1', 'read'), never('n1', 'zzz')] }]), state0());
    expect(ok).toStrictEqual({ ok: true, violated: [], reasons: [], evaluated: [{ id: 'a1', kind: 'always', result: 'pass' }, { id: 'n1', kind: 'never', result: 'pass' }] });
  });
  it('every clause is evaluated (no short-circuit), invariants first', () => {
    const inv: Invariant = { id: 'inv1', kind: 'never', when: W('read') };
    const c = contract([always('A', 'write'), never('N', 'read')], [inv]);
    const r = checkContract(act('read'), c, state0());
    expect(r.evaluated.map((e) => `${e.id}:${e.result}`)).toEqual(['inv1:violated', 'A:violated', 'N:violated']);
    expect(r.violated).toEqual(['inv1', 'A', 'N']);
    expect(r.reasons).toEqual(['inv1: forbidden action', 'A: always-invariant violated (action does not satisfy p)', 'N: never-invariant violated (forbidden action)']);
    // no invariants => no constitution rows
    expect(checkContract(act('read'), contract([always('A', 'read')]), state0()).evaluated.map((e) => e.id)).toEqual(['A']);
  });
  it('the embedded constitution runs exactly like the prohibition monitor (cap)', () => {
    const cap: Invariant = { id: 'cap1', kind: 'cap', when: W('spend'), amount: 'action.params.amt', max: 10 };
    const c = contract([], [cap]);
    const s1 = step(c, state0(), act('spend', '/r', { amt: 6 }));
    expect(s1.ledger).toEqual({ cap1: [{ t: NOW, amount: 6 }] });
    const r = checkContract(act('spend', '/r', { amt: 5 }), c, s1);
    expect(r.violated).toEqual(['cap1']);
    expect(r.reasons).toEqual(['cap1: cap exceeded: 6 + 5 > 10']);
    expect(checkContract(act('spend', '/r', { amt: 4 }), c, s1).ok).toBe(true);
  });
});

describe('responds_within deadline arithmetic', () => {
  const rw = (within: number, extra: Record<string, unknown> = {}): Contract => contract([{ id: 'R', kind: 'responds_within', p: W('open'), q: W('close'), within, ...extra } as Clause]);
  it('no stimulus, no obligation: deadlines stay absent', () => {
    const c = rw(3);
    const s = step(c, state0(), act('x'));
    expect(s.deadlines).toBeUndefined();
    expect('deadlines' in s).toBe(false);
    expect(s.seq).toBe(1);
  });
  it('stimulus opens an obligation of budget `within`; each non-response action burns one; reaching 0 is the violation', () => {
    const c = rw(3);
    let s = step(c, state0(), act('open'));
    expect(s.deadlines).toEqual({ R: 3 });
    s = step(c, s, act('x'));
    expect(s.deadlines).toEqual({ R: 2 });
    s = step(c, s, act('x'));
    expect(s.deadlines).toEqual({ R: 1 });
    const r = advanceContract(s, act('x'), c);
    expect(r.ok).toBe(false);
    expect(r.violated).toEqual(['R']);
    expect(r.decidedBy).toBe('contract');
    expect(r.next).toBe(s);
  });
  it('within = 1: the very next action must respond', () => {
    const c = rw(1);
    const s = step(c, state0(), act('open'));
    expect(s.deadlines).toEqual({ R: 1 });
    expect(advanceContract(s, act('x'), c).ok).toBe(false);
    const done = step(c, s, act('close'));
    expect(done.deadlines).toBeUndefined();
  });
  it('a response discharges the obligation (deadlines entry removed; empty map omitted)', () => {
    const c = rw(5);
    let s = step(c, state0(), act('open'));
    s = step(c, s, act('x'));
    expect(s.deadlines).toEqual({ R: 4 });
    s = step(c, s, act('close'));
    expect('deadlines' in s).toBe(false);
    // and later non-response actions are fine
    s = step(c, s, act('x'));
    s = step(c, s, act('x'));
    expect(s.seq).toBe(5);
  });
  it('response arrives in the same action as the final budget unit: discharge wins over violation', () => {
    const c = rw(2);
    let s = step(c, state0(), act('open'));
    s = step(c, s, act('x')); // budget 1
    expect(s.deadlines).toEqual({ R: 1 });
    s = step(c, s, act('close'));
    expect(s.deadlines).toBeUndefined();
  });
  it('re-stimulus while open keeps the MOST URGENT (smaller) budget', () => {
    const c = rw(5);
    let s = step(c, state0(), act('open')); // 5
    s = step(c, s, act('x')); // 4
    s = step(c, s, act('open')); // carried 3, fresh 5 => min = 3
    expect(s.deadlines).toEqual({ R: 3 });
    // and with a larger carried than within: within wins
    const c2 = rw(2);
    let t = step(c2, state0(), act('open')); // 2
    t = step(c2, t, act('open')); // carried 1, fresh 2 => 1
    expect(t.deadlines).toEqual({ R: 1 });
    const c3 = contract([{ id: 'R', kind: 'responds_within', p: W(['open', 'open2']), q: W('close'), within: 4 }]);
    let u = step(c3, state0(), act('open'));
    u = step(c3, u, act('open2'));
    expect(u.deadlines).toEqual({ R: 3 });
  });
  it('an action matching BOTH p and q: the response discharges the old obligation and p opens a fresh one', () => {
    const c = contract([{ id: 'R', kind: 'responds_within', p: W('both'), q: W('both'), within: 3 }]);
    let s = step(c, state0(), act('both'));
    expect(s.deadlines).toEqual({ R: 3 });
    s = step(c, s, act('both'));
    expect(s.deadlines).toEqual({ R: 3 });
  });
  it('stimulus is conservative (ambiguous p opens), response is affirmative (ambiguous q does not discharge)', () => {
    const amb = (v: string) => W(v, { where: [{ field: 'action.params.x', op: 'eq', value: 1 }] });
    const c = contract([{ id: 'R', kind: 'responds_within', p: amb('open'), q: amb('close'), within: 3 }]);
    let s = step(c, state0(), act('open', '/r', {})); // ambiguous stimulus
    expect(s.deadlines).toEqual({ R: 3 });
    s = step(c, s, act('close', '/r', {})); // ambiguous response: no discharge, burns
    expect(s.deadlines).toEqual({ R: 2 });
    s = step(c, s, act('close', '/r', { x: 1 })); // clean response
    expect(s.deadlines).toBeUndefined();
    // a cleanly-false stimulus does not open
    expect(step(c, state0(), act('open', '/r', { x: 2 })).deadlines).toBeUndefined();
  });
  it('two obligations are tracked per clause id; unrelated deadline entries survive', () => {
    const c = contract([
      { id: 'R1', kind: 'responds_within', p: W('open'), q: W('close1'), within: 2 },
      { id: 'R2', kind: 'responds_within', p: W('open'), q: W('close2'), within: 4 },
    ]);
    let s = step(c, state0(), act('open'));
    expect(s.deadlines).toEqual({ R1: 2, R2: 4 });
    s = step(c, s, act('close1'));
    expect(s.deadlines).toEqual({ R2: 3 });
    // a deadline for a clause id the contract no longer has is carried unchanged
    const carried: MonitorState = { ...state0(), deadlines: { gone: 7 } };
    expect(step(contract([]), carried, act('x')).deadlines).toEqual({ gone: 7 });
  });
  it('and: nested responds_within / precedes state is merged into the overlay', () => {
    const c = contract([{ id: 'AND', kind: 'and', clauses: [
      { id: 'R', kind: 'responds_within', p: W('open'), q: W('close'), within: 3 },
      { id: 'P', kind: 'precedes', p: W('review'), q: W('deploy') },
      { id: 'R2', kind: 'responds_within', p: W('review'), q: W('close'), within: 2 },
    ] }]);
    let s = step(c, state0(), act('open'));
    expect(s.deadlines).toEqual({ R: 3 });
    s = step(c, s, act('review'));
    expect(s.deadlines).toEqual({ R: 2, R2: 2 });
    expect(s.latched).toEqual({ P: NOW });
  });
});

describe('advanceContract', () => {
  const c = contract([always('A', 'read')]);
  it('success: seq+1, parent chain, decidedBy none, verdict fields preserved, input untouched', () => {
    const s0 = state0();
    const r = advanceContract(s0, act('read'), c);
    expect(r.ok).toBe(true);
    expect(r.decidedBy).toBe('none');
    expect(r.violated).toEqual([]);
    expect(r.reasons).toEqual([]);
    expect(r.evaluated).toStrictEqual([{ id: 'A', kind: 'always', result: 'pass' }]);
    expect(r.next.seq).toBe(1);
    expect(r.next.now).toBe(NOW);
    expect(r.next.parent).toBe(hashCanonical({ d: 'atlas-pca/monitor-state-link/v1', state: stateDigest(s0), action: hashCanonical(act('read')) }));
    expect(s0.seq).toBe(0);
    expect(s0.latched).toEqual({});
  });
  it('degenerate contract == prohibition advance, byte for byte', () => {
    const inv: Invariant[] = [
      { id: 'cap1', kind: 'cap', when: W('spend'), amount: 'action.params.amt', max: 100, window_secs: 60 },
      { id: 'rate1', kind: 'rate', when: W('spend'), max: 5, window_secs: 60 },
      { id: 'na', kind: 'never_after', after: W('lock'), forbid: W('write') },
      { id: 'rp', kind: 'require_prior', when: W('deploy'), prior: W('review') },
    ];
    const k = contract([], inv);
    const cons = embeddedConstitution(k);
    let s = state0();
    let t = state0();
    for (const a of [act('spend', '/r', { amt: 5 }), act('review'), act('lock'), act('deploy'), act('spend', '/r', { amt: 7 })]) {
      const ar = advanceContract(s, a, k);
      const br = advanceStateStrict(a, cons, t);
      expect(ar.ok).toBe(br.ok);
      if (br.ok) {
        expect(ar.next).toStrictEqual(br.state);
        expect(stateDigest(ar.next)).toBe(stateDigest(br.state));
        s = ar.next;
        t = br.state;
      }
    }
    expect(s.seq).toBe(5);
    expect(s.latched).toEqual({ na: NOW, rp: NOW });
  });
  it('clause latches never overwrite an existing latch (first observation wins)', () => {
    const k = contract([{ id: 'P', kind: 'precedes', p: W('review'), q: W('deploy') }]);
    const s1 = step(k, state0(), act('review'), { now: NOW + 10 });
    expect(s1.latched).toEqual({ P: NOW + 10 });
    const s2 = step(k, s1, act('review'), { now: NOW + 20 });
    expect(s2.latched).toEqual({ P: NOW + 10 });
    expect(s2.now).toBe(NOW + 20);
  });
  it('opts.now: used for the new state time and for latches; defaults to state.now; regression refused', () => {
    const k = contract([{ id: 'P', kind: 'precedes', p: W('review'), q: W('deploy') }]);
    const a = advanceContract(state0(), act('review'), k, { now: NOW + 5 });
    expect(a.next.now).toBe(NOW + 5);
    expect(a.next.latched).toEqual({ P: NOW + 5 });
    const b = advanceContract(state0(), act('review'), k);
    expect(b.next.now).toBe(NOW);
    const r = advanceContract(state0(), act('review'), k, { now: NOW - 1 });
    expect(r.ok).toBe(false);
    expect(r.decidedBy).toBe('state');
    expect(r.violated).toEqual(['<state>']);
    expect(r.reasons).toEqual(['<state>: advance failed: clock regression']);
    expect(r.evaluated).toStrictEqual([{ id: 'P', kind: 'precedes', result: 'pass' }]);
    const eq = advanceContract(state0(), act('review'), k, { now: NOW });
    expect(eq.ok).toBe(true);
  });
  it('CAS on seq: stale head refused with decidedBy state, before any other check', () => {
    const s1 = step(c, state0(), act('read'));
    const r = advanceContract(s1, act('read'), c, { expectedSeq: 0 });
    expect(r).toStrictEqual({
      ok: false,
      violated: ['<state>'],
      reasons: ['<state>: stale state head (seq)'],
      evaluated: [{ id: 'A', kind: 'always', result: 'pass' }],
      next: s1,
      decidedBy: 'state',
    });
    expect(r.next).toBe(s1);
    expect(advanceContract(s1, act('read'), c, { expectedSeq: 1 }).ok).toBe(true);
    expect(advanceContract(state0(), act('read'), c, { expectedSeq: 0 }).ok).toBe(true);
    // refusal is by seq even when the action would also violate
    const v = advanceContract(s1, act('write'), c, { expectedSeq: 5 });
    expect(v.decidedBy).toBe('state');
    expect(v.violated).toEqual(['A', '<state>']);
    expect(v.reasons).toEqual(['A: always-invariant violated (action does not satisfy p)', '<state>: stale state head (seq)']);
    // a non-object state under CAS: the structural <state> row is replaced, not duplicated in `violated`
    const n = advanceContract(null as unknown as MonitorState, act('read'), c, { expectedSeq: 0 });
    expect(n.ok).toBe(false);
    expect(n.violated).toEqual(['<state>']);
    expect(n.reasons).toEqual(['<state>: malformed monitor state', '<state>: stale state head (seq)']);
    expect(n.decidedBy).toBe('state');
  });
  it('CAS on digest: exact match required; a bad digest or an undigestable state is stale', () => {
    const s1 = step(c, state0(), act('read'));
    const d = stateDigest(s1);
    expect(advanceContract(s1, act('read'), c, { expectedStateDigest: d }).ok).toBe(true);
    const r = advanceContract(s1, act('read'), c, { expectedStateDigest: d + 'x' });
    expect(r.ok).toBe(false);
    expect(r.decidedBy).toBe('state');
    expect(r.violated).toEqual(['<state>']);
    expect(r.reasons).toEqual(['<state>: stale state head (digest)']);
    expect(r.next).toBe(s1);
    const bad = advanceContract({ bad: 1 } as unknown as MonitorState, act('read'), c, { expectedStateDigest: '<unhashable>' });
    expect(bad.ok).toBe(false);
    expect(bad.reasons).toEqual(['<state>: malformed monitor state']);
    // seq is checked before digest
    expect(advanceContract(s1, act('read'), c, { expectedSeq: 9, expectedStateDigest: d }).reasons).toEqual(['<state>: stale state head (seq)']);
    expect(advanceContract(s1, act('read'), c, { expectedSeq: 1, expectedStateDigest: 'nope' }).reasons).toEqual(['<state>: stale state head (digest)']);
  });
  it('violation: decidedBy contract for clause/invariant violations, state for structural ones; next is the input state', () => {
    const s0 = state0();
    const v = advanceContract(s0, act('write'), c);
    expect(v.ok).toBe(false);
    expect(v.decidedBy).toBe('contract');
    expect(v.next).toBe(s0);
    expect(v.violated).toEqual(['A']);
    for (const [a, k, st] of [
      [act('read'), { version: 9, principal: PRIN } as Contract, s0],
      [{} as ActionContext, c, s0],
      [act('read'), c, { bad: 1 } as unknown as MonitorState],
    ] as Array<[ActionContext, Contract, MonitorState]>) {
      const r = advanceContract(st, a, k);
      expect(r.ok).toBe(false);
      expect(r.decidedBy).toBe('state');
      expect(r.next).toBe(st);
    }
    // an id that merely starts with '<' (not a structural marker) is a contract violation
    const odd = contract([always('<odd', 'read')]);
    expect(advanceContract(s0, act('write'), odd).decidedBy).toBe('contract');
    const odd2 = contract([always('odd>', 'read')]);
    expect(advanceContract(s0, act('write'), odd2).decidedBy).toBe('contract');
    const odd3 = contract([always('<odd>', 'read')]);
    expect(advanceContract(s0, act('write'), odd3).decidedBy).toBe('state');
  });
  it('an uncomputable advance (unresolvable cap amount) is refused with the advance reason', () => {
    // verdict passes (the cap's `when` does not match during check), but the amount path is missing at advance... use a
    // cap whose amount resolves in check but not in advance: impossible; instead verify the pass-through of advance failures
    const k = contract([], [{ id: 'cap1', kind: 'cap', when: W('spend'), amount: 'action.params.amt', max: 10 }]);
    const r = advanceContract(state0(), act('spend', '/r', {}), k);
    expect(r.ok).toBe(false);
    expect(r.decidedBy).toBe('contract'); // the check already refuses (amount unresolvable)
    expect(r.reasons).toEqual(['cap1: amount unresolvable (fail closed)']);
  });
  it('a resulting state that violates the state invariants is refused (deadline key budget)', () => {
    const dl: Record<string, number> = {};
    for (let i = 0; i < 1024; i++) dl['d' + i] = 3;
    const full: MonitorState = { ...state0(), deadlines: dl };
    const k = contract([{ id: 'new', kind: 'responds_within', p: W('open'), q: W('close'), within: 2 }]);
    // not opening: the new clause's deadline entry is null (no key added)
    const ok = advanceContract(full, act('x'), k);
    expect(ok.ok).toBe(true);
    expect(Object.keys(ok.next.deadlines!).length).toBe(1024);
    const r = advanceContract(full, act('open'), k);
    expect(r.ok).toBe(false);
    expect(r.decidedBy).toBe('state');
    expect(r.violated).toEqual(['<state>']);
    expect(r.reasons).toEqual(['<state>: resulting state invalid: malformed monitor state: too many deadline keys']);
    expect(r.next).toBe(full);
  });
  it('never throws: a throwing option getter fails closed', () => {
    const opts = { get now(): number { throw new Error('boom'); } };
    const r = advanceContract(state0(), act('read'), c, opts as unknown as { now?: number });
    expect(r.ok).toBe(false);
    expect(r.decidedBy).toBe('state');
    expect(r.violated).toEqual(['<state>']);
    expect(r.reasons).toEqual(['<state>: advance error (fail closed)']);
    expect(r.evaluated).toStrictEqual([{ id: 'A', kind: 'always', result: 'pass' }]);
  });
  it('the verdict of the pre-state decides; next state latches come from the pre-state evaluation only', () => {
    // a q that arrives in the same action as p must still be refused (p is latched AFTER the action)
    const k = contract([{ id: 'P', kind: 'precedes', p: W(['review', 'deploy']), q: W('deploy') }]);
    const r = advanceContract(state0(), act('deploy'), k);
    expect(r.ok).toBe(false);
    expect(r.reasons).toEqual(['P: precedence violated (prerequisite p not yet admitted before q)']);
  });
});

describe('checkAndAdvanceContract', () => {
  const c = contract([always('A', 'read')]);
  it('allowed: permitted === true and the contract holds => advanced, allow true', () => {
    const r = checkAndAdvanceContract(true, state0(), act('read'), c);
    expect(r.allow).toBe(true);
    expect(r.permitted).toBe(true);
    expect(r.ok).toBe(true);
    expect(r.decidedBy).toBe('none');
    expect(r.next.seq).toBe(1);
  });
  it('permission denied: contract passes but the decision is deny with the <permission> reason; state not advanced', () => {
    const s0 = state0();
    const r = checkAndAdvanceContract(false, s0, act('read'), c);
    expect(r).toStrictEqual({
      ok: false,
      violated: [],
      reasons: ['<permission>: not permitted'],
      evaluated: [{ id: 'A', kind: 'always', result: 'pass' }],
      next: s0,
      decidedBy: 'contract',
      allow: false,
      permitted: false,
    });
    expect(r.next).toBe(s0);
  });
  it('only literal `true` counts as permitted', () => {
    for (const p of [1, 'true', {}, null, undefined, 'yes'] as unknown[]) {
      const r = checkAndAdvanceContract(p as boolean, state0(), act('read'), c);
      expect(r.allow).toBe(false);
      expect(r.permitted).toBe(false);
      expect(r.next.seq).toBe(0);
    }
  });
  it('contract refusal keeps its own verdict (and permitted is echoed)', () => {
    for (const permitted of [true, false]) {
      const r = checkAndAdvanceContract(permitted, state0(), act('write'), c);
      expect(r.allow).toBe(false);
      expect(r.permitted).toBe(permitted);
      expect(r.ok).toBe(false);
      expect(r.decidedBy).toBe('contract');
      expect(r.violated).toEqual(['A']);
      expect(r.reasons).toEqual(['A: always-invariant violated (action does not satisfy p)']);
    }
    const s1 = step(c, state0(), act('read'));
    const stale = checkAndAdvanceContract(true, s1, act('read'), c, { expectedSeq: 0 });
    expect(stale.allow).toBe(false);
    expect(stale.decidedBy).toBe('state');
    expect(stale.permitted).toBe(true);
  });
});

describe('contracts: late-failing inputs (fail-closed catches) and residual boundaries', () => {
  /** An object whose `key` getter serves `during` for the first `n` reads and `after` (or a throw) thereafter. */
  const flaky = (base: Record<string, unknown>, key: string, n: number, during: unknown, after: () => unknown): Record<string, unknown> => {
    let reads = 0;
    const o: Record<string, unknown> = { ...base };
    delete o[key];
    Object.defineProperty(o, key, { enumerable: true, get: () => (reads++ < n ? during : after()) });
    return o;
  };
  /** How many times validateContract reads `key` of a single clause. */
  const readsOf = (base: Record<string, unknown>, key: string, during: unknown): number => {
    let reads = 0;
    const o: Record<string, unknown> = { ...base };
    delete o[key];
    Object.defineProperty(o, key, { enumerable: true, get: () => (reads++, during) });
    expect(validateContract({ version: 1, principal: PRIN, clauses: [o as unknown as Clause] })).toEqual([]);
    return reads;
  };
  const boom = (): never => {
    throw new Error('boom');
  };

  it('a nested non-`and` clause carrying a `clauses` array does not inflate the clause count', () => {
    const flat = (n: number) => Array.from({ length: n }, (_, i) => always('c' + i, 'x'));
    const odd = { ...never('N', 'x'), clauses: flat(300) } as unknown as Clause;
    expect(validateContract({ version: 1, principal: PRIN, clauses: [odd] })).toEqual([]);
  });

  it('a clause whose kind changes after validation hits the default branch and fails closed with its reason', () => {
    const base = { id: 'x', p: W('a') };
    const n = readsOf({ ...base, kind: 'never' }, 'kind', 'never');
    const cl = flaky(base, 'kind', n, 'never', () => 'bogus') as unknown as Clause;
    const r = checkContract(act('zzz'), contract([cl]), state0());
    expect(r.ok).toBe(false);
    expect(r.violated).toEqual(['x']);
    expect(r.reasons).toEqual(['x: unknown clause kind (fail closed)']);
    expect(r.evaluated).toStrictEqual([{ id: 'x', kind: 'bogus', result: 'violated', reason: 'unknown clause kind (fail closed)' }]);
  });

  it('a clause whose `p` throws after validation is a violation with the evaluation-error reason', () => {
    const base = { id: 'x', kind: 'never' };
    const n = readsOf({ ...base, p: W('a') }, 'p', W('a'));
    const cl = flaky(base, 'p', n, W('a'), boom) as unknown as Clause;
    const r = checkContract(act('zzz'), contract([cl]), state0());
    expect(r.ok).toBe(false);
    expect(r.violated).toEqual(['x']);
    expect(r.reasons).toEqual(['x: clause evaluation error (fail closed)']);
    expect(r.evaluated).toStrictEqual([{ id: 'x', kind: 'never', result: 'violated', reason: 'clause evaluation error (fail closed)' }]);
  });

  /** A state whose `latched` throws once stateProblem is satisfied: evalClause fails outside its own try. */
  const lateState = (): MonitorState => {
    const probe = (() => {
      let reads = 0;
      const s: Record<string, unknown> = { ...state0() };
      delete s.latched;
      Object.defineProperty(s, 'latched', { enumerable: true, get: () => (reads++, {}) });
      expect(stateDigest(state0())).toBeTruthy();
      return { s, get reads() { return reads; } };
    })();
    // count the reads one checkContract performs before evalClause
    checkContract(act('zzz'), contract([]), probe.s as unknown as MonitorState);
    return flaky(state0() as unknown as Record<string, unknown>, 'latched', probe.reads, {}, boom) as unknown as MonitorState;
  };

  it('evalClause failing before its own try is caught per clause: a violated row keeping the clause kind', () => {
    const r = checkContract(act('zzz'), contract([never('x', 'a')]), lateState());
    expect(r.ok).toBe(false);
    expect(r.violated).toEqual(['x']);
    expect(r.reasons).toEqual(['x: clause evaluation error (fail closed)']);
    expect(r.evaluated).toStrictEqual([{ id: 'x', kind: 'never', result: 'violated', reason: 'clause evaluation error (fail closed)' }]);
  });

  it('...and a clause with no readable kind there is labelled "clause"', () => {
    const base = { id: 'x', p: W('a') };
    const n = readsOf({ ...base, kind: 'never' }, 'kind', 'never');
    const cl = flaky(base, 'kind', n, 'never', () => undefined) as unknown as Clause;
    const r = checkContract(act('zzz'), contract([cl]), lateState());
    expect(r.evaluated).toStrictEqual([{ id: 'x', kind: 'clause', result: 'violated', reason: 'clause evaluation error (fail closed)' }]);
    expect(r.reasons).toEqual(['x: clause evaluation error (fail closed)']);
  });

  it('a throwing action accessor is a <monitor> structural refusal', () => {
    const hostile = { get action(): never { return boom(); } } as unknown as ActionContext;
    const r = checkContract(hostile, contract([]), state0());
    expect(r).toStrictEqual({
      ok: false,
      violated: ['<monitor>'],
      reasons: ['<monitor>: monitor error (fail closed)'],
      evaluated: [{ id: '<monitor>', kind: 'structural', result: 'violated', reason: 'monitor error (fail closed)' }],
    });
  });

  it('a contract with no `clauses` property advances (clauses default to none)', () => {
    const c = { version: 1, principal: PRIN } as unknown as Contract;
    const r = advanceContract(state0(), act('x'), c);
    expect(r.ok).toBe(true);
    expect(r.next.seq).toBe(1);
    expect(r.next.latched).toEqual({});
    expect(r.next.deadlines).toBeUndefined();
  });

  it('decidedBy is "state" when ANY violated id looks structural (<...>), even beside an ordinary violation', () => {
    const c = contract([never('<a>', 'x'), never('b', 'x')]);
    const r = advanceContract(state0(), act('x'), c);
    expect(r.ok).toBe(false);
    expect(r.violated).toEqual(['<a>', 'b']);
    expect(r.decidedBy).toBe('state');
    expect(advanceContract(state0(), act('x'), contract([never('b', 'x'), never('c', 'x')])).decidedBy).toBe('contract');
  });
});
