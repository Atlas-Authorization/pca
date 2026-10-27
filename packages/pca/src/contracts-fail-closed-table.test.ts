import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from './keys';
import type { ActionContext } from './predicates';
import { emptyState, stateDigest, type MonitorState } from './prohibitions';
import {
  CONTRACT_VERSION,
  MAX_CLAUSES,
  MAX_CLAUSE_DEPTH,
  advanceContract,
  checkContract,
  signContract,
  validateContract,
  verifyContract,
  type Clause,
  type Contract,
} from './contracts';

const P = generateKeyPair();
const PRIN = encodeKey(P.publicKey);
const NOW = 1_700_000_000_000;
const act = (verb: string): ActionContext => ({ action: { verb, resource: '/r' } });
const base = (clauses: unknown): Contract => ({ version: CONTRACT_VERSION, principal: PRIN, clauses: clauses as Clause[] });
const nest = (n: number): Clause => {
  let c: Clause = { id: 'leaf', kind: 'never', p: { verb: 'x' } };
  for (let i = 0; i < n; i++) c = { id: `and${i}`, kind: 'and', clauses: [c] };
  return c;
};

describe('validateContract: missing or wrong X gives exact problem', () => {
  const NEVER = { id: 'a', kind: 'never', p: { verb: 'x' } };
  it.each<[string, unknown, string]>([
    ['not an object', null, 'contract not an object'],
    ['wrong version', { version: 2, principal: PRIN }, 'unsupported version 2'],
    ['no principal', { version: 1 }, 'principal missing'],
    ['clauses not an array', { version: 1, principal: PRIN, clauses: {} }, 'clauses not an array'],
    ['clause not an object', base([5]), 'clause not an object'],
    ['clause without id', base([{ kind: 'never', p: { verb: 'x' } }]), '<no id>: missing clause id'],
    ['unknown clause kind', base([{ id: 'u', kind: 'eventually', p: { verb: 'x' } }]), 'u: unknown clause kind eventually'],
    ['forbidden id', base([{ ...NEVER, id: '__proto__' }]), '__proto__: forbidden id'],
    ['duplicate ids', base([NEVER, NEVER]), 'a: duplicate id'],
    ['within 0', base([{ id: 'r', kind: 'responds_within', p: { verb: 'x' }, q: { verb: 'y' }, within: 0 }]), 'r: within must be an integer in [1, MAX_DEADLINE]'],
    ['within fractional', base([{ id: 'r', kind: 'responds_within', p: { verb: 'x' }, q: { verb: 'y' }, within: 1.5 }]), 'r: within must be an integer in [1, MAX_DEADLINE]'],
    ['empty and', base([{ id: 'n', kind: 'and', clauses: [] }]), 'n: and.clauses must be a non-empty array'],
  ])('%s', (_n, c, problem) => {
    expect(validateContract(c)).toContain(problem);
  });
  it('too many clauses', () => {
    const many = Array.from({ length: MAX_CLAUSES + 1 }, (_, i) => ({ id: `c${i}`, kind: 'never', p: { verb: 'x' } }));
    expect(validateContract(base(many))).toContain('too many clauses');
  });
  it('nesting deeper than the bound is refused; 20000 levels is refused without a stack overflow', () => {
    expect(validateContract(base([nest(MAX_CLAUSE_DEPTH - 2)]))).toEqual([]);
    expect(validateContract(base([nest(MAX_CLAUSE_DEPTH + 2)])).some((p) => p.includes('too deep'))).toBe(true);
    expect(validateContract(base([nest(20_000)])).length).toBeGreaterThan(0);
  });
});

describe('verifyContract: exact outcomes', () => {
  const sc = signContract(base([{ id: 'a', kind: 'never', p: { verb: 'x' } }]), P.secretKey);
  it('valid under the pinned principal', () => expect(verifyContract(sc, PRIN)).toEqual({ ok: true }));
  it('wrong principal', () => expect(verifyContract(sc, encodeKey(generateKeyPair().publicKey))).toEqual({ ok: false, reason: 'principal mismatch' }));
  it('tampered content changes the id', () => expect(verifyContract({ ...sc, clauses: [{ id: 'a', kind: 'never', p: { verb: 'y' } }] })).toEqual({ ok: false, reason: 'id does not match content' }));
  it('signature from another key', () => {
    const other = signContract({ ...base([{ id: 'a', kind: 'never', p: { verb: 'x' } }]) }, generateKeyPair().secretKey);
    expect(verifyContract({ ...sc, sig: other.sig })).toEqual({ ok: false, reason: 'bad signature' });
  });
  it('missing signature', () => expect(verifyContract({ ...sc, sig: undefined } as never)).toEqual({ ok: false, reason: 'bad signature' }));
  it('malformed input never throws', () => expect(verifyContract(null as never).ok).toBe(false));
});

describe('advanceContract: stale, forged and replayed state', () => {
  const c = base([{ id: 'order', kind: 'precedes', p: { verb: 'review' }, q: { verb: 'deploy' } }]);
  const s1 = advanceContract(emptyState(NOW), act('review'), c);
  it('admits the first action and chains seq 1', () => {
    expect(s1.ok).toBe(true);
    expect(s1.next.seq).toBe(1);
    expect(s1.next.parent).not.toBeNull();
  });
  it('replaying the genesis state with expectedSeq 1 is refused as stale and leaves the state unchanged', () => {
    const r = advanceContract(emptyState(NOW), act('review'), c, { expectedSeq: 1 });
    expect(r).toMatchObject({ ok: false, decidedBy: 'state', violated: ['<state>'] });
    expect(r.next).toEqual(emptyState(NOW));
  });
  it('a wrong digest head is refused', () => {
    const r = advanceContract(s1.next, act('deploy'), c, { expectedStateDigest: stateDigest(emptyState(NOW)) });
    expect(r).toMatchObject({ ok: false, decidedBy: 'state' });
  });
  it.each<[string, Partial<MonitorState> | Record<string, unknown>]>([
    ['negative seq', { seq: -1 }],
    ['seq with no parent link', { seq: 3, parent: null }],
    ['genesis with a parent', { seq: 0, parent: 'x' }],
    ['non-finite now', { now: Infinity }],
    ['ledger not an object', { ledger: 5 }],
  ])('forged state (%s) is refused, nothing advances', (_n, patch) => {
    const forged = { ...emptyState(NOW), ...patch } as MonitorState;
    const r = advanceContract(forged, act('review'), c);
    expect(r.ok).toBe(false);
    expect(r.next).toBe(forged);
  });
  it('the precedence obligation is enforced: deploy with no prior review is refused as a contract violation', () => {
    const r = advanceContract(emptyState(NOW), act('deploy'), c);
    expect(r).toMatchObject({ ok: false, decidedBy: 'contract', violated: ['order'] });
  });
  it('a clock that goes backwards is refused', () => {
    expect(advanceContract(s1.next, act('deploy'), c, { now: NOW - 1 }).ok).toBe(false);
  });
  it('checkContract with an unknown-kind clause smuggled past validation is refused (fail closed)', () => {
    const bad = base([{ id: 'u', kind: 'eventually', p: { verb: 'x' } }]);
    expect(checkContract(act('read'), bad, emptyState(NOW)).ok).toBe(false);
    expect(advanceContract(emptyState(NOW), act('read'), bad).ok).toBe(false);
  });
});
