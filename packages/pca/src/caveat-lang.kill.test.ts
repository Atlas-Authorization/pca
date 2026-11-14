// Exact-outcome tests for caveat-lang.ts that complement caveat-lang.mutation-kill.test.ts: closed member lists, type checks
// before a regex (an array coerces to a matching string), boundary values, the fail-closed catch paths, hop analysis over a
// custom ChainView, post-quantum narrow blocks, and the module-level constants and regexes (re-evaluated in a fresh module).
import { describe, expect, it, vi } from 'vitest';
import { capHash, mintRoot, type Capability, type Caveat } from './capability';
import {
  boundCaveats,
  deriveError,
  dischargeRequests,
  dischargeShapeError,
  evaluateDerive,
  evaluateK1,
  maxUsesError,
  narrowShapeError,
  needsDischargeError,
  reserveMaxUses,
  signDischarge,
  signNarrow,
  spiffeBoundError,
  spiffeIdError,
  verifyDischarge,
  verifyNarrow,
  type ChainView,
  type DeriveCaveat,
  type DischargePin,
} from './caveat-lang';
import { b64u } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';

const NOW = 1_800_000_000_000;
const MARK = ['Stry', 'ker was here'].join('');
const kp = () => {
  const k = generateKeyPair();
  return { sk: k.secretKey, pub: encodeKey(k.publicKey) };
};
const principal = kp(), agent = kp(), issuer = kp();
const PIN: DischargePin = { label: 'risk-team', class: 'human', pk: issuer.pub };
const rootOf = (caveats: unknown[], holderPq?: string) =>
  mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats: caveats as Caveat[], ...(holderPq !== undefined ? { holderPq } : {}) });
const g: Capability = rootOf([]);
const cap = capHash(g);
const nonce = b64u(new Uint8Array(16).fill(4));
const nd = (o: Record<string, unknown> = {}) => ({ type: 'needs_discharge', id: 'kyc', issuer: 'risk-team', issuer_class: 'human', bind: 'chain_hop', ttl_ms: 1000, require: [], ...o });
const dBody = (o: Record<string, unknown> = {}) => ({ v: 1, kind: 'pca-discharge', caveat_id: 'kyc', issuer: 'risk-team', cap_hash: cap, bind: 'chain_hop', claims: {}, iat: NOW, not_after: NOW + 1000, nonce, ...o });
const dis = (o: Record<string, unknown> = {}) => signDischarge(dBody(o) as never, issuer.sk);
const B = { cap_hash: cap, pins: [PIN], now: NOW };
const nBody = (o: Record<string, unknown> = {}) => ({ v: 1, kind: 'pca-narrow', cap_hash: cap, holder: agent.pub, caveats: [{ type: 'expires', at: NOW + 5 }], iat: NOW, not_after: NOW + 10, nonce, ...o });
const dv = (o: Record<string, unknown> = {}) => ({ type: 'derive', id: 'd', defs: [], check: { const: true }, ...o });
const view = (o: Omit<Partial<ChainView>, 'leaf'> & { leaf: unknown }): ChainView => ({ n: 1, hash: () => cap, count: () => 1, ...o }) as ChainView;

describe('spiffeIdError: a slash at index 1 of the rest still has its path checked', () => {
  it('exact', () => {
    expect(spiffeIdError('spiffe://a/..')).toBe('invalid path segment');
    expect(spiffeIdError('spiffe://a/')).toBe('path must not end with a slash');
    expect(spiffeIdError('spiffe://a/b')).toBeNull();
  });
});

describe('boundCaveats and chainView', () => {
  it('a null, empty-array or non-view object chain falls back to the grant', () => {
    const r = rootOf([{ type: 'sealed' }]);
    const want = [{ caveat: { type: 'sealed' }, hop: 0, cap_hash: capHash(r) }];
    expect(boundCaveats(r, null as never)).toEqual(want);
    expect(boundCaveats(r, [])).toEqual(want);
    expect(boundCaveats(r, {} as never)).toEqual(want);
  });
  it('a null hop in an array chain counts zero caveats', () => {
    const r = rootOf([{ type: 'sealed' }]);
    expect(boundCaveats(g, [null, r] as never)).toEqual([{ caveat: { type: 'sealed' }, hop: 1, cap_hash: capHash(r) }]);
  });
  it('a hop is hashed once per call (the hash is cached)', () => {
    let k = 0;
    const hop = { caveats: [{ type: 'a' }, { type: 'b' }], get x() { return k++; } };
    const out = boundCaveats(hop as never, [hop] as never)!;
    expect(out).toHaveLength(2);
    expect(out[0]!.cap_hash).toBe(out[1]!.cap_hash);
  });
  it('a caveat no hop count covers belongs to the last hop of the view (never past it, never -1)', () => {
    const v = view({ n: 3, leaf: { caveats: [{ type: 'sealed' }] }, hash: (i) => `h${i}`, count: (i) => (i === 3 ? 5 : 0) });
    expect(boundCaveats(g, v)).toEqual([{ caveat: { type: 'sealed' }, hop: 2, cap_hash: 'h2' }]);
  });
  it('a leaf whose caveats are not an array is malformed', () => {
    const odd = { forEach: (fn: (c: unknown, p: number) => void) => fn({ type: 'sealed' }, 0) };
    expect(boundCaveats(g, view({ leaf: { caveats: odd } }))).toBeNull();
    expect(boundCaveats(g, view({ leaf: undefined }))).toBeNull();
  });
  it('a throwing view is null (not undefined)', () => {
    expect(boundCaveats(g, view({ leaf: { caveats: [{ type: 'x' }] }, count: () => { throw new Error('boom'); } }))).toBeNull();
  });
});

describe('needs_discharge requirements and members', () => {
  const rq = (r: unknown) => needsDischargeError(nd({ require: [r] }));
  it('exact', () => {
    expect(rq({ claim: 'a', op: 'eq', value: 1, [MARK]: 1 })).toBe(`unknown member 'require.${MARK}'`);
    expect(rq({ claim: 'a', op: 'eq', value: 1, x: 1 })).toBe("unknown member 'require.x'");
    expect(rq({ claim: ['a'], op: 'eq', value: 1 })).toBe('claim name is malformed');
    expect(rq({ claim: 'a', op: 'in', value: [1, {}] })).toBe("'in' needs 1..16 scalar values");
    expect(rq({ claim: 'a', op: 'in', value: [{}, 1] })).toBe("'in' needs 1..16 scalar values");
    expect(needsDischargeError(nd({ id: ['kyc'] }))).toBe('id is malformed');
    expect(needsDischargeError(nd({ issuer: ['risk-team'] }))).toBe('issuer label is malformed');
  });
});

describe('dischargeShapeError edges', () => {
  const d = dis();
  it('exact', () => {
    expect(dischargeShapeError({ ...d, caveat_id: ['kyc'] })).toBe('caveat_id is malformed');
    expect(dischargeShapeError({ ...d, issuer: ['risk-team'] })).toBe('issuer label is malformed');
    expect(dischargeShapeError({ ...d, iat: 0, not_after: 1000 })).toBeNull();
    expect(dischargeShapeError({ ...d, not_after: -1 })).toBe('iat and not_after must be non-negative safe integers');
    expect(dischargeShapeError({ ...d, iat: 0, not_after: 0 })).toBe('not_after must be greater than iat');
    expect(dischargeShapeError({ ...d, nonce: 5 })).toBe('nonce must be canonical base64url of at least 16 bytes');
    expect(dischargeShapeError({ ...d, nonce: 'not base64!' })).toBe('nonce must be canonical base64url of at least 16 bytes');
  });
});

describe('verifyDischarge', () => {
  it('a pin that carries a SPIFFE ID still discharges a caveat that names none', () => {
    const ok = dis();
    expect(verifyDischarge(ok, nd(), { ...B, pins: [{ ...PIN, spiffe_id: 'spiffe://a.test/x' }] })).toEqual({ ok: true, digest: expect.any(String), claims: {} });
  });
  it('an exception is a fail-closed refusal with the message', () => {
    const boom = { cap_hash: cap, pins: [PIN], get now(): number { throw new Error('boom'); } };
    expect(verifyDischarge(dis(), nd(), boom)).toEqual({ ok: false, reason: 'discharge error (fail closed): boom' });
    const odd = { cap_hash: cap, pins: [PIN], get now(): number { throw 5; } };
    expect(verifyDischarge(dis(), nd(), odd)).toEqual({ ok: false, reason: 'discharge error (fail closed): unknown' });
  });
});

describe('dischargeRequests', () => {
  it('a null caveat is skipped, and an absent action digest is not a member', () => {
    expect(dischargeRequests(g, view({ leaf: { caveats: [null] } }), undefined)).toEqual([]);
    const r = rootOf([nd({ bind: 'action' })]);
    const out = dischargeRequests(r, [r], undefined);
    expect(out).toHaveLength(1);
    expect(Object.keys(out[0]!)).toEqual(['v', 'kind', 'caveat_id', 'issuer', 'cap_hash', 'bind', 'require', 'ttl_ms']);
  });
});

describe('narrowShapeError edges', () => {
  const n = signNarrow(nBody() as never, agent.sk);
  it('exact', () => {
    expect(narrowShapeError({ ...n, extra: 1 })).toBe("unknown member 'narrow.extra'");
    expect(narrowShapeError({ ...n, kind: 'x' })).toBe('not a pca-narrow v1');
    expect(narrowShapeError({ ...n, caveats: [{ type: 5 }] })).toBe('every caveat must be an object with a string type');
    expect(narrowShapeError({ ...n, iat: 0, not_after: 10 })).toBeNull();
    expect(narrowShapeError({ ...n, iat: 0, not_after: 1.5 })).toBe('iat and not_after must be non-negative safe integers');
    expect(narrowShapeError({ ...n, not_after: -1 })).toBe('iat and not_after must be non-negative safe integers');
    expect(narrowShapeError({ ...n, iat: 0, not_after: 0 })).toBe('not_after must be greater than iat');
    expect(narrowShapeError({ ...n, nonce: 5 })).toBe('nonce must be canonical base64url of at least 16 bytes');
    expect(narrowShapeError({ ...n, nonce: 'not base64!' })).toBe('nonce must be canonical base64url of at least 16 bytes');
    expect(narrowShapeError({ ...n, sig: 5 })).toBe('sig must be a string');
  });
});

describe('verifyNarrow', () => {
  it('malformed, wrong signer, exceptions', () => {
    expect(verifyNarrow(5, g, [g], { now: NOW })).toEqual({ ok: false, reason: 'malformed narrow block: not an object' });
    expect(verifyNarrow(signNarrow(nBody() as never, kp().sk), g, [g], { now: NOW })).toEqual({ ok: false, reason: 'narrow signature invalid' });
    const n = signNarrow(nBody() as never, agent.sk);
    expect(verifyNarrow(n, g, [g], { get now(): number { throw new Error('boom'); } })).toEqual({ ok: false, reason: 'narrow error (fail closed): boom' });
    expect(verifyNarrow(n, g, [g], { get now(): number { throw 5; } })).toEqual({ ok: false, reason: 'narrow error (fail closed): unknown' });
  });
  it('a post-quantum narrow verifies only under the PQ key the leaf commits to', () => {
    const m = mlDsa65Keygen(new Uint8Array(32).fill(7));
    const other = mlDsa65Keygen(new Uint8Array(32).fill(8));
    const pqOf = (k: ReturnType<typeof mlDsa65Keygen>) => encodeMlDsaPublicKey(k.publicKey);
    const sign = (r: Capability) => signNarrow(nBody({ cap_hash: capHash(r) }) as never, agent.sk, { alg: 'ml-dsa-65', mlDsa: m });
    const committed = rootOf([], pqOf(m));
    expect(verifyNarrow(sign(committed), committed, [committed], { now: NOW })).toEqual({ ok: true, caveats: [{ type: 'expires', at: NOW + 5 }] });
    const uncommitted = rootOf([]);
    expect(verifyNarrow(sign(uncommitted), uncommitted, [uncommitted], { now: NOW })).toEqual({ ok: false, reason: 'narrow signature invalid' });
    const wrong = rootOf([], pqOf(other));
    expect(verifyNarrow(sign(wrong), wrong, [wrong], { now: NOW })).toEqual({ ok: false, reason: 'narrow signature invalid' });
    // an Ed25519 narrow under a leaf that commits to a PQ key is still the Ed25519 signature
    const ed = signNarrow(nBody({ cap_hash: capHash(committed) }) as never, agent.sk);
    expect(verifyNarrow(ed, committed, [committed], { now: NOW })).toEqual({ ok: true, caveats: [{ type: 'expires', at: NOW + 5 }] });
  });
});

describe('max_uses', () => {
  const mu = (o: Record<string, unknown> = {}) => ({ type: 'max_uses', id: 'u', n: 2, until: NOW + 10, ...o });
  it('shape', () => {
    expect(maxUsesError(mu({ [MARK]: 1 }))).toBe(`unknown member 'max_uses.${MARK}'`);
    expect(maxUsesError(mu({ x: 1 }))).toBe("unknown member 'max_uses.x'");
    expect(maxUsesError(mu({ id: ['u'] }))).toBe('id is malformed');
  });
  it('a null caveat is skipped; a non-Error failure is unknown', async () => {
    const never = { consumeOnce: () => Promise.resolve(false) };
    expect(await reserveMaxUses(never, [{ caveat: null as never, hop: 0, cap_hash: cap }], NOW)).toEqual({ ok: true, spent: 0 });
    const odd = { consumeOnce: () => Promise.reject(5) };
    expect(await reserveMaxUses(odd, [{ caveat: mu() as never, hop: 0, cap_hash: cap }], NOW)).toEqual({ ok: false, reason: 'max_uses error (fail closed): unknown' });
  });
});

describe('deriveError: expressions', () => {
  const pa = [{ name: 'a', kind: 'param', path: 'a' }];
  const chk = (check: unknown, defs: unknown[] = pa) => deriveError(dv({ defs, check }));
  it('exact', () => {
    expect(chk(5)).toBe('expression must be an object');
    expect(chk({ ref: 'a', [MARK]: 1 })).toBe(`unknown member 'ref.${MARK}'`);
    expect(chk({ ref: 'a', x: 1 })).toBe("unknown member 'ref.x'");
    expect(chk({ const: true, [MARK]: 1 })).toBe(`unknown member 'const.${MARK}'`);
    expect(chk({ const: true, x: 1 })).toBe("unknown member 'const.x'");
    expect(chk({ op: 'and', args: [{ const: true }], [MARK]: 1 })).toBe(`unknown member 'and.${MARK}'`);
    expect(chk({ op: 'or', args: [{ const: true }], x: 1 })).toBe("unknown member 'or.x'");
    expect(chk({ op: 'and', args: [{ const: true }] })).toBeNull();
    expect(chk({ op: 'and', args: Array.from({ length: 8 }, () => ({ const: true })) })).toBeNull();
    expect(chk({ op: 'and', args: [{ op: 'and', args: [{ op: 'and', args: [{ op: 'and', args: [{ const: true }] }] }] }] })).toBe('expression nests deeper than 4');
    expect(chk({ op: 'not', arg: { const: true }, [MARK]: 1 })).toBe(`unknown member 'not.${MARK}'`);
    expect(chk({ op: 'not', arg: { const: true }, x: 1 })).toBe("unknown member 'not.x'");
    expect(chk({ op: 'eq', a: { const: 1 }, b: { const: 1 }, [MARK]: 1 })).toBe(`unknown member 'eq.${MARK}'`);
    expect(chk({ op: 'eq', a: { const: 1 }, b: { const: 1 }, x: 1 })).toBe("unknown member 'eq.x'");
    expect(chk({ op: 'eq', a: { const: 1 }, b: { ref: 'nope' } })).toBe('ref names no earlier def');
    expect(chk({ op: 'eq', a: { ref: 'nope' }, b: { const: 1 } })).toBe('ref names no earlier def');
    const deep = { op: 'not', arg: { op: 'not', arg: { op: 'not', arg: { const: true } } } };
    expect(chk({ op: 'eq', a: deep, b: { const: 1 } })).toBe('expression nests deeper than 4');
    expect(chk({ op: 'eq', a: { const: 1 }, b: deep })).toBe('expression nests deeper than 4');
    expect(chk({ op: 'eq', a: { ref: 'a' }, b: { const: 1 } })).toBeNull();
  });
});

describe('deriveError: caveat and defs', () => {
  const def = (d: unknown) => deriveError(dv({ defs: [d] }));
  it('exact', () => {
    expect(deriveError(dv({ [MARK]: 1 }))).toBe(`unknown member 'derive.${MARK}'`);
    expect(deriveError(dv({ x: 1 }))).toBe("unknown member 'derive.x'");
    expect(deriveError(dv({ id: ['d'] }))).toBe('id is malformed');
    expect(def({ name: ['a'], kind: 'param', path: 'x' })).toBe('def name is malformed');
    expect(def({ name: 'a', kind: 'count', window_ms: 1, x: 1 })).toBe("def 'a': unknown member 'count.x'");
    expect(def({ name: 'a', kind: 'param', path: 'x', [MARK]: 1 })).toBe(`def 'a': unknown member 'param.${MARK}'`);
    expect(def({ name: 'a', kind: 'param', path: 'x', x: 1 })).toBe("def 'a': unknown member 'param.x'");
    expect(def({ name: 'a', kind: 'param', path: ['a'] })).toBe("def 'a': param path is malformed");
    expect(def({ name: 'a', kind: 'action', field: 'verb', [MARK]: 1 })).toBe(`def 'a': unknown member 'action.${MARK}'`);
    expect(def({ name: 'a', kind: 'action', field: 'verb', x: 1 })).toBe("def 'a': unknown member 'action.x'");
    expect(def({ name: 'a', kind: 'action', field: 'resource' })).toBeNull();
    expect(def({ name: 'a', kind: 'action', field: 'verb' })).toBeNull();
    expect(def({ name: 'a', kind: 'claim', caveat_id: 'kyc', claim: 'lvl', [MARK]: 1 })).toBe(`def 'a': unknown member 'claim.${MARK}'`);
    expect(def({ name: 'a', kind: 'claim', caveat_id: 'kyc', claim: 'lvl', x: 1 })).toBe("def 'a': unknown member 'claim.x'");
    expect(def({ name: 'a', kind: 'claim', caveat_id: ['kyc'], claim: 'lvl' })).toBe("def 'a': claim reference is malformed");
    expect(def({ name: 'a', kind: 'claim', caveat_id: 'kyc', claim: ['lvl'] })).toBe("def 'a': claim reference is malformed");
    expect(def({ name: 'a', kind: 'claim', caveat_id: 'kyc', claim: 'lvl' })).toBeNull();
    expect(def({ name: 'a', kind: 'expr', expr: { const: true }, [MARK]: 1 })).toBe(`def 'a': unknown member 'expr.${MARK}'`);
    expect(def({ name: 'a', kind: 'expr', expr: { const: true }, x: 1 })).toBe("def 'a': unknown member 'expr.x'");
    expect(def({ name: 'a', kind: 'expr', expr: { ref: 'nope' } })).toBe("def 'a': ref names no earlier def");
    expect(def({ name: 'a', kind: 'expr', expr: { const: true } })).toBeNull();
  });
});

describe('evaluateDerive', () => {
  const run = (c: unknown, over: Record<string, unknown> = {}) => evaluateDerive(c as DeriveCaveat, { now: NOW, claims: {}, ...over } as never);
  it('a missing right operand is unknown', () => {
    expect(run(dv({ defs: [{ name: 'm', kind: 'param', path: 'm' }], check: { op: 'eq', a: { const: 1 }, b: { ref: 'm' } } }))).toBeNull();
    expect(run(dv({ defs: [{ name: 'm', kind: 'param', path: 'm' }], check: { op: 'neq', a: { const: 1 }, b: { ref: 'm' } } }))).toBeNull();
  });
  it('a history event with a non-string verb or resource makes the count unknown', () => {
    const c = dv({ defs: [{ name: 'n', kind: 'count', window_ms: 100 }], check: { op: 'eq', a: { ref: 'n' }, b: { const: 1 } } });
    expect(run(c, { history: [{ t: NOW, verb: 'v', resource: 'r' }] })).toBe(true);
    expect(run(c, { history: [{ t: NOW, verb: 5, resource: 'r' }] })).toBeNull();
    expect(run(c, { history: [{ t: NOW, verb: 'v', resource: 5 }] })).toBeNull();
  });
  it('an action fact without an action is unknown', () => {
    expect(run(dv({ defs: [{ name: 'r', kind: 'action', field: 'verb' }], check: { op: 'eq', a: { ref: 'r' }, b: { const: 'x' } } }))).toBeNull();
  });
});

describe('spiffeBoundError members', () => {
  it('exact', () => {
    expect(spiffeBoundError({ type: 'spiffe_bound', spiffe_id: 'spiffe://a.test/x', x: 1 })).toBe("unknown member 'spiffe_bound.x'");
  });
});

describe('evaluateK1 exact results', () => {
  const run = (caveats: unknown[], k1: unknown = {}, ctx: unknown = { now: NOW }) => {
    const r = rootOf(caveats);
    return evaluateK1(r, [r], k1 as never, ctx as never);
  };
  const res = (failed: string[], reasons: string[]) => ({ ok: failed.length === 0, failed, reasons });
  it('a missing ctx and a throwing clock are one <malformed> refusal with empty lists', () => {
    expect(evaluateK1(g, [g], {}, undefined as never)).toEqual({ ...res(['<malformed>'], ['the verifier clock is not a safe integer (fail closed)']), plain: [], bound: [] });
    expect(evaluateK1(g, [g], {}, { get now(): number { throw new Error('boom'); } })).toEqual({ ...res(['<malformed>'], ['caveat language error (fail closed): boom']), plain: [], bound: [] });
    expect(evaluateK1(g, [g], {}, { get now(): number { throw 5; } })).toEqual({ ...res(['<malformed>'], ['caveat language error (fail closed): unknown']), plain: [], bound: [] });
  });
  it('a failed narrow block returns only the K1 caveats as bound', () => {
    const r = rootOf([{ type: 'expires', at: NOW + 5 }, { type: 'sealed' }]);
    expect(evaluateK1(r, [r], { narrow: 5 }, { now: NOW })).toEqual({ ...res(['narrow'], ['malformed narrow block: not an object']), plain: [], bound: [{ caveat: { type: 'sealed' }, hop: 0, cap_hash: capHash(r) }] });
  });
  it('a caveat without an id never collides with the id "undefined"', () => {
    const r = run([dv({ id: 'undefined' }), { type: 'derive', defs: [], check: { const: true } }]);
    expect(r).toMatchObject(res(['derive'], ["missing member 'derive.id'"]));
  });
  it('needs_discharge: malformed, duplicate, discharges for other caveats are skipped', () => {
    expect(run([nd({ ttl_ms: 0 })])).toMatchObject(res(['needs_discharge'], ['ttl_ms must be 1..86400000']));
    expect(run([nd(), nd()])).toMatchObject(res(['needs_discharge', 'needs_discharge'], ["duplicate needs_discharge id 'kyc'", "duplicate needs_discharge id 'kyc'"]));
    expect(run([nd()], { pins: [PIN], discharges: [dis({ caveat_id: 'other' })] })).toMatchObject(res(['needs_discharge'], ['no discharge presented']));
  });
  it('sealed, max_uses, derive and spiffe_bound reasons', () => {
    expect(run([{ type: 'sealed', [MARK]: 1 }])).toMatchObject(res(['sealed'], [`unknown member 'sealed.${MARK}'`]));
    expect(run([{ type: 'sealed', x: 1 }])).toMatchObject(res(['sealed'], ["unknown member 'sealed.x'"]));
    const mu = { type: 'max_uses', id: 'u', n: 1, until: NOW + 1 };
    expect(run([mu, mu])).toMatchObject(res(['max_uses', 'max_uses'], ["duplicate max_uses id 'u'", "duplicate max_uses id 'u'"]));
    expect(run([{ ...mu, until: NOW }])).toMatchObject(res(['max_uses'], ["max_uses 'u' has expired"]));
    expect(run([{ ...mu, until: NOW + 1 }])).toMatchObject(res([], []));
    expect(run([dv(), dv()])).toMatchObject(res(['derive', 'derive'], ["duplicate derive id 'd'", "duplicate derive id 'd'"]));
    expect(run([dv({ check: { const: false } })])).toMatchObject(res(['derive'], ['derive check is false']));
    expect(run([dv({ defs: [{ name: 'm', kind: 'param', path: 'm' }], check: { ref: 'm' } })])).toMatchObject(res(['derive'], ['derive check is unknown (a fact is missing)']));
    expect(run([{ type: 'spiffe_bound', spiffe_id: 'spiffe://a.test/x' }])).toMatchObject(res(['spiffe_bound'], ['the presenting workload does not carry the required SPIFFE ID']));
  });
  it('a caveat whose type stops being a string is reported as <malformed>', () => {
    let flip = false;
    const cav = { get type() { return flip ? 5 : 'spiffe_bound'; }, spiffe_id: 'spiffe://a.test/x' };
    const k1 = { get spiffe_id() { flip = true; return undefined; } };
    const r = evaluateK1(g, view({ leaf: { caveats: [cav] } }), k1 as never, { now: NOW });
    expect({ ok: r.ok, failed: r.failed, reasons: r.reasons }).toEqual(res(['<malformed>'], ['the presenting workload does not carry the required SPIFFE ID']));
  });
});

// Module-level constants, regexes and helpers are built once at import: re-evaluate the module so they are rebuilt.
async function fresh() {
  vi.resetModules();
  return import('./caveat-lang');
}

describe('caveat-lang.ts (fresh module): constants', () => {
  it('names, domains and limits', async () => {
    const m = await fresh();
    expect([m.CAVEAT_NEEDS_DISCHARGE, m.CAVEAT_SEALED, m.CAVEAT_MAX_USES, m.CAVEAT_DERIVE, m.CAVEAT_SPIFFE_BOUND]).toEqual(['needs_discharge', 'sealed', 'max_uses', 'derive', 'spiffe_bound']);
    expect([...m.K1_CAVEAT_TYPES]).toEqual(['needs_discharge', 'sealed', 'max_uses', 'derive', 'spiffe_bound']);
    expect([m.DISCHARGE_DOMAIN, m.DISCHARGE_REF_DOMAIN, m.DISCHARGE_ACTION_DOMAIN, m.NARROW_DOMAIN, m.MAX_USES_DOMAIN]).toEqual([
      'atlas-pca/discharge/v1\0',
      'atlas-pca/discharge-ref/v1',
      'atlas-pca/discharge-action/v1',
      'atlas-pca/narrow/v1\0',
      'atlas-pca/max-uses/v1\0',
    ]);
    expect(m.DERIVE_MAX_WINDOW_MS).toBe(2_592_000_000);
    expect(m.isK1Caveat({ type: 'sealed' })).toBe(true);
    expect(m.isK1Caveat({ type: 'expires' })).toBe(false);
  });
  it('the narrow block forbids exactly envelope, sealed, budget_alloc and intent_session', async () => {
    const m = await fresh();
    const n = signNarrow(nBody() as never, agent.sk);
    for (const type of ['envelope', 'sealed', 'budget_alloc', 'intent_session']) expect(m.narrowShapeError({ ...n, caveats: [{ type }] })).toBe(`a narrow block cannot carry a '${type}' caveat`);
    expect(m.narrowShapeError({ ...n, caveats: [{ type: 'expires', at: 1 }] })).toBeNull();
  });
});

describe('caveat-lang.ts (fresh module): name and id syntax', () => {
  it('claim names: ^[a-z][a-z0-9_]{0,63}$', async () => {
    const m = await fresh();
    const claim = (c: string) => m.needsDischargeError(nd({ require: [{ claim: c, op: 'eq', value: 1 }] }));
    for (const c of ['a', 'ab', 'a_1', `a${'b'.repeat(63)}`]) expect(claim(c), c).toBeNull();
    for (const c of ['Aa', '1a', 'a-', '', `a${'b'.repeat(64)}`]) expect(claim(c), c).toBe('claim name is malformed');
  });
  it('ids: ^[a-z0-9][a-z0-9_.-]{0,63}$', async () => {
    const m = await fresh();
    const id = (i: string) => m.needsDischargeError(nd({ id: i }));
    for (const i of ['0', 'a', 'ab', 'a.b-c_d', `a${'b'.repeat(63)}`]) expect(id(i), i).toBeNull();
    for (const i of ['Xa', '.a', 'a/', '', `a${'b'.repeat(64)}`]) expect(id(i), i).toBe('id is malformed');
  });
  it('the own-property, string and scalar helpers', async () => {
    const m = await fresh();
    expect(m.deriveError(dv({ defs: [{ name: 'a', kind: 'param', path: 'a' }], check: { ref: 'a' } }))).toBeNull();
    expect(m.deriveError(dv({ check: { const: true } }))).toBeNull();
    const val = (v: unknown) => m.needsDischargeError(nd({ require: [{ claim: 'a', op: 'eq', value: v }] }));
    expect(val('x')).toBeNull();
    expect(val(1)).toBeNull();
    expect(val(true)).toBeNull();
    expect(val('')).toBe('value must be a scalar');
  });
  it('a ChainView is used as given', async () => {
    const m = await fresh();
    const v = view({ n: 3, leaf: { caveats: [{ type: 'sealed' }] }, hash: (i) => `h${i}`, count: (i) => (i === 2 ? 1 : 0) });
    expect(m.boundCaveats(g, v)).toEqual([{ caveat: { type: 'sealed' }, hop: 2, cap_hash: 'h2' }]);
  });
});
