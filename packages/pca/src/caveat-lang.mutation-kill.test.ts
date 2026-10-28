// Exact-outcome tests for caveat-lang.ts: every boundary, every refusal reason and every default is pinned, so a mutant that moves a
// limit by one, flips a comparison, drops a check or rewords a reason is caught here (the vectors pin the same from the other side).
import { describe, expect, it } from 'vitest';
import { capHash, delegate, mintRoot, type Capability, type Caveat } from './capability';
import {
  DERIVE_MAX_DEFS,
  DERIVE_MAX_DEPTH,
  DERIVE_MAX_HISTORY,
  DERIVE_MAX_NODES,
  DERIVE_MAX_WINDOW_MS,
  K1_CAVEAT_TYPES,
  K1_MAX_LIFETIME_MS,
  MAX_USES_LIMIT,
  NARROW_MAX_CAVEATS,
  SPIFFE_MAX_ID_BYTES,
  boundCaveats,
  deriveError,
  dischargeDigest,
  dischargeRequests,
  dischargeShapeError,
  evaluateDerive,
  evaluateK1,
  isK1Caveat,
  maxUsesError,
  maxUsesSlotKey,
  needsDischargeError,
  narrowShapeError,
  reserveMaxUses,
  signDischarge,
  signNarrow,
  spiffeBoundError,
  spiffeIdError,
  verifyDischarge,
  verifyNarrow,
  type DeriveCaveat,
  type DischargePin,
} from './caveat-lang';
import { b64u } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { InMemoryReplayStore } from './replay';

const NOW = 1_800_000_000_000;
const kp = () => {
  const k = generateKeyPair();
  return { sk: k.secretKey, pub: encodeKey(k.publicKey) };
};
const principal = kp(), agent = kp(), issuer = kp();
const PIN: DischargePin = { label: 'risk-team', class: 'human', pk: issuer.pub };
const g: Capability = mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats: [] });
const cap = capHash(g);
const nonce = b64u(new Uint8Array(16).fill(4));
const nd = (o: Record<string, unknown> = {}) => ({ type: 'needs_discharge', id: 'kyc', issuer: 'risk-team', issuer_class: 'human', bind: 'chain_hop', ttl_ms: 1000, require: [], ...o });
const body = (o: Record<string, unknown> = {}) => ({ v: 1, kind: 'pca-discharge', caveat_id: 'kyc', issuer: 'risk-team', cap_hash: cap, bind: 'chain_hop', claims: {}, iat: NOW, not_after: NOW + 1000, nonce, ...o });
const dis = (o: Record<string, unknown> = {}) => signDischarge(body(o) as never, issuer.sk);
const B = { cap_hash: cap, pins: [PIN], now: NOW };
const rootOf = (caveats: Caveat[]) => mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats });

describe('constants', () => {
  it('pin the limits', () => {
    expect([K1_MAX_LIFETIME_MS, MAX_USES_LIMIT, NARROW_MAX_CAVEATS, DERIVE_MAX_DEFS, DERIVE_MAX_NODES, DERIVE_MAX_DEPTH, DERIVE_MAX_WINDOW_MS, DERIVE_MAX_HISTORY, SPIFFE_MAX_ID_BYTES]).toEqual([86_400_000, 256, 16, 8, 32, 4, 2_592_000_000, 10_000, 2048]);
    expect([...K1_CAVEAT_TYPES]).toEqual(['needs_discharge', 'sealed', 'max_uses', 'derive', 'spiffe_bound']);
  });
  it('isK1Caveat is exact', () => {
    for (const t of K1_CAVEAT_TYPES) expect(isK1Caveat({ type: t })).toBe(true);
    for (const v of [{ type: 'expires' }, { type: 5 }, {}, null, 'sealed', [], { type: 'Sealed' }]) expect(isK1Caveat(v)).toBe(false);
  });
});

describe('spiffeIdError', () => {
  it.each([
    ['', 'SPIFFE ID must be a non-empty string'],
    ['http://a.test/x', 'SPIFFE ID must begin with spiffe://'],
    ['spiffe:///x', 'invalid trust domain'],
    ['spiffe://A.test', 'invalid trust domain'],
    ['spiffe://a.test/', 'path must not end with a slash'],
    ['spiffe://a.test/x/', 'path must not end with a slash'],
    ['spiffe://a.test//x', 'invalid path segment'],
    ['spiffe://a.test/.', 'invalid path segment'],
    ['spiffe://a.test/..', 'invalid path segment'],
    ['spiffe://a.test/x y', 'invalid path segment'],
    ['spiffe://a.test/x?y', 'invalid path segment'],
    ['spiffe://a.test:80/x', 'invalid trust domain'],
  ])('%s -> %s', (id, why) => expect(spiffeIdError(id)).toBe(why));
  it('accepts the documented shapes and the length boundaries', () => {
    expect(spiffeIdError('spiffe://a')).toBeNull();
    expect(spiffeIdError('spiffe://a-b_c.d/E.f_g-h/1')).toBeNull();
    const td255 = 'a'.repeat(255);
    expect(spiffeIdError(`spiffe://${td255}`)).toBeNull();
    expect(spiffeIdError(`spiffe://${td255}a`)).toBe('invalid trust domain');
    const room = 2048 - 'spiffe://a.test/'.length;
    expect(spiffeIdError(`spiffe://a.test/${'p'.repeat(room)}`)).toBeNull();
    expect(spiffeIdError(`spiffe://a.test/${'p'.repeat(room + 1)}`)).toBe('SPIFFE ID is too long');
    expect(spiffeIdError(5)).toBe('SPIFFE ID must be a non-empty string');
    // length is in bytes, not code units
    expect(spiffeIdError(`spiffe://a.test/${'é'.repeat(1024)}`)).toBe('SPIFFE ID is too long');
  });
});

describe('needsDischargeError', () => {
  it('exact messages', () => {
    expect(needsDischargeError(nd())).toBeNull();
    expect(needsDischargeError(5)).toBe('caveat must be an object');
    expect(needsDischargeError(nd({ type: 'x' }))).toBe('not a needs_discharge caveat');
    expect(needsDischargeError(nd({ id: 'A' }))).toBe('id is malformed');
    expect(needsDischargeError(nd({ issuer: '' }))).toBe('issuer label is malformed');
    expect(needsDischargeError(nd({ issuer_class: 'x' }))).toBe('issuer_class must be human, org, workload, model or artifact');
    expect(needsDischargeError(nd({ bind: 'x' }))).toBe("bind must be 'chain_hop' or 'action'");
    expect(needsDischargeError(nd({ ttl_ms: 0 }))).toBe('ttl_ms must be 1..86400000');
    expect(needsDischargeError(nd({ ttl_ms: 86_400_001 }))).toBe('ttl_ms must be 1..86400000');
    expect(needsDischargeError(nd({ ttl_ms: 1 }))).toBeNull();
    expect(needsDischargeError(nd({ ttl_ms: 86_400_000 }))).toBeNull();
    expect(needsDischargeError(nd({ require: 'x' }))).toBe('require must be an array of at most 16 requirements');
    expect(needsDischargeError(nd({ require: Array.from({ length: 17 }, () => ({ claim: 'a', op: 'eq', value: 1 })) }))).toBe('require must be an array of at most 16 requirements');
    expect(needsDischargeError(nd({ require: Array.from({ length: 16 }, () => ({ claim: 'a', op: 'eq', value: 1 })) }))).toBeNull();
    expect(needsDischargeError(nd({ issuer_spiffe: 'x' }))).toBe('issuer_spiffe: SPIFFE ID must begin with spiffe://');
    expect(needsDischargeError(nd({ extra: 1 }))).toBe("unknown member 'needs_discharge.extra'");
    const { ttl_ms: _t, ...noTtl } = nd();
    expect(needsDischargeError(noTtl)).toBe("missing member 'needs_discharge.ttl_ms'");
  });
  it('requirements', () => {
    const rq = (r: unknown) => needsDischargeError(nd({ require: [r] }));
    expect(rq(5)).toBe('requirement must be an object');
    expect(rq({ claim: 'A', op: 'eq', value: 1 })).toBe('claim name is malformed');
    expect(rq({ claim: 'a', op: 'lt', value: 1 })).toBe('op must be eq, neq, gte, lte or in');
    expect(rq({ claim: 'a', op: 'in', value: [] })).toBe("'in' needs 1..16 scalar values");
    expect(rq({ claim: 'a', op: 'in', value: Array.from({ length: 16 }, (_, i) => i) })).toBeNull();
    expect(rq({ claim: 'a', op: 'in', value: Array.from({ length: 17 }, (_, i) => i) })).toBe("'in' needs 1..16 scalar values");
    expect(rq({ claim: 'a', op: 'gte', value: 1.5 })).toBe("'gte' needs a safe integer");
    expect(rq({ claim: 'a', op: 'lte', value: 2 ** 53 })).toBe("'lte' needs a safe integer");
    expect(rq({ claim: 'a', op: 'lte', value: 2 ** 53 - 1 })).toBeNull();
    expect(rq({ claim: 'a', op: 'eq', value: null })).toBe('value must be a scalar');
    expect(rq({ claim: 'a', op: 'eq', value: 'x'.repeat(256) })).toBeNull();
    expect(rq({ claim: 'a', op: 'eq', value: 'x'.repeat(257) })).toBe('value must be a scalar');
    expect(rq({ claim: 'a', op: 'eq', value: '' })).toBe('value must be a scalar');
    expect(rq({ claim: 'a', op: 'eq', value: 'é'.repeat(129) })).toBe('value must be a scalar');
    expect(rq({ claim: 'a', op: 'eq', value: true })).toBeNull();
    expect(rq({ claim: 'a', op: 'eq', value: -0 })).toBe('value must be a scalar');
  });
});

describe('dischargeShapeError', () => {
  const d = dis();
  it('exact messages', () => {
    expect(dischargeShapeError(d)).toBeNull();
    expect(dischargeShapeError(null)).toBe('not an object');
    expect(dischargeShapeError({ ...d, v: 2 })).toBe('not a pca-discharge v1');
    expect(dischargeShapeError({ ...d, kind: 'x' })).toBe('not a pca-discharge v1');
    expect(dischargeShapeError({ ...d, caveat_id: 'A' })).toBe('caveat_id is malformed');
    expect(dischargeShapeError({ ...d, issuer: 'A' })).toBe('issuer label is malformed');
    expect(dischargeShapeError({ ...d, cap_hash: 'short' })).toBe('cap_hash must be canonical base64url (32 bytes)');
    expect(dischargeShapeError({ ...d, bind: 'x' })).toBe("bind must be 'chain_hop' or 'action'");
    expect(dischargeShapeError({ ...d, action_digest: cap })).toBe('action_digest is required for bind action and forbidden for chain_hop');
    expect(dischargeShapeError({ ...d, bind: 'action' })).toBe('action_digest is required for bind action and forbidden for chain_hop');
    expect(dischargeShapeError({ ...d, claims: [] })).toBe('claims must be an object of at most 16 members');
    const many = Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`c${i}`, 1]));
    expect(dischargeShapeError({ ...d, claims: many })).toBe('claims must be an object of at most 16 members');
    expect(dischargeShapeError({ ...d, claims: { ...Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`c${i}`, 1])) } })).toBeNull();
    expect(dischargeShapeError({ ...d, iat: -1 })).toBe('iat and not_after must be non-negative safe integers');
    expect(dischargeShapeError({ ...d, not_after: 1.5 })).toBe('iat and not_after must be non-negative safe integers');
    expect(dischargeShapeError({ ...d, not_after: d.iat })).toBe('not_after must be greater than iat');
    expect(dischargeShapeError({ ...d, not_after: d.iat + 86_400_001 })).toBe('a discharge lives at most 86400000 ms');
    expect(dischargeShapeError({ ...d, not_after: d.iat + 86_400_000 })).toBeNull();
    expect(dischargeShapeError({ ...d, nonce: b64u(new Uint8Array(15)) })).toBe('nonce must be canonical base64url of at least 16 bytes');
    expect(dischargeShapeError({ ...d, nonce: b64u(new Uint8Array(16)) })).toBeNull();
    expect(dischargeShapeError({ ...d, sig: 5 })).toBe('sig must be a string');
  });
});

describe('verifyDischarge boundaries and order', () => {
  const c = nd();
  const ok = dis();
  it('window edges are inclusive, one outside is refused with the exact reason', () => {
    expect(verifyDischarge(ok, c, { ...B, now: NOW }).ok).toBe(true);
    expect(verifyDischarge(ok, c, { ...B, now: NOW + 1000 }).ok).toBe(true);
    expect(verifyDischarge(ok, c, { ...B, now: NOW - 1 })).toEqual({ ok: false, reason: 'the discharge is from the future' });
    expect(verifyDischarge(ok, c, { ...B, now: NOW + 1001 })).toEqual({ ok: false, reason: 'the discharge has expired' });
    expect(verifyDischarge(ok, c, { ...B, now: NaN })).toEqual({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' });
    expect(verifyDischarge(ok, c, { ...B, now: 2 ** 53 })).toEqual({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' });
  });
  it('ttl_ms is an inclusive bound', () => {
    expect(verifyDischarge(ok, nd({ ttl_ms: 1000 }), B).ok).toBe(true);
    expect(verifyDischarge(ok, nd({ ttl_ms: 999 }), B)).toEqual({ ok: false, reason: 'the discharge lives longer than the caveat allows' });
  });
  it('exact refusal reasons, in order', () => {
    expect(verifyDischarge(ok, 5, B)).toEqual({ ok: false, reason: 'malformed needs_discharge caveat: caveat must be an object' });
    expect(verifyDischarge(5, c, B)).toEqual({ ok: false, reason: 'malformed discharge: not an object' });
    expect(verifyDischarge(dis({ caveat_id: 'other' }), c, B)).toEqual({ ok: false, reason: 'the discharge is for another caveat' });
    expect(verifyDischarge(ok, nd({ issuer: 'other' }), B)).toEqual({ ok: false, reason: 'the discharge names another issuer' });
    expect(verifyDischarge(ok, c, { ...B, pins: 5 as never })).toEqual({ ok: false, reason: 'no issuer is pinned' });
    expect(verifyDischarge(ok, c, { ...B, pins: [] })).toEqual({ ok: false, reason: 'the issuer is not pinned by this verifier' });
    expect(verifyDischarge(ok, c, { ...B, pins: [PIN, PIN] })).toEqual({ ok: false, reason: 'the issuer label is pinned more than once (ambiguous)' });
    expect(verifyDischarge(ok, nd({ issuer_class: 'org' }), B)).toEqual({ ok: false, reason: 'the pinned issuer is not of the class the caveat requires' });
    expect(verifyDischarge(ok, nd({ issuer_spiffe: 'spiffe://a.test/x' }), B)).toEqual({ ok: false, reason: 'the pinned issuer does not carry the SPIFFE ID the caveat requires' });
    expect(verifyDischarge(ok, c, { ...B, pins: [{ ...PIN, pk: kp().pub }] })).toEqual({ ok: false, reason: 'discharge signature invalid' });
    expect(verifyDischarge(ok, nd({ bind: 'action' }), B)).toEqual({ ok: false, reason: 'the discharge binds differently than the caveat requires' });
    expect(verifyDischarge(ok, c, { ...B, cap_hash: b64u(new Uint8Array(32)) })).toEqual({ ok: false, reason: 'the discharge is bound to another hop' });
    expect(verifyDischarge(ok, c, { ...B, revoked: [dischargeDigest(ok)] })).toEqual({ ok: false, reason: 'the discharge is revoked' });
  });
  it('claim operators, exactly', () => {
    const rq = (claim: string, op: string, value: unknown, claims: Record<string, unknown>) => verifyDischarge(dis({ claims }), nd({ require: [{ claim, op, value }] }), B).ok;
    expect(rq('a', 'gte', 5, { a: 5 })).toBe(true);
    expect(rq('a', 'gte', 5, { a: 4 })).toBe(false);
    expect(rq('a', 'lte', 5, { a: 5 })).toBe(true);
    expect(rq('a', 'lte', 5, { a: 6 })).toBe(false);
    expect(rq('a', 'gte', 5, { a: '9' })).toBe(false);
    expect(rq('a', 'eq', 5, { a: 5 })).toBe(true);
    expect(rq('a', 'eq', 5, { a: '5' })).toBe(false);
    expect(rq('a', 'neq', 5, { a: '5' })).toBe(true);
    expect(rq('a', 'neq', 5, { a: 5 })).toBe(false);
    expect(rq('a', 'neq', 5, {})).toBe(false); // an absent claim fails even neq
    expect(rq('a', 'in', [1, 2], { a: 2 })).toBe(true);
    expect(rq('a', 'in', [1, 2], { a: 3 })).toBe(false);
    expect(rq('a', 'in', [true], { a: 1 })).toBe(false);
    expect(rq('toString', 'eq', 1, {})).toBe(false); // own properties only
  });
  it('the digest and revocation name signed bytes', () => {
    expect(dischargeDigest(ok)).toHaveLength(43);
    expect(dischargeDigest(ok)).not.toBe(dischargeDigest({ ...ok, sig: ok.sig.replace(/^./, 'A') }));
  });
  it('dischargeRequests skips malformed and non-K1 caveats and carries the action digest only for bind action', () => {
    const r = rootOf([nd({ id: 'a' }), nd({ id: 'b', bind: 'action' }), { type: 'expires', at: 1 }, { ...nd({ id: 'c' }), extra: 1 }]);
    const out = dischargeRequests(r, [r], 'DIG');
    expect(out.map((x) => [x.caveat_id, x.bind, x.action_digest])).toEqual([['a', 'chain_hop', undefined], ['b', 'action', 'DIG']]);
    expect(dischargeRequests(r, [r], undefined)[1]!.action_digest).toBeUndefined();
  });
});

describe('narrow', () => {
  const nb = (o: Record<string, unknown> = {}) => ({ v: 1, kind: 'pca-narrow', cap_hash: cap, holder: agent.pub, caveats: [{ type: 'expires', at: NOW + 5 }], iat: NOW, not_after: NOW + 10, nonce, ...o });
  it('shape messages and limits', () => {
    const n = signNarrow(nb() as never, agent.sk);
    expect(narrowShapeError(n)).toBeNull();
    expect(narrowShapeError(null)).toBe('not an object');
    expect(narrowShapeError({ ...n, v: 2 })).toBe('not a pca-narrow v1');
    expect(narrowShapeError({ ...n, cap_hash: 'x' })).toBe('cap_hash must be canonical base64url (32 bytes)');
    expect(narrowShapeError({ ...n, holder: 'x' })).toBe('holder must be canonical base64url (32 bytes)');
    expect(narrowShapeError({ ...n, caveats: [] })).toBe('caveats must be 1..16 caveats');
    expect(narrowShapeError({ ...n, caveats: [5] })).toBe('every caveat must be an object with a string type');
    expect(narrowShapeError({ ...n, caveats: [{ type: 'sealed' }] })).toBe("a narrow block cannot carry a 'sealed' caveat");
    expect(narrowShapeError({ ...n, caveats: Array.from({ length: 16 }, () => ({ type: 'expires', at: 1 })) })).toBeNull();
    expect(narrowShapeError({ ...n, action_digest: 'x' })).toBe('action_digest must be canonical base64url (32 bytes)');
    expect(narrowShapeError({ ...n, iat: -1 })).toBe('iat and not_after must be non-negative safe integers');
    expect(narrowShapeError({ ...n, not_after: n.iat })).toBe('not_after must be greater than iat');
    expect(narrowShapeError({ ...n, not_after: n.iat + 86_400_001 })).toBe('a narrow block lives at most 86400000 ms');
    expect(narrowShapeError({ ...n, not_after: n.iat + 86_400_000 })).toBeNull();
    expect(narrowShapeError({ ...n, nonce: b64u(new Uint8Array(15)) })).toBe('nonce must be canonical base64url of at least 16 bytes');
  });
  it('window edges and action binding', () => {
    const n = signNarrow(nb({ action_digest: cap }) as never, agent.sk);
    expect(verifyNarrow(n, g, [g], { now: NOW, action_digest: cap }).ok).toBe(true);
    expect(verifyNarrow(n, g, [g], { now: NOW + 10, action_digest: cap }).ok).toBe(true);
    expect(verifyNarrow(n, g, [g], { now: NOW - 1, action_digest: cap })).toEqual({ ok: false, reason: 'the narrow block is from the future' });
    expect(verifyNarrow(n, g, [g], { now: NOW + 11, action_digest: cap })).toEqual({ ok: false, reason: 'the narrow block has expired' });
    expect(verifyNarrow(n, g, [g], { now: NOW })).toEqual({ ok: false, reason: 'the narrow block is bound to another action' });
    expect(verifyNarrow(n, g, [g], { now: 0.5 })).toEqual({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' });
    expect(verifyNarrow(signNarrow(nb() as never, agent.sk), g, [g], { now: NOW, action_digest: cap }).ok).toBe(true); // an unbound block ignores the action
  });
});

describe('max_uses', () => {
  const mu = (o: Record<string, unknown> = {}) => ({ type: 'max_uses', id: 'u', n: 2, until: NOW + 10, ...o });
  it('shape', () => {
    expect(maxUsesError(mu())).toBeNull();
    expect(maxUsesError(5)).toBe('caveat must be an object');
    expect(maxUsesError(mu({ type: 'x' }))).toBe('not a max_uses caveat');
    expect(maxUsesError(mu({ id: 'A' }))).toBe('id is malformed');
    expect(maxUsesError(mu({ n: 0 }))).toBe('n must be 1..256');
    expect(maxUsesError(mu({ n: 257 }))).toBe('n must be 1..256');
    expect(maxUsesError(mu({ n: 1 }))).toBeNull();
    expect(maxUsesError(mu({ n: 256 }))).toBeNull();
    expect(maxUsesError(mu({ until: -1 }))).toBe('until must be a non-negative safe integer');
    expect(maxUsesError(mu({ until: 0 }))).toBeNull();
  });
  it('slot keys are 43-char digests that differ per part', () => {
    const k = maxUsesSlotKey(cap, 'u', 0);
    expect(k).toHaveLength(43);
    expect(new Set([k, maxUsesSlotKey(cap, 'u', 1), maxUsesSlotKey(cap, 'v', 0), maxUsesSlotKey(b64u(new Uint8Array(32)), 'u', 0)]).size).toBe(4);
    // the NUL separator keeps ("ab","c") and ("a","bc") apart
    expect(maxUsesSlotKey(cap, 'ab', 1)).not.toBe(maxUsesSlotKey(cap, 'a', 11));
  });
  it('spends in order, reports the count, and tells the store the horizon', async () => {
    const seen: [string, number, number][] = [];
    const store = { consumeOnce: (k: string, u: number, n: number) => (seen.push([k, u, n]), Promise.resolve(seen.length > 1)) };
    const r = await reserveMaxUses(store, [{ caveat: mu(), hop: 0, cap_hash: cap }], NOW);
    expect(r).toEqual({ ok: true, spent: 1 });
    expect(seen).toEqual([[maxUsesSlotKey(cap, 'u', 0), NOW + 10, NOW], [maxUsesSlotKey(cap, 'u', 1), NOW + 10, NOW]]);
  });
  it('refusal reasons', async () => {
    const st = new InMemoryReplayStore();
    const one = (c: unknown) => reserveMaxUses(st, [{ caveat: c as never, hop: 0, cap_hash: cap }], NOW);
    expect(await one(mu({ n: 0 }))).toEqual({ ok: false, reason: 'malformed max_uses caveat: n must be 1..256' });
    expect(await one(mu({ until: NOW }))).toEqual({ ok: false, reason: "max_uses 'u' has expired" });
    expect(await one(mu({ until: NOW + 1 }))).toEqual({ ok: true, spent: 1 });
    expect(await reserveMaxUses(st, [], NaN)).toEqual({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' });
    expect(await reserveMaxUses(st, [{ caveat: { type: 'expires' }, hop: 0, cap_hash: cap }], NOW)).toEqual({ ok: true, spent: 0 });
  });
});

describe('derive', () => {
  const d = (o: Record<string, unknown> = {}) => ({ type: 'derive', id: 'd', defs: [], check: { const: true }, ...o });
  const run = (c: unknown, over: Record<string, unknown> = {}) => evaluateDerive(c as DeriveCaveat, { now: NOW, claims: {}, ...over } as never);
  it('shape messages', () => {
    expect(deriveError(d())).toBeNull();
    expect(deriveError(5)).toBe('caveat must be an object');
    expect(deriveError(d({ type: 'x' }))).toBe('not a derive caveat');
    expect(deriveError(d({ id: 'A' }))).toBe('id is malformed');
    expect(deriveError(d({ defs: 5 }))).toBe('defs must be an array of at most 8');
    expect(deriveError(d({ defs: [5] }))).toBe('def name is malformed');
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'param', path: 'x' }, { name: 'a', kind: 'param', path: 'x' }] }))).toBe("def 'a' is defined twice");
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'sql' }] }))).toBe("def 'a': unknown def kind");
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'count', window_ms: 0 }] }))).toBe("def 'a': window_ms out of range");
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'count', window_ms: 1, verb: '' }] }))).toBe("def 'a': verb must be a non-empty string");
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'count', window_ms: 1, resource_prefix: '' }] }))).toBe("def 'a': resource_prefix must be a non-empty string");
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'count', window_ms: 1, verb: 'v', resource_prefix: 'r' }] }))).toBeNull();
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'param', path: 'a..b' }] }))).toBe("def 'a': param path is malformed");
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'action', field: 'x' }] }))).toBe("def 'a': field must be 'verb' or 'resource'");
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'claim', caveat_id: 'A', claim: 'x' }] }))).toBe("def 'a': claim reference is malformed");
    expect(deriveError(d({ check: { ref: 'nope' } }))).toBe('ref names no earlier def');
    expect(deriveError(d({ check: { const: {} } }))).toBe('const must be a scalar');
    expect(deriveError(d({ check: { op: 'xor' } }))).toBe('unknown expression');
    expect(deriveError(d({ check: { op: 'and', args: [] } }))).toBe('and needs 1..8 arguments');
    expect(deriveError(d({ check: { op: 'or', args: Array.from({ length: 9 }, () => ({ const: true })) } }))).toBe('or needs 1..8 arguments');
  });
  it('limits are exact', () => {
    const nest = (n: number): unknown => (n <= 1 ? { const: true } : { op: 'not', arg: nest(n - 1) });
    expect(deriveError(d({ check: nest(4) }))).toBeNull();
    expect(deriveError(d({ check: nest(5) }))).toBe('expression nests deeper than 4');
    const wide = (n: number) => ({ op: 'and', args: Array.from({ length: n }, () => ({ const: true })) });
    expect(deriveError(d({ check: { op: 'and', args: [wide(7), wide(7), wide(7), wide(6)] } }))).toBeNull(); // 32 nodes
    expect(deriveError(d({ check: { op: 'and', args: [wide(7), wide(7), wide(7), wide(7)] } }))).toBe('more than 32 expression nodes');
    const defs = (n: number) => Array.from({ length: n }, (_, i) => ({ name: `p${i}`, kind: 'param', path: 'a' }));
    expect(deriveError(d({ defs: defs(8) }))).toBeNull();
    expect(deriveError(d({ defs: defs(9) }))).toBe('defs must be an array of at most 8');
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'count', window_ms: 2_592_000_000 }] }))).toBeNull();
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'count', window_ms: 2_592_000_001 }] }))).toBe("def 'a': window_ms out of range");
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'param', path: 'a.b.c.d' }] }))).toBeNull();
    expect(deriveError(d({ defs: [{ name: 'a', kind: 'param', path: 'a.b.c.d.e' }] }))).toBe("def 'a': param path is malformed");
  });
  it('count: verb, prefix and window edges', () => {
    const c = d({ defs: [{ name: 'n', kind: 'count', verb: 'refund', resource_prefix: 'o/', window_ms: 100 }], check: { op: 'eq', a: { ref: 'n' }, b: { const: 2 } } });
    const ev = (t: number, verb = 'refund', resource = 'o/1') => ({ t, verb, resource });
    expect(run(c, { history: [ev(NOW), ev(NOW - 99)] })).toBe(true);
    expect(run(c, { history: [ev(NOW), ev(NOW - 100)] })).toBe(false); // the window is (now - 100, now]
    expect(run(c, { history: [ev(NOW), ev(NOW + 1)] })).toBe(false);
    expect(run(c, { history: [ev(NOW), ev(NOW - 1, 'read')] })).toBe(false);
    expect(run(c, { history: [ev(NOW), ev(NOW - 1, 'refund', 'x/1')] })).toBe(false);
    expect(run(c, { history: [ev(NOW), { t: 1.5, verb: 'refund', resource: 'o/1' }] })).toBeNull();
    expect(run(c, {})).toBeNull();
    const big = (n: number) => Array.from({ length: n }, () => ev(NOW - 1));
    expect(run(d({ defs: [{ name: 'n', kind: 'count', window_ms: 100 }], check: { op: 'eq', a: { ref: 'n' }, b: { const: 10_000 } } }), { history: big(10_000) })).toBe(true);
    expect(run(d({ defs: [{ name: 'n', kind: 'count', window_ms: 100 }], check: { op: 'eq', a: { ref: 'n' }, b: { const: 10_000 } } }), { history: big(10_001) })).toBeNull();
  });
  it('facts: param, action, claim', () => {
    const pc = d({ defs: [{ name: 'a', kind: 'param', path: 'x.y' }], check: { op: 'eq', a: { ref: 'a' }, b: { const: 7 } } });
    expect(run(pc, { action: { params: { x: { y: 7 } } } })).toBe(true);
    expect(run(pc, { action: { params: { x: { y: '7' } } } })).toBe(false);
    expect(run(pc, { action: { params: { x: {} } } })).toBeNull();
    expect(run(pc, { action: { params: { x: { y: { z: 1 } } } } })).toBeNull();
    expect(run(pc, {})).toBeNull();
    const ac = d({ defs: [{ name: 'r', kind: 'action', field: 'resource' }], check: { op: 'eq', a: { ref: 'r' }, b: { const: 'o/1' } } });
    expect(run(ac, { action: { resource: 'o/1' } })).toBe(true);
    expect(run(ac, { action: { resource: 5 } })).toBeNull();
    const cc = d({ defs: [{ name: 'k', kind: 'claim', caveat_id: 'kyc', claim: 'lvl' }], check: { op: 'gte', a: { ref: 'k' }, b: { const: 2 } } });
    expect(run(cc, { claims: { kyc: { lvl: 2 } } })).toBe(true);
    expect(run(cc, { claims: { kyc: { lvl: 1 } } })).toBe(false);
    expect(run(cc, { claims: { kyc: {} } })).toBeNull();
    expect(run(cc, { claims: {} })).toBeNull();
  });
  it('operators and Kleene tables', () => {
    const T = { op: 'eq', a: { const: 1 }, b: { const: 1 } }, F = { op: 'eq', a: { const: 1 }, b: { const: 2 } };
    const U = { op: 'eq', a: { ref: 'm' }, b: { const: 1 } };
    const k = (check: unknown) => run(d({ defs: [{ name: 'm', kind: 'param', path: 'm' }], check }));
    const and = (...args: unknown[]) => k({ op: 'and', args });
    const or = (...args: unknown[]) => k({ op: 'or', args });
    expect([and(T, T), and(T, F), and(F, U), and(U, F), and(T, U), and(U, U), and(T)]).toEqual([true, false, false, false, null, null, true]);
    expect([or(F, F), or(T, F), or(T, U), or(U, T), or(F, U), or(U, U), or(F)]).toEqual([false, true, true, true, null, null, false]);
    expect([k({ op: 'not', arg: T }), k({ op: 'not', arg: F }), k({ op: 'not', arg: U })]).toEqual([false, true, null]);
    const cmp = (op: string, a: unknown, b: unknown) => k({ op, a: { const: a }, b: { const: b } });
    expect([cmp('lt', 1, 2), cmp('lt', 2, 2), cmp('lte', 2, 2), cmp('lte', 3, 2), cmp('gt', 3, 2), cmp('gt', 2, 2), cmp('gte', 2, 2), cmp('gte', 1, 2)]).toEqual([true, false, true, false, true, false, true, false]);
    expect([cmp('lt', 'a', 'b'), cmp('lt', true, 1), cmp('eq', 'a', 'a'), cmp('eq', 1, true), cmp('neq', 1, true), cmp('neq', 'a', 'a')]).toEqual([null, null, true, false, true, false]);
    expect(k({ const: 1 })).toBeNull();
    expect(k({ const: false })).toBe(false);
  });
});

describe('spiffe_bound', () => {
  it('shape', () => {
    expect(spiffeBoundError({ type: 'spiffe_bound', spiffe_id: 'spiffe://a.test/x' })).toBeNull();
    expect(spiffeBoundError(5)).toBe('caveat must be an object');
    expect(spiffeBoundError({ type: 'x', spiffe_id: 'spiffe://a.test/x' })).toBe('not a spiffe_bound caveat');
    expect(spiffeBoundError({ type: 'spiffe_bound' })).toBe('exactly one of spiffe_id and spiffe_prefix');
    expect(spiffeBoundError({ type: 'spiffe_bound', spiffe_id: 'spiffe://a.test/x', spiffe_prefix: 'spiffe://a.test' })).toBe('exactly one of spiffe_id and spiffe_prefix');
    expect(spiffeBoundError({ type: 'spiffe_bound', spiffe_id: 'x' })).toBe('SPIFFE ID must begin with spiffe://');
  });
});

describe('evaluateK1 exact results', () => {
  const run = (caveats: Caveat[], k1: unknown, ctx: Record<string, unknown> = { now: NOW }) => {
    const r = rootOf(caveats);
    return evaluateK1(r, [r], k1 as never, ctx as never);
  };
  it('unconfigured and malformed inputs', () => {
    for (const k1 of [undefined, null, 5, 'x', []]) {
      const r = run([{ type: 'sealed' }, { type: 'expires', at: NOW + 1 }], k1);
      expect(r).toMatchObject({ ok: false, failed: ['sealed'], reasons: ['the caveat language is not configured (no k1 input)'] });
      expect(r.bound).toHaveLength(1);
    }
    expect(run([{ type: 'expires', at: 1 }], undefined).ok).toBe(true); // nothing to refuse
    expect(run([{ type: 'sealed' }], {}).ok).toBe(true);
  });
  it('a bad clock or chain is one refusal', () => {
    expect(run([{ type: 'sealed' }], {}, { now: 1.5 })).toMatchObject({ ok: false, failed: ['<malformed>'], reasons: ['the verifier clock is not a safe integer (fail closed)'] });
    expect(evaluateK1({ caveats: 5 } as never, [{ caveats: 5 } as never], {}, { now: NOW })).toMatchObject({ ok: false, reasons: ['malformed capability chain'] });
  });
  it('failures are reported by caveat type, discharges first', () => {
    const r = run([{ type: 'sealed' }, { type: 'max_uses', id: 'u', n: 0, until: NOW + 1 }, nd()], {});
    expect(r.failed).toEqual(['needs_discharge', 'max_uses']);
    expect(r.reasons).toEqual(['no discharge presented', 'n must be 1..256']);
  });
  it('a malformed caveat without a string type is reported as <malformed>', () => {
    const r = mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats: [{ type: 'derive' } as never] });
    expect(evaluateK1(r, [r], {}, { now: NOW }).failed).toEqual(['derive']);
  });
  it('a narrow block that fails stops evaluation with one narrow failure; its K1 caveats are evaluated and its plain ones returned', () => {
    const bad = run([nd()], { narrow: 5 });
    expect(bad).toMatchObject({ ok: false, failed: ['narrow'] });
    const r = rootOf([]);
    const n = signNarrow({ v: 1, kind: 'pca-narrow', cap_hash: capHash(r), holder: agent.pub, caveats: [{ type: 'expires', at: NOW + 5 }, { type: 'spiffe_bound', spiffe_id: 'spiffe://a.test/x' }], iat: NOW, not_after: NOW + 10, nonce } as never, agent.sk);
    const ok = evaluateK1(r, [r], { narrow: n, spiffe_id: 'spiffe://a.test/x' }, { now: NOW });
    expect(ok.ok).toBe(true);
    expect(ok.plain).toEqual([{ type: 'expires', at: NOW + 5 }]);
    expect(evaluateK1(r, [r], { narrow: n }, { now: NOW }).failed).toEqual(['spiffe_bound']);
  });
  it('duplicate ids fail every caveat that shares one, per type', () => {
    const r = rootOf([{ type: 'derive', id: 'x', defs: [], check: { const: true } }, { type: 'derive', id: 'x', defs: [], check: { const: true } }, { type: 'max_uses', id: 'x', n: 1, until: NOW + 1 }]);
    expect(evaluateK1(r, [r], {}, { now: NOW }).failed).toEqual(['derive', 'derive']);
  });
  it('sealed on a hop in the middle is judged by hop position', () => {
    const c1 = delegate(g, agent.pub, [{ type: 'sealed' }], agent.sk);
    const c2 = delegate(c1, agent.pub, [], agent.sk);
    expect(evaluateK1(g, [g, c1], {}, { now: NOW }).ok).toBe(true);
    expect(evaluateK1(g, [g, c1, c2], {}, { now: NOW }).reasons).toEqual(['a hop was appended below a sealed hop']);
    expect(boundCaveats(g, [g, c1, c2])!.map((b) => b.hop)).toEqual([1]);
  });
});
