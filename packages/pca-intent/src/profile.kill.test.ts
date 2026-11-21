import { describe, expect, it } from 'vitest';
import { RevocationSet, b64u, mlDsa65Keygen, publicKeyOf, sha256, signRevocationEpoch, utf8, type Predicate } from '@atlasauth/pca';
import { profileRevocationId, profileRevocationScope } from '@atlasauth/pca/ext/intent';
import {
  intentProfileDigest,
  intentProfileShapeError,
  numRep,
  profileApplies,
  profileCeiling,
  profileUsable,
  profileVetoCells,
  signIntentProfile,
  standingAdmits,
  standingPermits,
  verifyIntentProfile,
  verifyProfileSuccession,
  type IntentProfileBody,
  type NumDim,
  type Omega,
  type VerbSpace,
} from './index';

const seed = (l: string) => sha256(utf8(`profile-kill-test/${l}`));
const owner = seed('owner');
const NOW = 1_800_000_000_000;
const D32 = b64u(new Uint8Array(32));
const body = (over: Partial<IntentProfileBody> = {}): Omit<IntentProfileBody, 'owner'> => ({
  v: 1, kind: 'pca-intent-profile', profile_id: 'prof_a', version: 1,
  scope: { sites: ['a.example'] },
  standing: { deny: [], permit: [] },
  prior: { observations: [], maps: [] },
  expires_at: NOW + 1000,
  revocation: { epoch_uri: 'https://rev.example/e' },
  ...over,
});
const base = signIntentProfile(body(), owner);
const shape = (over: Record<string, unknown>, opts?: { signed?: boolean }) => intentProfileShapeError({ ...base, ...over }, opts);
const obs = (over: Record<string, unknown> = {}) => ({ verb: 'v', values: {}, y: 0, at: 0, ...over });
const prior = (observations: unknown[], maps: unknown[] = []) => ({ observations, maps });

describe('intentProfileShapeError: exact refusals', () => {
  it('accepts the signed base and an unsigned body', () => {
    expect(intentProfileShapeError(base)).toBeNull();
    const { sig: _sig, ...unsigned } = base;
    expect(intentProfileShapeError(unsigned, { signed: false })).toBeNull();
    expect(intentProfileShapeError(unsigned)).toBe('sig must be a string');
    expect(intentProfileShapeError({ ...unsigned, alg: 'bogus' }, { signed: false })).toBeNull();
  });

  it('refuses anything that is not a plain object', () => {
    const arrWithObjectProto = Object.setPrototypeOf([], Object.prototype);
    const fnWithObjectProto = Object.setPrototypeOf(() => 1, Object.prototype);
    class K {}
    for (const v of [null, undefined, 5, 'x', [], new K(), arrWithObjectProto, fnWithObjectProto]) {
      expect(intentProfileShapeError(v)).toBe('profile is not an object');
    }
    const bare = Object.assign(Object.create(null) as Record<string, unknown>, base);
    expect(intentProfileShapeError(bare)).toBeNull();
  });

  it('a throwing prototype lookup is reported as a malformed profile', () => {
    const p = new Proxy({}, { getPrototypeOf() { throw new Error('trap'); } });
    expect(intentProfileShapeError(p)).toBe('malformed profile: trap');
  });

  it('a body the strict encoder refuses is a malformed profile', () => {
    expect(shape({ standing: { deny: [{ verb: 'x', n: Number.NaN }], permit: [] } })).toMatch(/^malformed profile: .+/);
  });

  it('unknown members, kind and version', () => {
    expect(shape({ extra: 1 })).toBe("profile: unknown member 'extra'");
    expect(shape({ v: 2 })).toBe('not a pca-intent-profile v1');
    expect(shape({ kind: 'other' })).toBe('not a pca-intent-profile v1');
  });

  it('profile_id is anchored on both ends', () => {
    const m = 'profile_id must match [A-Za-z0-9_.-]{1,128}';
    for (const id of [5, '', 'a b', '!ab', 'ab!', 'a'.repeat(129)]) expect(shape({ profile_id: id })).toBe(m);
    expect(shape({ profile_id: 'a'.repeat(128) })).toBeNull();
    expect(shape({ profile_id: 'A_b.c-1' })).toBeNull();
  });

  it('version is a safe integer >= 1', () => {
    const m = 'version must be a safe integer >= 1';
    for (const v of [0, 1.5, '1', -1, Number.MAX_SAFE_INTEGER + 1]) expect(shape({ version: v, prev: D32 })).toBe(m);
    expect(shape({ version: 2, prev: D32 })).toBeNull();
  });

  it('owner must be canonical base64url of 32 bytes', () => {
    const m = 'owner must be canonical base64url (32 bytes)';
    for (const o of [5, 'AAAA', D32 + 'A', 'a'.repeat(43)]) expect(shape({ owner: o })).toBe(m);
  });

  it('scope members and their lists', () => {
    expect(shape({ scope: 'x' })).toBe('scope must be {sites?, verbs?, semantic_types?}');
    expect(shape({ scope: [] })).toBe('scope must be {sites?, verbs?, semantic_types?}');
    expect(shape({ scope: { foo: ['a'] } })).toBe('scope must be {sites?, verbs?, semantic_types?}');
    expect(shape({ scope: {} })).toBeNull();
    expect(shape({ scope: { sites: ['a'], verbs: ['b'], semantic_types: ['c'] } })).toBeNull();
    for (const k of ['sites', 'verbs', 'semantic_types']) {
      const m = `scope.${k} must be a list of strings`;
      expect(shape({ scope: { [k]: 'x' } })).toBe(m);
      expect(shape({ scope: { [k]: [5] } })).toBe(m);
      expect(shape({ scope: { [k]: [''] } })).toBe(m);
      expect(shape({ scope: { [k]: ['a', 7] } })).toBe(m);
      // a non-empty list is not a non-empty string
      expect(shape({ scope: { [k]: [['a']] } })).toBe(m);
      expect(shape({ scope: { [k]: Array.from({ length: 257 }, (_, i) => `s${i}`) } })).toBe(m);
      expect(shape({ scope: { [k]: Array.from({ length: 256 }, (_, i) => `s${i}`) } })).toBeNull();
    }
  });

  it('standing has exactly deny and permit, in any key order', () => {
    const m = 'standing must be {deny, permit}';
    expect(shape({ standing: 'x' })).toBe(m);
    expect(shape({ standing: { deny: [] } })).toBe(m);
    expect(shape({ standing: { deny: [], permit: [], more: [] } })).toBe(m);
    expect(shape({ standing: { permit: [], deny: [] } })).toBeNull();
  });

  it('standing rule lists: type, bound and predicate shape', () => {
    for (const k of ['deny', 'permit']) {
      const m = `standing.${k} must be at most 256 predicates`;
      const other = k === 'deny' ? 'permit' : 'deny';
      const mk = (rules: unknown) => ({ [k]: rules, [other]: [] });
      expect(shape({ standing: mk('x') })).toBe(m);
      expect(shape({ standing: mk(Array.from({ length: 257 }, () => ({ verb: 'x' }))) })).toBe(m);
      expect(shape({ standing: mk(Array.from({ length: 256 }, () => ({ verb: 'x' }))) })).toBeNull();
      expect(shape({ standing: mk([{ verb: 'x' }, 5]) })).toBe(m);
      expect(shape({ standing: mk([{ verb: 'x' }, {}]) })).toBe(m);
      expect(shape({ standing: mk([{ verb: 5 }]) })).toBe(m);
      expect(shape({ standing: mk([{ verb: {} }]) })).toBe(m);
      expect(shape({ standing: mk([{ verb: ['a', 5] }]) })).toBe(m);
      expect(shape({ standing: mk([{ verb: ['a', 'b'] }]) })).toBeNull();
      expect(shape({ standing: mk([{ verb: [] }]) })).toBeNull();
      expect(shape({ standing: mk([{ verb: 'x' }, { verb: ['a'] }]) })).toBeNull();
    }
  });

  it('prior has exactly observations and maps', () => {
    const m = 'prior must be {observations, maps}';
    expect(shape({ prior: 'x' })).toBe(m);
    expect(shape({ prior: { observations: [] } })).toBe(m);
    expect(shape({ prior: { observations: [], maps: [], z: 1 } })).toBe(m);
    expect(shape({ prior: { maps: [], observations: [] } })).toBeNull();
  });

  it('observation list: type and bound', () => {
    const m = 'prior.observations must be at most 2000';
    expect(shape({ prior: { observations: 'x', maps: [] } })).toBe(m);
    expect(shape({ prior: prior(Array.from({ length: 2001 }, () => obs())) })).toBe(m);
    expect(shape({ prior: prior(Array.from({ length: 2000 }, () => obs())) })).toBeNull();
  });

  it('observation entries: every member is checked on its own', () => {
    const m = 'prior.observations entries are {verb, values, y, at}';
    for (const bad of [null, 5, [], { verb: 'v', values: {}, y: 0 }, { ...obs(), extra: 1 }, obs({ verb: 5 }), obs({ values: [] }), obs({ values: null }), obs({ y: 2 }), obs({ y: '0' }), obs({ at: -1 }), obs({ at: 1.5 }), obs({ at: -0 }), obs({ at: '1' })]) {
      expect(shape({ prior: prior([bad]) })).toBe(m);
    }
    expect(shape({ prior: prior([obs({ y: 1, at: 0 }), obs({ values: { a: 1, b: 'x' }, at: 5 })]) })).toBeNull();
  });

  it('prior.maps are 32-byte digests', () => {
    const m = 'prior.maps must be 32-byte digests';
    expect(shape({ prior: { observations: [], maps: 'x' } })).toBe(m);
    expect(shape({ prior: prior([], [D32, 'AAAA']) })).toBe(m);
    expect(shape({ prior: prior([], [5]) })).toBe(m);
    expect(shape({ prior: prior([], [D32, D32]) })).toBeNull();
  });

  it('expires_at is a non-negative safe integer', () => {
    const m = 'expires_at must be a non-negative safe integer';
    for (const e of [-1, 1.5, '5', -0, undefined, Number.MAX_SAFE_INTEGER + 1]) expect(shape({ expires_at: e })).toBe(m);
    expect(shape({ expires_at: 0 })).toBeNull();
  });

  it('revocation members', () => {
    const m = 'revocation must be {epoch_uri, key?}';
    for (const r of ['x', [], {}, { epoch_uri: '' }, { epoch_uri: 5 }, { epoch_uri: 'u', extra: 1 }, { key: D32 }]) expect(shape({ revocation: r })).toBe(m);
    expect(shape({ revocation: { epoch_uri: 'u' } })).toBeNull();
    expect(shape({ revocation: { epoch_uri: 'u', key: D32 } })).toBeNull();
    const km = 'revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)';
    expect(shape({ revocation: { epoch_uri: 'u', key: 'AAAA' } })).toBe(km);
    expect(shape({ revocation: { epoch_uri: 'u', key: 5 } })).toBe(km);
  });

  it('prev is required exactly when version > 1', () => {
    const m = 'prev is required exactly when version > 1';
    expect(shape({ version: 2 })).toBe(m);
    expect(shape({ prev: D32 })).toBe(m);
    expect(shape({ version: 2, prev: 'AAAA' })).toBe('prev must be canonical base64url (32 bytes)');
    expect(shape({ version: 2, prev: 5 })).toBe('prev must be canonical base64url (32 bytes)');
    expect(shape({ version: 2, prev: D32 })).toBeNull();
  });

  it('signature fields: alg, pq members, sig', () => {
    expect(shape({ alg: 5 })).toBe('alg must be a string');
    expect(shape({ alg: 'bogus' })).toBe("alg: unsupported_suite: 'bogus'");
    const pqm = 'an ed25519 profile must not carry pq_pk / pq_sig';
    expect(shape({ pq_pk: 'x' })).toBe(pqm);
    expect(shape({ pq_sig: 'x' })).toBe(pqm);
    expect(shape({ alg: 'ed25519', pq_pk: 'x' })).toBe(pqm);
    expect(shape({ alg: 'ed25519', pq_sig: 'x' })).toBe(pqm);
    expect(shape({ alg: 'ed25519', pq_pk: 'x', pq_sig: 'y' })).toBe(pqm);
    expect(shape({ alg: 'ed25519' })).toBeNull();
    expect(shape({ alg: 'ml-dsa-65', pq_pk: 'x', sig: 's' })).toBeNull();
    expect(shape({ alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: 'x', pq_sig: 'y', sig: 's' })).toBeNull();
    expect(shape({ sig: 5 })).toBe('sig must be a string');
    expect(shape({ sig: undefined })).toBe('sig must be a string');
  });
});

describe('signIntentProfile / verifyIntentProfile: exact outcomes', () => {
  it('owner binding', () => {
    const pub = b64u(publicKeyOf(owner));
    expect(signIntentProfile({ ...body(), owner: pub }, owner).owner).toBe(pub);
    expect(() => signIntentProfile({ ...body(), owner: D32 }, owner)).toThrow('signIntentProfile: owner does not match the signing key');
  });

  it('an invalid body is refused with the shape error', () => {
    expect(() => signIntentProfile(body({ version: 2 }), owner)).toThrow('signIntentProfile: prev is required exactly when version > 1');
    expect(() => signIntentProfile(body({ profile_id: '' }), owner)).toThrow('signIntentProfile: profile_id must match [A-Za-z0-9_.-]{1,128}');
  });

  it('verify returns the shape reason, a signature verdict and a malformed verdict', () => {
    expect(verifyIntentProfile(base)).toEqual({ ok: true });
    expect(verifyIntentProfile({ ...base, version: 0 })).toEqual({ ok: false, reason: 'version must be a safe integer >= 1' });
    expect(verifyIntentProfile({ ...base, expires_at: base.expires_at + 1 })).toEqual({ ok: false, reason: 'profile signature invalid' });
    expect(verifyIntentProfile({ ...base, owner: b64u(publicKeyOf(seed('other'))) })).toEqual({ ok: false, reason: 'profile signature invalid' });
    const throwing = { get pqPins(): never { throw new Error('pin'); } };
    const pq = { ...base, alg: 'ml-dsa-65' as const, pq_pk: 'AAAA' };
    const r = verifyIntentProfile(pq, throwing);
    expect(r).toEqual({ ok: false, reason: expect.stringMatching(/^malformed profile: .+/) });
  });
});

describe('verifyProfileSuccession: exact reasons', () => {
  const v1 = signIntentProfile(body(), owner);
  const v2 = signIntentProfile(body({ version: 2, prev: intentProfileDigest(v1) }), owner);
  it('accepts a proper successor', () => {
    expect(verifyProfileSuccession(v1, v2)).toEqual({ ok: true });
  });
  it('names which side failed verification', () => {
    const bad1 = { ...v1, expires_at: v1.expires_at + 1 };
    const bad2 = { ...v2, expires_at: v2.expires_at + 1 };
    expect(verifyProfileSuccession(bad1, v2)).toEqual({ ok: false, reason: 'previous version: profile signature invalid' });
    expect(verifyProfileSuccession(v1, bad2)).toEqual({ ok: false, reason: 'next version: profile signature invalid' });
  });
  it('id and owner cannot change', () => {
    const m = 'a profile version cannot change its id or owner';
    const otherId = signIntentProfile(body({ profile_id: 'prof_b', version: 2, prev: intentProfileDigest(v1) }), owner);
    const otherOwner = signIntentProfile(body({ version: 2, prev: intentProfileDigest(v1) }), seed('other'));
    expect(verifyProfileSuccession(v1, otherId)).toEqual({ ok: false, reason: m });
    expect(verifyProfileSuccession(v1, otherOwner)).toEqual({ ok: false, reason: m });
  });
  it('version must advance by exactly one', () => {
    const m = 'versions are append-only: next.version must be previous + 1';
    const v3 = signIntentProfile(body({ version: 3, prev: intentProfileDigest(v1) }), owner);
    expect(verifyProfileSuccession(v1, v3)).toEqual({ ok: false, reason: m });
    expect(verifyProfileSuccession(v2, v1)).toEqual({ ok: false, reason: m });
  });
  it('prev must be the digest of the previous version', () => {
    const fork = signIntentProfile(body({ version: 2, prev: D32 }), owner);
    expect(verifyProfileSuccession(v1, fork)).toEqual({ ok: false, reason: 'next.prev is not the digest of the previous version' });
  });
});

describe('profileApplies: scope and expiry', () => {
  const p = (scope: IntentProfileBody['scope'], expires_at = NOW + 10): IntentProfileBody => ({ ...body({ scope, expires_at }), owner: D32 });
  const u = { aud: 'a.example', verb: 'pay', now: NOW };
  it('expiry is exclusive', () => {
    expect(profileApplies(p({}), { ...u, now: NOW + 9 })).toBe(true);
    expect(profileApplies(p({}), { ...u, now: NOW + 10 })).toBe(false);
  });
  it('sites', () => {
    expect(profileApplies(p({ sites: ['a.example'] }), u)).toBe(true);
    expect(profileApplies(p({ sites: ['b.example'] }), u)).toBe(false);
  });
  it('verbs', () => {
    expect(profileApplies(p({ verbs: ['pay'] }), u)).toBe(true);
    expect(profileApplies(p({ verbs: ['pay', 'refund'] }), { ...u, verb: 'refund' })).toBe(true);
    expect(profileApplies(p({ verbs: ['refund'] }), u)).toBe(false);
  });
  it('semantic types need an overlap', () => {
    const s = p({ semantic_types: ['money'] });
    expect(profileApplies(s, u)).toBe(false);
    expect(profileApplies(s, { ...u, semantics: [] })).toBe(false);
    expect(profileApplies(s, { ...u, semantics: ['name'] })).toBe(false);
    expect(profileApplies(s, { ...u, semantics: ['money'] })).toBe(true);
    expect(profileApplies(s, { ...u, semantics: ['name', 'money'] })).toBe(true);
    expect(profileApplies(p({}), u)).toBe(true);
  });
});

describe('standing deny and permit layers', () => {
  const big: Predicate = { verb: 'pay', where: [{ field: 'action.params.amount', op: 'gte', value: 50 }] };
  const small: Predicate = { verb: 'pay', where: [{ field: 'action.params.amount', op: 'lte', value: 10 }] };
  const p = (scope: IntentProfileBody['scope'], standing: { deny: Predicate[]; permit: Predicate[] }): IntentProfileBody => ({ ...body({ scope, standing }), owner: D32 });
  const u = { aud: 'a.example', verb: 'pay', now: NOW };
  const at = (amount: number) => ({ action: { verb: 'pay', resource: 'r', params: { amount } } });

  it('deny: any matching rule excludes; out of scope says nothing', () => {
    const d = p({ sites: ['a.example'] }, { deny: [big, small], permit: [] });
    expect(standingAdmits(d, u, at(5))).toBe(false);
    expect(standingAdmits(d, u, at(60))).toBe(false);
    expect(standingAdmits(d, u, at(20))).toBe(true);
    expect(standingAdmits(d, { ...u, aud: 'b.example' }, at(5))).toBe(true);
  });

  it('permit: any matching rule admits, only in scope', () => {
    const d = p({ sites: ['a.example'] }, { deny: [], permit: [big, small] });
    expect(standingPermits(d, u, at(5))).toBe(true);
    expect(standingPermits(d, u, at(60))).toBe(true);
    expect(standingPermits(d, u, at(20))).toBe(false);
    expect(standingPermits(d, { ...u, aud: 'b.example' }, at(5))).toBe(false);
    expect(standingPermits(d, { ...u, now: NOW + 5000 }, at(5))).toBe(false);
  });

  it('the ceiling builds the action from the outcome, including env and subject', () => {
    const rule: Predicate = {
      verb: 'pay',
      where: [
        { field: 'action.params.amount', op: 'gte', value: 50 },
        { field: 'env.region', op: 'eq', value: 'eu' },
        { field: 'subject.tier', op: 'eq', value: 'gold' },
      ],
    };
    const d = p({ verbs: ['pay'] }, { deny: [rule], permit: [] });
    const vs: VerbSpace = { verb: 'pay', reversibility: 'irreversible', weight: 1, dims: [] };
    const ceil = profileCeiling(d, { aud: 'a.example', now: NOW });
    const v = { 'action.params.amount': 60, 'env.region': 'eu', 'subject.tier': 'gold' };
    expect(ceil(vs, { verb: 'pay', values: v })).toBe(false);
    expect(ceil(vs, { verb: 'pay', values: { ...v, 'action.params.amount': 10 } })).toBe(true);
    expect(ceil(vs, { verb: 'pay', values: { ...v, 'env.region': 'us' } })).toBe(true);
    expect(ceil(vs, { verb: 'pay', values: { ...v, 'subject.tier': 'basic' } })).toBe(true);
    const noEnv = { 'action.params.amount': 60, 'subject.tier': 'gold' };
    expect(ceil(vs, { verb: 'pay', values: noEnv })).toBe(true);
    const noSubject = { 'action.params.amount': 60, 'env.region': 'eu' };
    expect(ceil(vs, { verb: 'pay', values: noSubject })).toBe(true);
    // the outcome's verb is what the profile scope is checked against
    expect(ceil({ ...vs, verb: 'refund' }, { verb: 'refund', values: v })).toBe(true);
  });
});

describe('profileVetoCells', () => {
  const dim = (path: string): NumDim => ({ kind: 'num', path, lo: 0, hi: 100, cuts: [10, 20, 30, 40, 50, 60], dist: 'uniform' });
  const A = dim('action.params.a');
  const B = dim('action.params.b');
  const omega: Omega = {
    v: 1, approximate: [],
    verbs: [
      { verb: 'pay', reversibility: 'irreversible', weight: 1, dims: [A, B] },
      { verb: 'refund', reversibility: 'irreversible', weight: 1, dims: [{ kind: 'num', path: 'action.params.c', lo: 0, hi: 5, cuts: [], dist: 'uniform' }] },
    ],
  };
  const pay = (ia: number, ib: number, y: 0 | 1 = 0) => ({ verb: 'pay', values: { 'action.params.a': numRep(A, ia), 'action.params.b': numRep(B, ib) }, y, at: 0 });
  const withObs = (observations: IntentProfileBody['prior']['observations']): IntentProfileBody => ({ ...body({ prior: { observations, maps: [] } }), owner: D32 });

  it('keeps distinct cells apart, dedupes repeats, skips positives and unmappable observations', () => {
    const p = withObs([
      pay(1, 12),
      pay(11, 2),
      pay(1, 12),
      pay(3, 3, 1),
      { verb: 'nope', values: { 'action.params.a': 1 }, y: 0, at: 0 },
      { verb: 'pay', values: { 'action.params.a': 500, 'action.params.b': 1 }, y: 0, at: 0 },
      { verb: 'refund', values: { 'action.params.c': 3 }, y: 0, at: 0 },
    ]);
    expect(profileVetoCells(p, omega)).toEqual([
      { verb: 'pay', cell: [1, 12] },
      { verb: 'pay', cell: [11, 2] },
      { verb: 'refund', cell: [0] },
    ]);
  });

  it('the same cell under two verbs stays two vetoes', () => {
    const p = withObs([
      { verb: 'pay', values: { 'action.params.a': 1, 'action.params.b': 1 }, y: 0, at: 0 },
      { verb: 'refund', values: { 'action.params.c': 1 }, y: 0, at: 0 },
    ]);
    expect(profileVetoCells(p, omega).map((c) => c.verb)).toEqual(['pay', 'refund']);
  });
});

describe('profileUsable: exact verdicts', () => {
  const sk = seed('usable');
  const prof = signIntentProfile(body({ expires_at: NOW + 100_000 }), sk);
  const epoch = (revoked: string[], issued: number, suite?: Parameters<typeof signRevocationEpoch>[2]) => {
    const set = new RevocationSet(revoked);
    return {
      epoch: signRevocationEpoch(sk, { instance_id: 'x', grant_ref: profileRevocationScope('prof_a'), epoch: set.size, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + 300_000 }, suite),
      revoked: set.list(),
    };
  };
  const c = { now: NOW, maxAgeMs: 60_000 };

  it('usable, expired, revoked and an invalid profile', () => {
    expect(profileUsable(prof, { ...c, revocation: epoch([], NOW - 1) })).toEqual({ ok: true });
    expect(profileUsable({ ...prof, expires_at: prof.expires_at + 1 }, { ...c, revocation: epoch([], NOW - 1) })).toEqual({ ok: false, reason: 'profile signature invalid' });
    expect(profileUsable(prof, { ...c, now: NOW + 100_000, revocation: epoch([], NOW + 99_999) })).toEqual({ ok: false, reason: 'the profile has expired' });
    const id = profileRevocationId('prof_a', 1);
    expect(profileUsable(prof, { ...c, revocation: epoch([id], NOW - 1) })).toEqual({ ok: false, reason: `profile revocation: '${id}' is revoked` });
    expect(profileUsable(prof, c)).toEqual({ ok: false, reason: 'profile revocation: no session revocation epoch supplied' });
  });

  it('the pin policy reaches the revocation epoch check', () => {
    const pq = { alg: 'ml-dsa-65' as const, mlDsa: mlDsa65Keygen(seed('pq')) };
    const rev = epoch([], NOW - 1, pq);
    expect(profileUsable(prof, { ...c, revocation: rev, pin: { allowUnboundPq: true } })).toEqual({ ok: true });
    expect(profileUsable(prof, { ...c, revocation: rev })).toMatchObject({ ok: false });
  });
});
