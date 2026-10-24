/**
 * r13 mutation kills for intent-revocation.ts (group g2): the strict epoch shape, every step of checkSessionRevocation
 * (rule 13 step 7) by its exact reason, the namespaced ids / scopes and the T22 exposure bound.
 */
import { describe, expect, it } from 'vitest';
import {
  checkSessionRevocation,
  profileRevocationId,
  profileRevocationScope,
  revocationEpochShapeError,
  revocationExposureEnd,
  sessionRevocationScope,
  type SessionRevocationCheck,
  type SessionRevocationEvidence,
} from './intent-revocation';
import { RevocationSet, signRevocationEpoch } from './revocation';
import { b64u, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';

const seed = (l: string) => sha256(utf8(`r13-g2-revocation/${l}`));
const key = (l: string) => {
  const sk = seed(l);
  return { sk, pub: b64u(publicKeyOf(sk)) };
};
const auth = key('authority');
const stranger = key('stranger');
const SESSION = b64u(seed('session'));
const NOW = 1_800_000_000_000;
const ID = 'pca-intent:session:mine';

const revEv = (revoked: string[], issuedAt = NOW - 1_000, o: { signer?: typeof auth; grantRef?: string; epoch?: number; setSize?: number; root?: string } = {}): SessionRevocationEvidence => {
  const set = new RevocationSet(revoked);
  const epoch = signRevocationEpoch((o.signer ?? auth).sk, {
    instance_id: 'ana',
    grant_ref: o.grantRef ?? sessionRevocationScope(SESSION),
    epoch: o.epoch ?? set.size,
    set_size: o.setSize ?? set.size,
    root: o.root ?? set.root,
    issued_at: issuedAt,
    not_after: issuedAt + 300_000,
  });
  return { epoch, revoked: set.list() };
};
const C = (o: Partial<SessionRevocationCheck> = {}): SessionRevocationCheck => ({ session: SESSION, authority: auth.pub, ids: [ID], now: NOW, maxAgeMs: 60_000, ...o });
const EV = revEv(['pca-intent:session:other']);
const check = (ev: unknown, o: Partial<SessionRevocationCheck> = {}) => checkSessionRevocation(ev as SessionRevocationEvidence, C(o));
const no = (reason: string) => ({ ok: false, reason });

describe('revocationEpochShapeError', () => {
  it('accepts a signed epoch and the optional members', () => {
    expect(revocationEpochShapeError(EV.epoch)).toBeNull();
    expect(revocationEpochShapeError({ ...EV.epoch, guardian_epoch: 0 })).toBeNull();
    expect(revocationEpochShapeError({ ...EV.epoch, alg: 'ed25519', pq_pk: 'x', pq_sig: 'y' })).toBeNull();
  });
  it('refuses each member with the exact text', () => {
    for (const x of [null, [], 'e', Object.create(EV.epoch)]) expect(revocationEpochShapeError(x)).toBe('the revocation epoch must be an object');
    for (const k of ['instance_id', 'grant_ref', 'root', 'guardian', 'sig']) expect(revocationEpochShapeError({ ...EV.epoch, [k]: 5 })).toBe(`revocation epoch ${k} must be a string`);
    for (const k of ['epoch', 'set_size', 'issued_at', 'not_after']) for (const v of [-1, 1.5, '1']) expect(revocationEpochShapeError({ ...EV.epoch, [k]: v })).toBe(`revocation epoch ${k} must be a non-negative safe integer`);
    for (const g of [-1, 1.5, null]) expect(revocationEpochShapeError({ ...EV.epoch, guardian_epoch: g })).toBe('revocation epoch guardian_epoch must be a non-negative safe integer');
    expect(revocationEpochShapeError({ ...EV.epoch, alg: 'x-suite' })).toBe("revocation epoch alg: unsupported_suite: 'x-suite'");
    expect(revocationEpochShapeError({ ...EV.epoch, alg: 5 })).toBe('revocation epoch alg: alg must be a string');
    expect(revocationEpochShapeError({ ...EV.epoch, pq_pk: 5 })).toBe('revocation epoch pq_pk must be a string');
    expect(revocationEpochShapeError({ ...EV.epoch, pq_sig: 5 })).toBe('revocation epoch pq_sig must be a string');
  });
});

describe('ids, scopes, exposure', () => {
  it('namespaced', () => {
    expect(profileRevocationId('travel', 3)).toBe('pca-intent:profile:travel@3');
    expect(profileRevocationScope('travel')).toBe('pca-intent-profile:travel');
    expect(revocationExposureEnd(1_000, 60_000)).toBe(121_000);
    expect(revocationExposureEnd(1_000, 60_000, 5)).toBe(61_005);
  });
});

describe('checkSessionRevocation', () => {
  it('admits a fresh epoch by the authority that omits every required id', () => {
    expect(check(EV)).toEqual({ ok: true });
    expect(check(revEv([]))).toEqual({ ok: true });
    expect(check(revEv([], NOW - 60_000))).toEqual({ ok: true });
    expect(check(revEv(['pca-intent:session:｡', 'pca-intent:session:\u{1F600}']))).toEqual({ ok: true });
  });
  it('a: fails closed on a misconfigured check', () => {
    for (const maxAgeMs of [-1, 1.5, Number.NaN]) expect(check(EV, { maxAgeMs })).toEqual(no('revocation max age misconfigured (fail closed)'));
    expect(check(EV, { now: 1.5 })).toEqual(no('the verifier clock is not a safe integer (fail closed)'));
    expect(check(EV, { ids: 'x' as never })).toEqual(no('ids must be an array and the authority a key'));
    expect(check(EV, { authority: 5 as never })).toEqual(no('ids must be an array and the authority a key'));
  });
  it('b: the evidence is a closed object with a strictly typed epoch by the authority', () => {
    for (const ev of [undefined, null, [], 'x']) expect(check(ev)).toEqual(no('no session revocation epoch supplied'));
    expect(check({ ...EV, x: 1 })).toEqual(no("the revocation evidence has the unknown member 'x' (it is exactly {epoch, revoked})"));
    expect(check({ epoch: { ...EV.epoch, sig: 5 }, revoked: EV.revoked })).toEqual(no('revocation epoch sig must be a string'));
    expect(check({ revoked: EV.revoked })).toEqual(no('the revocation epoch must be an object'));
    expect(check(revEv([], NOW - 1_000, { signer: stranger }))).toEqual(no('the revocation epoch is not signed by the session revocation authority'));
  });
  it('c: the epoch verifies for the scope', () => {
    expect(check({ epoch: { ...EV.epoch, not_after: EV.epoch.not_after + 1 }, revoked: EV.revoked })).toEqual(no('revocation epoch signature invalid'));
    const custom = revEv([], NOW - 1_000, { grantRef: 'scope-x' });
    expect(check(custom)).toEqual(no('revocation epoch is for a different grant'));
    expect(check(custom, { scope: 'scope-x' })).toEqual({ ok: true });
    expect(check(EV, { scope: 'scope-x' })).toEqual(no('revocation epoch is for a different grant'));
    expect(check(revEv([], NOW - 400_000), { maxAgeMs: 1_000_000 })).toEqual(no('revocation epoch expired (stale revocation root)'));
    expect(check(revEv([], NOW + 60_001))).toEqual(no('revocation epoch issued in the future'));
  });
  it('d: the age bound is inclusive', () => {
    expect(check(revEv([], NOW - 60_001))).toEqual(no('the session revocation epoch is older than 60000 ms'));
    expect(check(revEv([], NOW - 1_000), { maxAgeMs: 999 })).toEqual(no('the session revocation epoch is older than 999 ms'));
    expect(check(revEv([], NOW - 1_000), { maxAgeMs: 1_000 })).toEqual({ ok: true });
  });
  it('e: the revoked list is the signed set', () => {
    for (const revoked of ['abc', [1], ['a', 2], {}]) expect(check({ epoch: EV.epoch, revoked })).toEqual(no('revoked must be an array of ids'));
    const two = revEv(['pca-intent:session:a', 'pca-intent:session:b']);
    expect(check({ epoch: two.epoch, revoked: ['pca-intent:session:b', 'pca-intent:session:a'] })).toEqual(no('revoked must be sorted by UTF-8 bytes and distinct'));
    expect(check({ epoch: two.epoch, revoked: ['pca-intent:session:a', 'pca-intent:session:a'] })).toEqual(no('revoked must be sorted by UTF-8 bytes and distinct'));
    expect(check({ epoch: two.epoch, revoked: ['pca-intent:session:\u{1F600}', 'pca-intent:session:｡'] })).toEqual(no('revoked must be sorted by UTF-8 bytes and distinct'));
    const size = 'the epoch must be numbered by its set size and list exactly set_size ids';
    expect(check({ epoch: two.epoch, revoked: ['pca-intent:session:a'] })).toEqual(no(size));
    expect(check(revEv([], NOW - 1_000, { epoch: 3 }))).toEqual(no(size));
    const one = revEv(['pca-intent:session:a']);
    expect(check({ epoch: one.epoch, revoked: ['pca-intent:session:b'] })).toEqual(no('the revoked list is not the signed set (root mismatch)'));
  });
  it('f: append-only against the tracked last epoch', () => {
    const last = revEv(['pca-intent:session:a', 'pca-intent:session:b'], NOW - 30_000);
    const L = (l: unknown) => ({ last: l as SessionRevocationEvidence });
    expect(check(revEv(['pca-intent:session:a', 'pca-intent:session:b', 'pca-intent:session:c']), L(last))).toEqual({ ok: true });
    expect(check(revEv(['pca-intent:session:a', 'pca-intent:session:b']), L(last))).toEqual({ ok: true });
    const bad = 'the tracked last epoch is malformed (fail closed)';
    for (const l of ['x', null, [], { ...last, x: 1 }, { epoch: { ...last.epoch, sig: 5 }, revoked: last.revoked }, { epoch: last.epoch, revoked: ['pca-intent:session:a'] }]) expect(check(EV, L(l))).toEqual(no(bad));
    expect(check(revEv(['pca-intent:session:a']), L(last))).toEqual(no('revocation epoch rollback (older than the last accepted)'));
    expect(check(revEv(['pca-intent:session:a', 'pca-intent:session:c']), L(last))).toEqual(no("the epoch drops 'pca-intent:session:b', revoked in the last accepted epoch (not append-only)"));
    expect(check(revEv(['pca-intent:session:c', 'pca-intent:session:d', 'pca-intent:session:e']), L(last))).toEqual(no("the epoch drops 'pca-intent:session:a', revoked in the last accepted epoch (not append-only)"));
  });
  it('g: no required id is revoked', () => {
    expect(check(revEv([ID]))).toEqual(no(`'${ID}' is revoked`));
    expect(check(EV, { ids: ['pca-intent:session:x', 'pca-intent:session:other'] })).toEqual(no("'pca-intent:session:other' is revoked"));
    expect(check(EV, { ids: [5 as never] })).toEqual(no("'5' is revoked"));
    expect(check(EV, { ids: [] })).toEqual({ ok: true });
  });
  it('an exception inside the check is a fail-closed refusal', () => {
    const ev = {
      get epoch(): never {
        throw new Error('boom');
      },
      revoked: [],
    };
    expect(check(ev)).toEqual(no('session revocation check error (fail closed): boom'));
  });
});
