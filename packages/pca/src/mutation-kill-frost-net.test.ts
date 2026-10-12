/**
 * Mutation-kill tests for src/frost-net.ts (Stryker). Each test pins one specific behaviour: exact reason
 * strings, validation boundaries, field-by-field wire output, ordering, and the ordering of refusals.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToScalar, frostTrustedDealerKeygen, L, scalarToBytes } from './frost';
import { generateKeyPair } from './keys';
import { b64u, utf8 } from './hash';
import {
  ALLOW_TOKEN_TYP,
  CoordinatorError,
  CoordinatorTimeoutError,
  createSignerPoP,
  enrollVerificationShares,
  EquivocationError,
  EquivocationGuard,
  frostActionDigest,
  GuardianSignerService,
  httpSignerTransport,
  inProcessTransport,
  issueAllowToken,
  NetworkCoordinator,
  PoPError,
  SIGNER_POP_DST,
  startSignerHttpServer,
  verifyAllowToken,
  verifySignerPoP,
  type Round1Request,
  type Round1Response,
  type Round2Request,
  type Round2Response,
  type SignerTransport,
} from './frost-net';

const MSG = utf8('mutation-kill message');
const R1 = (session_id: string): Round1Request => ({ typ: 'pca.frost.round1.v1', session_id });

function fixture(t = 2, n = 3) {
  const kg = frostTrustedDealerKeygen(t, n);
  const policy = generateKeyPair();
  const verificationShares = kg.participantShares.map((p) => ({ identifier: p.identifier, publicKey: p.publicKey }));
  const mk = (i: number, extra: Record<string, unknown> = {}) => {
    const p = kg.participantShares[i]!;
    return new GuardianSignerService({
      identifier: p.identifier,
      share: p.share.slice(),
      groupPublicKey: kg.groupPublicKey,
      threshold: t,
      policyAuthorityPublicKey: policy.publicKey,
      ...extra,
    } as never);
  };
  const svcs = kg.participantShares.map((_, i) => mk(i));
  const allow = (over: Record<string, unknown> = {}) =>
    issueAllowToken(policy.secretKey, { message: MSG, groupPublicKey: kg.groupPublicKey, ...over });
  return { t, n, kg, policy, verificationShares, mk, svcs, allow };
}
type Fx = ReturnType<typeof fixture>;

function ok1(r: Round1Response) {
  if (!r.ok) throw new Error('round1 refused: ' + r.reason);
  return r;
}

/** Open round 1 on `idx` services and build a valid round-2 request (overridable). */
function open(fx: Fx, sid: string, idx = [0, 1]) {
  const r1s = idx.map((i) => ok1(fx.svcs[i]!.round1(R1(sid))));
  const ids = new Set(r1s.map((r) => r.identifier));
  const req = (over: Partial<Round2Request> = {}): Round2Request => ({
    typ: 'pca.frost.round2.v1',
    session_id: sid,
    message: b64u(MSG),
    group_pk: b64u(fx.kg.groupPublicKey),
    commitments: r1s.map((r) => r.commitment),
    verification_shares: fx.verificationShares
      .filter((v) => ids.has(v.identifier))
      .map((v) => ({ identifier: v.identifier, publicKey: b64u(v.publicKey) })),
    allow: fx.allow(),
    ...over,
  });
  return { r1s, req };
}

const wrap = (svc: GuardianSignerService, over: Partial<SignerTransport> = {}): SignerTransport => ({
  ...inProcessTransport(svc),
  ...over,
});

function coord(fx: Fx, transports: SignerTransport[], extra: Record<string, unknown> = {}) {
  return new NetworkCoordinator({
    groupPublicKey: fx.kg.groupPublicKey,
    threshold: fx.t,
    signers: transports,
    verificationShares: fx.verificationShares,
    ...extra,
  } as never);
}

async function failure(p: Promise<unknown>): Promise<CoordinatorError> {
  try {
    await p;
  } catch (e) {
    return e as CoordinatorError;
  }
  throw new Error('expected rejection');
}

const BASE = ed25519.ExtendedPoint.BASE;
function cat(...ps: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(ps.reduce((a, p) => a + p.length, 0));
  let i = 0;
  for (const p of ps) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}
/** Independent re-implementation of the PoP prover so we can mint validly-signed pops for odd inputs. */
function forgePop(id: number, share: Uint8Array, gpk: ArrayLike<number>, k = 987654321n) {
  const x = bytesToScalar(share);
  const pk = BASE.multiply(x).toRawBytes();
  const R = BASE.multiply(k).toRawBytes();
  const h = sha512(cat(utf8(SIGNER_POP_DST), Uint8Array.from(gpk), scalarToBytes(BigInt(id)), pk, R));
  let e = bytesToScalar(h);
  if (e === 0n) e = 1n;
  const s = (k + e * x) % L;
  return { identifier: id, publicKey: b64u(pk), R: b64u(R), s: b64u(scalarToBytes(s)) };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// =================================================================================================
describe('frostActionDigest / issueAllowToken', () => {
  it('rejects non-bytes with TypeError and the exact message', () => {
    expect(() => frostActionDigest('abc' as never)).toThrow(TypeError);
    expect(() => frostActionDigest('abc' as never)).toThrow('frostActionDigest: message must be bytes');
    expect(() => frostActionDigest([1, 2] as never)).toThrow('frostActionDigest: message must be bytes');
  });
  it('issueAllowToken without message or digest throws the exact message', () => {
    const fx = fixture();
    expect(() => issueAllowToken(fx.policy.secretKey, { groupPublicKey: fx.kg.groupPublicKey })).toThrow(
      'issueAllowToken: provide message or frostActionDigest',
    );
  });
});

describe('verifyAllowToken reasons', () => {
  const fx = fixture();
  const exp = (over: Record<string, unknown> = {}) => ({
    policyAuthorityPublicKey: fx.policy.publicKey,
    groupPublicKey: fx.kg.groupPublicKey,
    message: MSG,
    now: 1000,
    ...over,
  });
  const v = (t: unknown, over: Record<string, unknown> = {}) => verifyAllowToken(t, exp(over) as never);

  it('accepts a good token (control)', () => {
    expect(v(fx.allow())).toEqual({ ok: true });
  });
  it('null / non-object token -> missing or malformed', () => {
    for (const t of [null, undefined, 'str', 5, true]) {
      expect(v(t)).toEqual({ ok: false, reason: 'allow token missing or malformed' });
    }
  });
  it('missing / non-object body -> no body', () => {
    for (const t of [{}, { body: null }, { body: 'str' }, { body: 7 }]) {
      expect(v(t)).toEqual({ ok: false, reason: 'allow token has no body' });
    }
  });
  it('wrong typ reports the typ', () => {
    expect(v({ body: { typ: 'nope' }, sig: 'x' })).toEqual({ ok: false, reason: 'allow token wrong typ (nope)' });
    expect(v({ body: {}, sig: 'x' })).toEqual({ ok: false, reason: 'allow token wrong typ (undefined)' });
  });
  it('non-string sig -> missing signature', () => {
    expect(v({ body: { typ: ALLOW_TOKEN_TYP }, sig: 5 })).toEqual({ ok: false, reason: 'allow token missing signature' });
    expect(v({ body: { typ: ALLOW_TOKEN_TYP } })).toEqual({ ok: false, reason: 'allow token missing signature' });
  });
  it('non-canonical sig encoding', () => {
    expect(v({ body: { typ: ALLOW_TOKEN_TYP }, sig: 'AAAA' })).toEqual({
      ok: false,
      reason: 'allow token signature not canonical base64url',
    });
  });
  it('signature by an untrusted key', () => {
    const other = generateKeyPair();
    const tok = issueAllowToken(other.secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    expect(v(tok)).toEqual({ ok: false, reason: 'allow token not signed by the trusted policy authority' });
  });
  it('different group key / action digest', () => {
    const otherG = frostTrustedDealerKeygen(2, 3).groupPublicKey;
    expect(v(fx.allow({ groupPublicKey: otherG }))).toEqual({
      ok: false,
      reason: 'allow token authorizes a different group key',
    });
    expect(v(fx.allow({ message: utf8('other') }))).toEqual({
      ok: false,
      reason: 'allow token authorizes a different action digest',
    });
  });
  it('non-finite verification time', () => {
    expect(v(fx.allow(), { now: NaN })).toEqual({ ok: false, reason: 'invalid verification time' });
    expect(v(fx.allow(), { now: Infinity })).toEqual({ ok: false, reason: 'invalid verification time' });
  });
  it('not_before boundary: now == not_before is valid, now < not_before is not yet valid', () => {
    const tok = fx.allow({ notBefore: 1000 });
    expect(v(tok, { now: 999 })).toEqual({ ok: false, reason: 'allow token not yet valid' });
    expect(v(tok, { now: 1000 })).toEqual({ ok: true });
    expect(v(tok, { now: 5000 })).toEqual({ ok: true });
    expect(v(fx.allow({ notBefore: 0 }), { now: -1 })).toEqual({ ok: false, reason: 'allow token not yet valid' });
  });
  it('expires_at boundary: now == expires_at is expired', () => {
    const tok = fx.allow({ expiresAt: 2000 });
    expect(v(tok, { now: 1999 })).toEqual({ ok: true });
    expect(v(tok, { now: 2000 })).toEqual({ ok: false, reason: 'allow token expired' });
  });
  it('fails closed with the thrown message (Error) or "unknown" (non-Error)', () => {
    const t1 = {
      get body(): never {
        throw new Error('boom');
      },
    };
    expect(v(t1)).toEqual({ ok: false, reason: 'allow token verification error (fail closed): boom' });
    const t2 = {
      get body(): never {
        // eslint-disable-next-line no-throw-literal
        throw 'str';
      },
    };
    expect(v(t2)).toEqual({ ok: false, reason: 'allow token verification error (fail closed): unknown' });
  });
});

// =================================================================================================
describe('signer proof-of-possession', () => {
  const kg = frostTrustedDealerKeygen(2, 3);
  const share = kg.participantShares[0]!.share;
  const gpk = kg.groupPublicKey;

  it('createSignerPoP validations', () => {
    for (const id of [0, -1, 1.5, NaN, '1' as never]) {
      expect(() => createSignerPoP(id as number, share, { groupPublicKey: gpk })).toThrow(
        'createSignerPoP: identifier must be a positive integer',
      );
    }
    expect(() => createSignerPoP(1, new Uint8Array(31), { groupPublicKey: gpk })).toThrow('createSignerPoP: share must be 32 bytes');
    expect(() => createSignerPoP(1, Array.from(share) as never, { groupPublicKey: gpk })).toThrow(
      'createSignerPoP: share must be 32 bytes',
    );
    expect(() => createSignerPoP(1, share, { groupPublicKey: new Uint8Array(31) })).toThrow(
      'createSignerPoP: groupPublicKey must be 32 bytes',
    );
    expect(() => createSignerPoP(1, share, { groupPublicKey: Array.from(gpk) as never })).toThrow(
      'createSignerPoP: groupPublicKey must be 32 bytes',
    );
  });
  it('a zero share still yields a PoP whose key is the identity encoding (0 maps to identity, not an error)', () => {
    const pop = createSignerPoP(1, new Uint8Array(32), { groupPublicKey: gpk });
    const identity = new Uint8Array(32);
    identity[0] = 1;
    expect(pop.publicKey).toBe(b64u(identity));
  });
  it('the PoP s equals k + e*x (matches the independent prover) and verifies', () => {
    const pop = createSignerPoP(1, share, { groupPublicKey: gpk });
    expect(verifySignerPoP(pop, { groupPublicKey: gpk })).toBe(true);
    const f = forgePop(1, share, gpk);
    expect(verifySignerPoP(f, { groupPublicKey: gpk })).toBe(true);
  });
  it('verify returns exactly false for non-objects', () => {
    for (const p of [null, undefined, 'str', 5]) expect(verifySignerPoP(p, { groupPublicKey: gpk })).toBe(false);
  });
  it('rejects a validly-signed pop with a non-positive identifier', () => {
    expect(verifySignerPoP(forgePop(0, share, gpk), { groupPublicKey: gpk })).toBe(false);
    expect(verifySignerPoP(forgePop(-1, share, gpk), { groupPublicKey: gpk })).toBe(false);
    expect(verifySignerPoP({ ...forgePop(1, share, gpk), identifier: 1.5 }, { groupPublicKey: gpk })).toBe(false);
    expect(verifySignerPoP({ ...forgePop(1, share, gpk), identifier: '1' }, { groupPublicKey: gpk })).toBe(false);
  });
  it('rejects a groupPublicKey that is not exactly 32 Uint8Array bytes even if the pop was minted for it', () => {
    const short = gpk.slice(0, 31);
    expect(verifySignerPoP(forgePop(1, share, short), { groupPublicKey: short })).toBe(false);
    const arr = Array.from(gpk);
    expect(verifySignerPoP(forgePop(1, share, arr), { groupPublicKey: arr as never })).toBe(false);
    expect(verifySignerPoP(forgePop(1, share, gpk), { groupPublicKey: gpk })).toBe(true);
  });
  it('rejects malformed field encodings with false', () => {
    const good = forgePop(1, share, gpk);
    expect(verifySignerPoP({ ...good, publicKey: '!!!' }, { groupPublicKey: gpk })).toBe(false);
    expect(verifySignerPoP({ ...good, R: '!!!' }, { groupPublicKey: gpk })).toBe(false);
    expect(verifySignerPoP({ ...good, s: '!!!' }, { groupPublicKey: gpk })).toBe(false);
    expect(verifySignerPoP({ ...good, s: undefined }, { groupPublicKey: gpk })).toBe(false);
  });
  it('rejects non-canonical s (s + L) and a tampered s', () => {
    const good = forgePop(1, share, gpk);
    const s = bytesToScalar(Uint8Array.from(Buffer.from(good.s, 'base64url')));
    const big = s + L;
    const enc = new Uint8Array(32);
    let v = big;
    for (let i = 0; i < 32; i++) {
      enc[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    // s + L fits in 253 bits + so it fits in 32 bytes for small s; skip if it does not
    if (big < 1n << 256n) expect(verifySignerPoP({ ...good, s: b64u(enc) }, { groupPublicKey: gpk })).toBe(false);
    expect(verifySignerPoP({ ...good, s: b64u(scalarToBytes(s + 1n)) }, { groupPublicKey: gpk })).toBe(false);
  });
  it('s = 0 (identity lhs) verifies false without throwing', () => {
    const good = forgePop(1, share, gpk);
    expect(verifySignerPoP({ ...good, s: b64u(new Uint8Array(32)) }, { groupPublicKey: gpk })).toBe(false);
  });
});

describe('enrollVerificationShares', () => {
  const kg = frostTrustedDealerKeygen(2, 3);
  const gpk = kg.groupPublicKey;
  const enrol = (i: number) => {
    const p = kg.participantShares[i]!;
    return { identifier: p.identifier, publicKey: p.publicKey, pop: createSignerPoP(p.identifier, p.share, { groupPublicKey: gpk }) };
  };
  const caught = (f: () => unknown): PoPError => {
    try {
      f();
    } catch (e) {
      return e as PoPError;
    }
    throw new Error('expected throw');
  };

  it('accepts valid enrollments and returns {identifier, publicKey}', () => {
    const out = enrollVerificationShares([enrol(0), enrol(1)], { groupPublicKey: gpk });
    expect(out.map((o) => o.identifier)).toEqual([1, 2]);
    expect(Object.keys(out[0]!).sort()).toEqual(['identifier', 'publicKey']);
  });
  it('empty or non-array enrollments', () => {
    for (const e of [[], null, undefined, {}, 'x']) {
      const err = caught(() => enrollVerificationShares(e as never, { groupPublicKey: gpk }));
      expect(err).toBeInstanceOf(PoPError);
      expect(err.message).toBe('enrollVerificationShares: no signer enrollments');
      expect(err.name).toBe('PoPError');
    }
  });
  it('bad group key', () => {
    for (const g of [new Uint8Array(31), Array.from(gpk), undefined]) {
      const err = caught(() => enrollVerificationShares([enrol(0)], { groupPublicKey: g as never }));
      expect(err).toBeInstanceOf(PoPError);
      expect(err.message).toBe('enrollVerificationShares: groupPublicKey must be 32 bytes');
    }
  });
  it('invalid identifier / null enrollment', () => {
    for (const bad of [null, undefined, { ...enrol(0), identifier: 0 }, { ...enrol(0), identifier: -2 }, { ...enrol(0), identifier: 1.5 }]) {
      const err = caught(() => enrollVerificationShares([bad as never], { groupPublicKey: gpk }));
      expect(err).toBeInstanceOf(PoPError);
      expect(err.message).toBe('enrollVerificationShares: enrollment with invalid identifier');
      expect(err.identifier).toBeUndefined();
    }
  });
  it('a zero-id enrollment carrying a validly-signed pop is still rejected for its identifier', () => {
    const p = kg.participantShares[0]!;
    const pop = forgePop(0, p.share, gpk);
    const err = caught(() => enrollVerificationShares([{ identifier: 0, publicKey: p.publicKey, pop }], { groupPublicKey: gpk }));
    expect(err.message).toBe('enrollVerificationShares: enrollment with invalid identifier');
  });
  it('duplicate id carries the identifier and exact message', () => {
    const err = caught(() => enrollVerificationShares([enrol(1), enrol(1)], { groupPublicKey: gpk }));
    expect(err.message).toBe('enrollVerificationShares: duplicate enrollment for signer 2');
    expect(err.identifier).toBe(2);
  });
  it('bad publicKey length', () => {
    for (const pk of [new Uint8Array(31), Array.from(enrol(1).publicKey)]) {
      const err = caught(() => enrollVerificationShares([{ ...enrol(1), publicKey: pk as never }], { groupPublicKey: gpk }));
      expect(err.message).toBe('enrollVerificationShares: signer 2 verification share must be 32 bytes');
      expect(err.identifier).toBe(2);
    }
  });
  it('missing or mismatched pop', () => {
    const base = enrol(1);
    const msg = 'enrollVerificationShares: signer 2 missing or mismatched proof-of-possession (rogue key rejected)';
    for (const e of [
      { ...base, pop: undefined },
      { ...base, pop: null },
      { ...base, pop: { ...base.pop, identifier: 3 } },
      { ...base, pop: enrol(2).pop },
      { ...base, pop: enrol(0).pop },
    ]) {
      const err = caught(() => enrollVerificationShares([e as never], { groupPublicKey: gpk }));
      expect(err).toBeInstanceOf(PoPError);
      expect(err.message).toBe(msg);
      expect(err.identifier).toBe(2);
    }
  });
  it('a pop minted for another id but pointing at the same key is rejected (identifier binding)', () => {
    const p = kg.participantShares[1]!;
    const pop = createSignerPoP(7, p.share, { groupPublicKey: gpk });
    const err = caught(() => enrollVerificationShares([{ identifier: 2, publicKey: p.publicKey, pop }], { groupPublicKey: gpk }));
    expect(err.message).toContain('missing or mismatched');
  });
  it('invalid pop (right key, forged proof)', () => {
    const base = enrol(1);
    const err = caught(() =>
      enrollVerificationShares([{ ...base, pop: { ...base.pop, s: b64u(scalarToBytes(5n)) } }], { groupPublicKey: gpk }),
    );
    expect(err.message).toBe('enrollVerificationShares: signer 2 invalid proof-of-possession (rogue key rejected)');
    expect(err.identifier).toBe(2);
  });
  it('PoPError without identifier has none', () => {
    expect(new PoPError('x').identifier).toBeUndefined();
    expect(new PoPError('x', 3).identifier).toBe(3);
  });
});

// =================================================================================================
describe('EquivocationGuard / EquivocationError', () => {
  it('argument validation with exact messages', () => {
    const g = new EquivocationGuard();
    for (const s of ['', 123, null, undefined]) {
      expect(() => g.observe(s as never, 1, 1, {})).toThrow('EquivocationGuard: session_id must be a non-empty string');
    }
    for (const r of [0, -1, 1.5, NaN]) {
      expect(() => g.observe('s', r, 1, {})).toThrow('EquivocationGuard: round must be a positive integer');
    }
    for (const i of [0, -1, 1.5, NaN]) {
      expect(() => g.observe('s', 1, i, {})).toThrow('EquivocationGuard: identifier must be a positive integer');
    }
    expect(() => g.observe('s', 1, 1, { a: 1 })).not.toThrow();
  });
  it('round 1 boundary: accepted; idempotent repeat; differing message throws a typed error', () => {
    const g = new EquivocationGuard();
    g.observe('s', 1, 1, { a: 1 });
    g.observe('s', 1, 1, { a: 1 });
    let err: EquivocationError | undefined;
    try {
      g.observe('s', 1, 1, { a: 2 });
    } catch (e) {
      err = e as EquivocationError;
    }
    expect(err).toBeInstanceOf(EquivocationError);
    expect(err!.name).toBe('EquivocationError');
    expect(err!.message).toBe("equivocation: signer 1 sent two different messages for session 's' round 1");
    expect(err!.session_id).toBe('s');
    expect(err!.round).toBe(1);
    expect(err!.identifier).toBe(1);
    expect(err!.previousDigest).not.toBe(err!.offendingDigest);
  });
  it('forget frees exactly the named session', () => {
    const g = new EquivocationGuard();
    g.observe('a', 1, 1, { x: 1 });
    g.observe('a', 2, 5, { x: 1 });
    g.observe('ab', 1, 1, { x: 1 });
    g.observe('b', 1, 1, { x: 1 });
    g.forget('a');
    expect(() => g.observe('a', 1, 1, { x: 2 })).not.toThrow();
    expect(() => g.observe('a', 2, 5, { x: 2 })).not.toThrow();
    expect(() => g.observe('ab', 1, 1, { x: 2 })).toThrow(EquivocationError);
    expect(() => g.observe('b', 1, 1, { x: 2 })).toThrow(EquivocationError);
  });
});

// =================================================================================================
describe('GuardianSignerService constructor', () => {
  const fx = fixture();
  const p = fx.kg.participantShares[0]!;
  const base = () => ({
    identifier: p.identifier,
    share: p.share.slice(),
    groupPublicKey: fx.kg.groupPublicKey,
    threshold: 2,
    policyAuthorityPublicKey: fx.policy.publicKey,
  });
  const mk = (over: Record<string, unknown>) => () => new GuardianSignerService({ ...base(), ...over } as never);

  it('control constructs', () => {
    expect(mk({})).not.toThrow();
    expect(mk({ threshold: 1 })).not.toThrow();
    expect(mk({ sessionTtlMs: 1 })).not.toThrow();
    expect(mk({ sessionTtlMs: undefined })).not.toThrow();
  });
  it('identifier', () => {
    for (const id of [0, -1, 1.5, NaN]) expect(mk({ identifier: id })).toThrow('GuardianSignerService: identifier must be a positive integer');
  });
  it('share', () => {
    for (const s of [new Uint8Array(31), new Uint8Array(33), Array.from(p.share)]) {
      expect(mk({ share: s })).toThrow('GuardianSignerService: share must be 32 bytes');
    }
  });
  it('groupPublicKey', () => {
    for (const s of [new Uint8Array(31), Array.from(fx.kg.groupPublicKey)]) {
      expect(mk({ groupPublicKey: s })).toThrow('GuardianSignerService: groupPublicKey must be 32 bytes');
    }
  });
  it('threshold', () => {
    for (const t of [0, -1, 1.5, NaN]) expect(mk({ threshold: t })).toThrow('GuardianSignerService: threshold must be a positive integer');
  });
  it('policyAuthorityPublicKey', () => {
    for (const s of [new Uint8Array(31), Array.from(fx.policy.publicKey)]) {
      expect(mk({ policyAuthorityPublicKey: s })).toThrow('GuardianSignerService: policyAuthorityPublicKey must be 32 bytes');
    }
  });
  it('sessionTtlMs', () => {
    for (const t of [0, -5, NaN, Infinity, -Infinity]) {
      expect(mk({ sessionTtlMs: t })).toThrow('GuardianSignerService: sessionTtlMs must be a positive finite number');
    }
  });
  it('copies its inputs: caller mutation after construction does not affect the service', () => {
    const f = fixture();
    const share = f.kg.participantShares[0]!.share.slice();
    const gpk = f.kg.groupPublicKey.slice();
    const pol = f.policy.publicKey.slice();
    const svc0 = new GuardianSignerService({
      identifier: 1,
      share,
      groupPublicKey: gpk,
      threshold: 2,
      policyAuthorityPublicKey: pol,
    });
    const svc1 = f.svcs[1]!;
    share.fill(0);
    gpk.fill(0);
    pol.fill(0);
    const sid = 'copy';
    const a = ok1(svc0.round1(R1(sid)));
    const b = ok1(svc1.round1(R1(sid)));
    const req: Round2Request = {
      typ: 'pca.frost.round2.v1',
      session_id: sid,
      message: b64u(MSG),
      group_pk: b64u(f.kg.groupPublicKey),
      commitments: [a.commitment, b.commitment],
      verification_shares: f.verificationShares.slice(0, 2).map((v) => ({ identifier: v.identifier, publicKey: b64u(v.publicKey) })),
      allow: f.allow(),
    };
    const r = svc0.round2(req);
    expect(r.ok).toBe(true);
  });
  it('enrollment() returns a copy of the verification share and the same pop', () => {
    const f = fixture();
    const svc = f.svcs[0]!;
    const before = svc.verificationShare.slice();
    const e = svc.enrollment();
    expect(e.identifier).toBe(1);
    expect(e.pop).toBe(svc.proofOfPossession);
    expect(e.publicKey).toEqual(before);
    e.publicKey.fill(7);
    expect(svc.verificationShare).toEqual(before);
    expect(svc.enrollment().publicKey).toEqual(before);
    expect(verifySignerPoP(svc.proofOfPossession, { groupPublicKey: f.kg.groupPublicKey })).toBe(true);
  });
});

// =================================================================================================
describe('GuardianSignerService.round1', () => {
  it('malformed requests are refused with the exact reason and identifier', () => {
    const fx = fixture();
    const svc = fx.svcs[1]!;
    const bad = [null, undefined, {}, { typ: 'x', session_id: 's' }, { typ: 'pca.frost.round1.v1' }, { typ: 'pca.frost.round1.v1', session_id: 5 }, { typ: 'pca.frost.round1.v1', session_id: '' }];
    for (const b of bad) {
      expect(svc.round1(b as never)).toEqual({ ok: false, identifier: 2, reason: 'malformed round-1 request' });
    }
  });
  it('success response shape; duplicate; spent', () => {
    const fx = fixture();
    const svc = fx.svcs[0]!;
    const r = svc.round1(R1('s1'));
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error();
    expect(r.identifier).toBe(1);
    expect(r.pop).toBe(svc.proofOfPossession);
    expect(Object.keys(r.commitment).sort()).toEqual(['binding', 'hiding', 'identifier']);
    expect(svc.round1(R1('s1'))).toEqual({ ok: false, identifier: 1, reason: 'duplicate round-1 for session' });
  });
  it('a signed session cannot be re-opened (spent) with the dedicated reason', () => {
    const fx = fixture();
    const { req } = open(fx, 'sp');
    expect(fx.svcs[0]!.round2(req()).ok).toBe(true);
    expect(fx.svcs[0]!.round1(R1('sp'))).toEqual({ ok: false, identifier: 1, reason: 'session already signed' });
  });
  it('catch: a throwing clock becomes a refusal (Error message, or "round-1 error")', () => {
    const fx = fixture();
    const s1 = fx.mk(0, { now: () => { throw new Error('clock down'); } });
    expect(s1.round1(R1('a'))).toEqual({ ok: false, identifier: 1, reason: 'clock down' });
    const s2 = fx.mk(0, { now: () => { throw 'x'; } }); // eslint-disable-line no-throw-literal
    expect(s2.round1(R1('a'))).toEqual({ ok: false, identifier: 1, reason: 'round-1 error' });
  });
});

describe('GuardianSignerService.round2', () => {
  it('malformed requests', () => {
    const fx = fixture();
    const { req } = open(fx, 's');
    const good = req();
    for (const b of [null, undefined, { ...good, typ: 'pca.frost.round2.v1x' }, { ...good, typ: 'pca.frost.round1.v1' }, { ...good, session_id: 7 }]) {
      expect(fx.svcs[0]!.round2(b as never)).toEqual({
        ok: false,
        identifier: 1,
        refused: true,
        reason: 'malformed round-2 request',
      });
    }
  });
  it('success: shape, one-shot, and spent beats missing-state', () => {
    const fx = fixture();
    const { req } = open(fx, 'ok');
    const r = fx.svcs[0]!.round2(req());
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error();
    expect(Object.keys(r).sort()).toEqual(['identifier', 'ok', 'sig_share']);
    expect(r.identifier).toBe(1);
    expect(Buffer.from(r.sig_share, 'base64url').length).toBe(32);
    expect(fx.svcs[0]!.round2(req())).toEqual({
      ok: false,
      identifier: 1,
      refused: true,
      reason: 'session already signed (one-shot)',
    });
  });
  it('no round-1 state', () => {
    const fx = fixture();
    const { req } = open(fx, 'x');
    expect(fx.svcs[2]!.round2(req())).toEqual({
      ok: false,
      identifier: 3,
      refused: true,
      reason: 'no round-1 state for this session',
    });
  });
  it('stale-session guard: boundary, arithmetic, message, and the session is dropped', () => {
    let clock = 1000;
    const fx = fixture();
    const svcs = fx.kg.participantShares.map((_, i) => fx.mk(i, { sessionTtlMs: 100, now: () => clock }));
    fx.svcs.splice(0, 3, ...svcs);
    const a = open(fx, 'ttl-ok');
    clock = 1100; // age == ttl : still live
    expect(fx.svcs[0]!.round2(a.req()).ok).toBe(true);

    clock = 2000;
    const b = open(fx, 'ttl-stale');
    clock = 2101; // age 101 > 100
    expect(fx.svcs[0]!.round2(b.req())).toEqual({
      ok: false,
      identifier: 1,
      refused: true,
      reason: 'session expired (stale-session guard: round-1 older than 100ms)',
    });
    // The stale session was DROPPED: a retry now reports no state (and is not signable).
    clock = 2102;
    expect(fx.svcs[0]!.round2(b.req())).toMatchObject({ ok: false, reason: 'no round-1 state for this session' });

    clock = 5000;
    const c = open(fx, 'ttl-sum');
    clock = 5050; // age 50 (a + instead of - would give 10050 > 100)
    expect(fx.svcs[0]!.round2(c.req()).ok).toBe(true);
  });
  it('message must be canonical base64url', () => {
    const fx = fixture();
    const { req } = open(fx, 'm');
    expect(fx.svcs[0]!.round2(req({ message: '!!' }))).toMatchObject({ ok: false, reason: 'message not canonical base64url' });
  });
  it('request group key mismatch is refused (token alone would still bind the real group)', () => {
    const fx = fixture();
    const { req } = open(fx, 'g');
    const other = frostTrustedDealerKeygen(2, 3).groupPublicKey;
    expect(fx.svcs[0]!.round2(req({ group_pk: b64u(other) }))).toMatchObject({
      ok: false,
      reason: 'request names a different group key',
    });
  });
  it('policy authorization failure carries the verifier reason', () => {
    const fx = fixture();
    const { req } = open(fx, 'p');
    const forged = issueAllowToken(generateKeyPair().secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    expect(fx.svcs[0]!.round2(req({ allow: forged }))).toMatchObject({
      ok: false,
      reason: 'policy authorization failed: allow token not signed by the trusted policy authority',
    });
    expect(fx.svcs[0]!.round2(req({ allow: undefined as never }))).toMatchObject({
      ok: false,
      reason: 'policy authorization failed: allow token missing or malformed',
    });
  });
  it('the allow token validity window uses the signer clock', () => {
    const fx = fixture();
    const clk = fx.kg.participantShares.map((_, i) => fx.mk(i, { now: () => 10_000 }));
    fx.svcs.splice(0, 3, ...clk);
    const { req } = open(fx, 'w');
    expect(fx.svcs[0]!.round2(req({ allow: fx.allow({ expiresAt: 10_000 }) }))).toMatchObject({
      reason: 'policy authorization failed: allow token expired',
    });
    expect(fx.svcs[0]!.round2(req({ allow: fx.allow({ notBefore: 10_001 }) }))).toMatchObject({
      reason: 'policy authorization failed: allow token not yet valid',
    });
    expect(fx.svcs[0]!.round2(req({ allow: fx.allow({ notBefore: 10_000, expiresAt: 10_001 }) })).ok).toBe(true);
  });
  it('refusal keeps the nonces: an honest retry with a valid token then succeeds', () => {
    const fx = fixture();
    const { req } = open(fx, 'retry');
    expect(fx.svcs[0]!.round2(req({ allow: fx.allow({ message: utf8('other') }) })).ok).toBe(false);
    expect(fx.svcs[0]!.round2(req()).ok).toBe(true);
  });
  it('commitments: missing list is below threshold; short list is below threshold (exact message)', () => {
    const fx = fixture();
    const { req, r1s } = open(fx, 'c');
    expect(fx.svcs[0]!.round2(req({ commitments: undefined as never }))).toMatchObject({
      reason: 'signing set below threshold t=2',
    });
    expect(fx.svcs[0]!.round2(req({ commitments: [r1s[0]!.commitment] }))).toMatchObject({
      reason: 'signing set below threshold t=2',
    });
  });
  it('malformed commitments: id and encodings', () => {
    const fx = fixture();
    const { req, r1s } = open(fx, 'bc');
    const c0 = r1s[0]!.commitment;
    const c1 = r1s[1]!.commitment;
    for (const id of [0, -1, 1.5]) {
      expect(fx.svcs[0]!.round2(req({ commitments: [c0, { ...c1, identifier: id }] }))).toMatchObject({
        reason: 'bad commitment identifier',
      });
    }
    // bad id AND bad encoding: the id message wins (checked first)
    expect(fx.svcs[0]!.round2(req({ commitments: [c0, { ...c1, identifier: 0, hiding: '!' }] }))).toMatchObject({
      reason: 'bad commitment identifier',
    });
    expect(fx.svcs[0]!.round2(req({ commitments: [c0, { ...c1, hiding: '!!' }] }))).toMatchObject({
      reason: 'bad commitment point encoding',
    });
    expect(fx.svcs[0]!.round2(req({ commitments: [c0, { ...c1, binding: '!!' }] }))).toMatchObject({
      reason: 'bad commitment point encoding',
    });
    // still live after refusals
    expect(fx.svcs[0]!.round2(req()).ok).toBe(true);
  });
  it('own commitment must be in the set', () => {
    const fx = fixture();
    const { req, r1s } = open(fx, 'own', [1, 2]); // signer 2 & 3 open; signer 1 is asked but has no commitment in set
    void r1s;
    // signer idx1 (id 2) in set -> fine; ask idx0 (id1, with its own round1 opened separately)
    ok1(fx.svcs[0]!.round1(R1('own')));
    expect(fx.svcs[0]!.round2(req())).toMatchObject({
      ok: false,
      reason: 'our commitment is not in the signing set',
    });
  });
  it('equivocation: a differing hiding OR binding in the set for our id is refused with the typed reason', () => {
    const fx = fixture();
    const { req, r1s } = open(fx, 'eq');
    const mine = r1s[0]!.commitment;
    const other = ok1(fx.svcs[2]!.round1(R1('eq-other'))).commitment;
    const msg = 'equivocation detected: our commitment in the signing set differs from our round-1 commitment';
    expect(fx.svcs[0]!.round2(req({ commitments: [{ ...mine, hiding: other.hiding }, r1s[1]!.commitment] }))).toMatchObject({ reason: msg });
    expect(fx.svcs[0]!.round2(req({ commitments: [{ ...mine, binding: other.binding }, r1s[1]!.commitment] }))).toMatchObject({ reason: msg });
    expect(fx.svcs[0]!.round2(req({ commitments: [{ ...mine, hiding: other.hiding, binding: other.binding }, r1s[1]!.commitment] }))).toMatchObject({
      reason: msg,
    });
    expect(fx.svcs[0]!.round2(req()).ok).toBe(true);
  });
  it('verification_shares must be a list; and shares that do not interpolate to the group key are refused', () => {
    const fx = fixture();
    const { req, r1s } = open(fx, 'vs');
    for (const bad of [undefined, null, {}, 'x']) {
      expect(fx.svcs[0]!.round2(req({ verification_shares: bad as never }))).toMatchObject({
        reason: 'verification_shares must be a list',
      });
    }
    const vs = req().verification_shares;
    // swap in the wrong key for signer 2
    const wrong = [vs[0]!, { identifier: vs[1]!.identifier, publicKey: b64u(fx.kg.participantShares[2]!.publicKey) }];
    expect(fx.svcs[0]!.round2(req({ verification_shares: wrong }))).toMatchObject({
      ok: false,
      reason: 'frostSign: group public key does not match the verification shares',
    });
    // missing a share for a set member
    expect(fx.svcs[0]!.round2(req({ verification_shares: [vs[0]!] }))).toMatchObject({
      ok: false,
      reason: 'frostSign: missing verification share for 2',
    });
    void r1s;
    expect(fx.svcs[0]!.round2(req()).ok).toBe(true);
  });
  it('malformed verification-share entries', () => {
    const fx = fixture();
    const { req } = open(fx, 'vs2');
    const vs = req().verification_shares;
    for (const id of [0, -1, 1.5]) {
      expect(fx.svcs[0]!.round2(req({ verification_shares: [vs[0]!, { ...vs[1]!, identifier: id }] }))).toMatchObject({
        reason: 'bad verification-share identifier',
      });
    }
    expect(fx.svcs[0]!.round2(req({ verification_shares: [vs[0]!, { ...vs[1]!, publicKey: '!!' }] }))).toMatchObject({
      reason: 'bad verification-share key encoding',
    });
    // bad id + bad key: the key is decoded first but the id message wins
    expect(fx.svcs[0]!.round2(req({ verification_shares: [vs[0]!, { identifier: 0, publicKey: '!!' }] }))).toMatchObject({
      reason: 'bad verification-share identifier',
    });
  });
  it('catch: non-Error throw becomes "round-2 error"; Error becomes its message', () => {
    let calls = 0;
    const fx = fixture();
    const s = fx.mk(0, {
      now: () => {
        calls++;
        if (calls === 1) return 0; // round1
        throw 'oops'; // eslint-disable-line no-throw-literal
      },
    });
    fx.svcs[0] = s;
    const { req } = open(fx, 'thr');
    expect(s.round2(req())).toEqual({ ok: false, identifier: 1, refused: true, reason: 'round-2 error' });
    let n2 = 0;
    const s2 = fx.mk(0, {
      now: () => {
        if (n2++ === 0) return 0;
        throw new Error('clock gone');
      },
    });
    fx.svcs[0] = s2;
    const { req: req2 } = open(fx, 'thr2');
    expect(s2.round2(req2())).toMatchObject({ reason: 'clock gone', refused: true });
  });
});

// =================================================================================================
describe('HTTP server and transport', () => {
  async function srv(fx: Fx, opts: { port?: number } = {}) {
    return startSignerHttpServer(fx.svcs[0]!, opts);
  }
  it('rejects non-POST with 405 and a JSON body', async () => {
    const fx = fixture();
    const s = await srv(fx);
    try {
      const r = await fetch(s.url + '/round1', { method: 'GET' });
      expect(r.status).toBe(405);
      expect(r.headers.get('content-type')).toBe('application/json');
      expect(await r.json()).toEqual({ ok: false, reason: 'method not allowed' });
    } finally {
      await s.close();
    }
  });
  it('routes /round1, /round2 and 404s anything else', async () => {
    const fx = fixture();
    const s = await srv(fx);
    try {
      const post = (path: string, body: unknown) =>
        fetch(s.url + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      const a = await post('/round1', R1('h1'));
      expect(a.status).toBe(200);
      expect(a.headers.get('content-type')).toBe('application/json');
      const aj = (await a.json()) as { ok: boolean; identifier: number; commitment: unknown };
      expect(aj.ok).toBe(true);
      expect(aj.identifier).toBe(1);
      const b = await post('/round2', {});
      expect(b.status).toBe(200);
      expect(await b.json()).toEqual({ ok: false, identifier: 1, refused: true, reason: 'malformed round-2 request' });
      const c = await post('/other', {});
      expect(c.status).toBe(404);
      expect(c.headers.get('content-type')).toBe('application/json');
      expect(await c.json()).toEqual({ ok: false, reason: 'not found' });
    } finally {
      await s.close();
    }
  });
  it('bad JSON maps to a 400 refusal, never a stack', async () => {
    const fx = fixture();
    const s = await srv(fx);
    try {
      const r = await fetch(s.url + '/round1', { method: 'POST', body: '{not json' });
      expect(r.status).toBe(400);
      const j = (await r.json()) as Record<string, unknown>;
      expect(j.ok).toBe(false);
      expect(j.identifier).toBe(1);
      expect(j.refused).toBe(true);
      expect(typeof j.reason).toBe('string');
      expect((j.reason as string).length).toBeGreaterThan(0);
    } finally {
      await s.close();
    }
  });
  it('body size limit: exactly 1 MiB is accepted, 1 MiB + 1 and larger bodies are refused', async () => {
    const fx = fixture();
    const s = await srv(fx);
    try {
      const mk = (n: number) => {
        const head = '{"a":"';
        const tail = '"}';
        return head + 'x'.repeat(n - head.length - tail.length) + tail;
      };
      const exact = await fetch(s.url + '/round1', { method: 'POST', body: mk(1 << 20) });
      expect(exact.status).toBe(200);
      const over = await fetch(s.url + '/round1', { method: 'POST', body: mk((1 << 20) + 1) });
      expect(over.status).toBe(400);
      expect(((await over.json()) as { reason: string }).reason).toBe('request body too large');
      // several chunks accumulate
      const big = await fetch(s.url + '/round1', { method: 'POST', body: mk(3 << 20) });
      expect(big.status).toBe(400);
    } finally {
      await s.close();
    }
  });
  it('honours a pinned port, reports url/port, and close() really stops listening', async () => {
    const fx = fixture();
    const probe = await srv(fx);
    const port = probe.port;
    await probe.close();
    const s = await srv(fx, { port });
    expect(s.port).toBe(port);
    expect(s.url).toBe(`http://127.0.0.1:${port}`);
    expect(s.server.listening).toBe(true);
    await s.close();
    expect(s.server.listening).toBe(false);
    await expect(fetch(s.url + '/round1', { method: 'POST', body: '{}' })).rejects.toThrow();
  });
  it('a listen error (port in use) rejects', async () => {
    const fx = fixture();
    const s = await srv(fx);
    try {
      await expect(startSignerHttpServer(fx.svcs[1]!, { port: s.port })).rejects.toThrow(/EADDRINUSE|address already in use/);
    } finally {
      await s.close();
    }
  });
  it('httpSignerTransport sends POST JSON to base+path and returns the parsed body', async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return { json: async () => ({ ok: true, echoed: JSON.parse(init.body as string) }) };
    });
    const t = httpSignerTransport('http://x:1', 4);
    expect(t.identifier).toBe(4);
    const r1 = await t.round1(R1('a'));
    const r2 = await t.round2({ typ: 'pca.frost.round2.v1' } as never);
    expect(r1).toEqual({ ok: true, echoed: R1('a') });
    expect(r2).toEqual({ ok: true, echoed: { typ: 'pca.frost.round2.v1' } });
    expect(calls[0]!.url).toBe('http://x:1/round1');
    expect(calls[1]!.url).toBe('http://x:1/round2');
    for (const c of calls) {
      expect(c.init.method).toBe('POST');
      expect(c.init.headers).toEqual({ 'content-type': 'application/json' });
      expect(c.init.signal).toBeInstanceOf(AbortSignal);
    }
  });
  it('httpSignerTransport clears its timer on success and on failure', async () => {
    const handles: unknown[] = [];
    const realSet = globalThis.setTimeout;
    vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms: number, ...a: unknown[]) => {
      const h = (realSet as (...x: unknown[]) => unknown)(fn, ms, ...a);
      if (ms === 7777) handles.push(h);
      return h;
    }) as never);
    const cleared: unknown[] = [];
    const realClear = globalThis.clearTimeout;
    vi.spyOn(globalThis, 'clearTimeout').mockImplementation(((h: never) => {
      cleared.push(h);
      return realClear(h);
    }) as never);
    vi.stubGlobal('fetch', async () => ({ json: async () => ({ ok: true }) }));
    const t = httpSignerTransport('http://x', 1, { timeoutMs: 7777 });
    await t.round1(R1('a'));
    expect(handles.length).toBe(1);
    expect(cleared).toContain(handles[0]);
    vi.stubGlobal('fetch', async () => {
      throw new Error('net');
    });
    await expect(t.round1(R1('b'))).rejects.toThrow('net');
    expect(handles.length).toBe(2);
    expect(cleared).toContain(handles[1]);
  });
  it('httpSignerTransport aborts a hung request after timeoutMs', async () => {
    vi.stubGlobal('fetch', (_u: string, init: RequestInit) => {
      return new Promise((_res, rej) => {
        init.signal!.addEventListener('abort', () => rej(new Error('aborted')));
      });
    });
    const t = httpSignerTransport('http://x', 1, { timeoutMs: 20 });
    await expect(t.round1(R1('a'))).rejects.toThrow('aborted');
  });
});

// =================================================================================================
describe('NetworkCoordinator constructor', () => {
  const fx = fixture();
  const mk = (over: Record<string, unknown>) => () =>
    new NetworkCoordinator({
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: 2,
      signers: [],
      verificationShares: fx.verificationShares,
      ...over,
    } as never);
  it('control and boundaries', () => {
    expect(mk({})).not.toThrow();
    expect(mk({ threshold: 1 })).not.toThrow();
    expect(mk({ timeoutMs: 1 })).not.toThrow();
    expect(mk({ timeoutMs: undefined })).not.toThrow();
  });
  it('groupPublicKey', () => {
    for (const g of [new Uint8Array(31), Array.from(fx.kg.groupPublicKey)]) {
      expect(mk({ groupPublicKey: g })).toThrow('NetworkCoordinator: groupPublicKey must be 32 bytes');
    }
  });
  it('threshold', () => {
    for (const t of [0, -1, 1.5, NaN]) expect(mk({ threshold: t })).toThrow('NetworkCoordinator: threshold must be a positive integer');
  });
  it('timeoutMs', () => {
    for (const t of [0, -1, NaN, Infinity]) {
      expect(mk({ timeoutMs: t })).toThrow('NetworkCoordinator: timeoutMs must be a positive finite number');
    }
  });
  it('requires verificationShares or enroll', () => {
    expect(mk({ verificationShares: undefined })).toThrow('NetworkCoordinator: provide verificationShares or enroll');
  });
  it('enroll takes the PoP-verified path and wins over plain verificationShares', () => {
    const enroll = fx.svcs.map((s) => s.enrollment());
    expect(mk({ verificationShares: undefined, enroll })).not.toThrow();
    const rogue = enroll.map((e, i) => (i === 0 ? { ...e, pop: { ...e.pop, s: b64u(scalarToBytes(3n)) } } : e));
    expect(mk({ verificationShares: undefined, enroll: rogue })).toThrow(PoPError);
    // enroll present => rogue enrollment is still checked even though verificationShares is also supplied
    expect(mk({ enroll: rogue })).toThrow(PoPError);
  });
});

// =================================================================================================
describe('NetworkCoordinator.sign', () => {
  it('rejects non-bytes messages', async () => {
    const fx = fixture();
    const c = coord(fx, fx.svcs.map(inProcessTransport));
    await expect(c.sign('x' as never, fx.allow())).rejects.toThrow('coordinator.sign: message must be bytes');
  });
  it('too few selected signers', async () => {
    const fx = fixture();
    const c = coord(fx, fx.svcs.map(inProcessTransport));
    const e = await failure(c.sign(MSG, fx.allow(), { signerIds: [1] }));
    expect(e).toBeInstanceOf(CoordinatorError);
    expect(e.name).toBe('CoordinatorError');
    expect(e.message).toBe('coordinator: only 1 signer(s) selected, need t=2');
    expect(e.refusals).toEqual([]);
  });
  it('signing set is exactly t signers even when more commit; result fields', async () => {
    const fx = fixture();
    const seen: Round2Request[] = [];
    const ts = fx.svcs.map((s) => wrap(s, { round2: (r) => { seen.push(r); return Promise.resolve(s.round2(r)); } }));
    const c = coord(fx, ts, { newSessionId: () => 'fixed-sid' });
    const allow = fx.allow();
    const res = await c.sign(MSG, allow, { signerIds: [1, 2, 3] });
    expect(res.signers).toEqual([1, 2]);
    expect(res.sessionId).toBe('fixed-sid');
    expect(seen.length).toBe(2);
    for (const r of seen) {
      expect(r.typ).toBe('pca.frost.round2.v1');
      expect(r.session_id).toBe('fixed-sid');
      expect(r.message).toBe(b64u(MSG));
      expect(r.group_pk).toBe(b64u(fx.kg.groupPublicKey));
      expect(r.commitments.map((x) => x.identifier)).toEqual([1, 2]);
      expect(r.verification_shares.map((x) => x.identifier)).toEqual([1, 2]);
      expect(r.verification_shares[0]!.publicKey).toBe(b64u(fx.verificationShares[0]!.publicKey));
      expect(r.allow).toBe(allow);
    }
  });
  it('round 1: a throwing transport is a refusal (Error message / "unreachable")', async () => {
    const fx = fixture();
    const ts = [
      wrap(fx.svcs[0]!),
      wrap(fx.svcs[1]!, { round1: () => Promise.reject(new Error('conn reset')) }),
      wrap(fx.svcs[2]!, { round1: () => Promise.reject('weird') }),
    ];
    const c = coord(fx, ts);
    const e = await failure(c.sign(MSG, fx.allow(), { signerIds: [1, 2, 3] }));
    expect(e.message).toBe('coordinator: round 1 produced 1 commitment(s), need t=2');
    expect(e.refusals).toEqual([
      { identifier: 2, reason: 'conn reset' },
      { identifier: 3, reason: 'unreachable' },
    ]);
  });
  it('round 1: an explicit refusal is recorded with identifier and reason', async () => {
    const fx = fixture();
    const ts = [
      wrap(fx.svcs[0]!),
      wrap(fx.svcs[1]!, { round1: () => Promise.resolve({ ok: false, identifier: 2, reason: 'nope' }) }),
    ];
    const e = await failure(coord(fx, ts).sign(MSG, fx.allow()));
    expect(e.refusals).toEqual([{ identifier: 2, reason: 'nope' }]);
    expect(e.message).toBe('coordinator: round 1 produced 1 commitment(s), need t=2');
  });
  it('round 1: a signer with no verification share on record is refused', async () => {
    const fx = fixture();
    const c = new NetworkCoordinator({
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: 2,
      signers: fx.svcs.map(inProcessTransport),
      verificationShares: fx.verificationShares.filter((v) => v.identifier !== 2),
    });
    const e = await failure(c.sign(MSG, fx.allow(), { signerIds: [1, 2] }));
    expect(e.refusals).toEqual([{ identifier: 2, reason: 'no verification share on record for this signer' }]);
  });
  describe('round 1 PoP defense', () => {
    const POP = 'invalid or missing proof-of-possession (rogue-key defense)';
    const mutate = (svc: GuardianSignerService, f: (r: Extract<Round1Response, { ok: true }>) => unknown): SignerTransport =>
      wrap(svc, { round1: (req) => Promise.resolve(f(ok1(svc.round1(req))) as Round1Response) });
    it('missing pop', async () => {
      const fx = fixture();
      const ts = [wrap(fx.svcs[0]!), mutate(fx.svcs[1]!, (r) => ({ ...r, pop: undefined }))];
      const e = await failure(coord(fx, ts).sign(MSG, fx.allow()));
      expect(e.refusals).toEqual([{ identifier: 2, reason: POP }]);
    });
    it('pop whose identifier differs but key/proof otherwise valid', async () => {
      const fx = fixture();
      const sh = fx.kg.participantShares[1]!.share;
      const ts = [wrap(fx.svcs[0]!), mutate(fx.svcs[1]!, (r) => ({ ...r, pop: createSignerPoP(7, sh, { groupPublicKey: fx.kg.groupPublicKey }) }))];
      const e = await failure(coord(fx, ts).sign(MSG, fx.allow()));
      expect(e.refusals).toEqual([{ identifier: 2, reason: POP }]);
    });
    it('pop for a different (but self-consistent) key', async () => {
      const fx = fixture();
      const sh = fx.kg.participantShares[2]!.share;
      const ts = [wrap(fx.svcs[0]!), mutate(fx.svcs[1]!, (r) => ({ ...r, pop: createSignerPoP(2, sh, { groupPublicKey: fx.kg.groupPublicKey }) }))];
      const e = await failure(coord(fx, ts).sign(MSG, fx.allow()));
      expect(e.refusals).toEqual([{ identifier: 2, reason: POP }]);
    });
    it('pop with a forged proof for the right key and id', async () => {
      const fx = fixture();
      const ts = [wrap(fx.svcs[0]!), mutate(fx.svcs[1]!, (r) => ({ ...r, pop: { ...r.pop, s: b64u(scalarToBytes(9n)) } }))];
      const e = await failure(coord(fx, ts).sign(MSG, fx.allow()));
      expect(e.refusals).toEqual([{ identifier: 2, reason: POP }]);
    });
  });
  describe('equivocation across rounds', () => {
    it('round 1: a signer re-using a session id with a new commitment is refused; non-Equivocation errors give the generic reason', async () => {
      const fx = fixture();
      let n = 0;
      const flaky = (svc: GuardianSignerService): SignerTransport =>
        wrap(svc, { round1: () => Promise.resolve(svc.round1(R1('inner-' + n++))) });
      const c = coord(fx, [flaky(fx.svcs[0]!), flaky(fx.svcs[1]!)], { newSessionId: () => 'S' });
      // first run fails later (wrong session id at the signer), but round-1 bindings are recorded
      await failure(c.sign(MSG, fx.allow()));
      const e = await failure(c.sign(MSG, fx.allow()));
      expect(e.message).toBe('coordinator: round 1 produced 0 commitment(s), need t=2');
      expect(e.refusals.map((r) => r.identifier)).toEqual([1, 2]);
      expect(e.refusals[0]!.reason).toBe("equivocation: signer 1 sent two different messages for session 'S' round 1");
      expect(e.refusals[1]!.reason).toBe("equivocation: signer 2 sent two different messages for session 'S' round 1");
    });
    it('round 1: a non-equivocation guard failure is reported generically', async () => {
      const fx = fixture();
      const inner = (svc: GuardianSignerService) => wrap(svc, { round1: () => Promise.resolve(svc.round1(R1('z'))) });
      const c = coord(fx, [inner(fx.svcs[0]!), inner(fx.svcs[1]!)], { newSessionId: () => '' });
      const e = await failure(c.sign(MSG, fx.allow()));
      expect(e.refusals).toEqual([
        { identifier: 1, reason: 'equivocation check failed' },
        { identifier: 2, reason: 'equivocation check failed' },
      ]);
    });
    it('round 2: two different shares for the same (session, round, signer) are refused', async () => {
      const fx = fixture();
      const r1: Record<number, Round1Response> = {};
      let k = 0;
      const fake = (svc: GuardianSignerService): SignerTransport => ({
        identifier: svc.identifier,
        round1: () => Promise.resolve((r1[svc.identifier] ??= svc.round1(R1('fake-' + svc.identifier)))),
        round2: () =>
          Promise.resolve({ ok: true, identifier: svc.identifier, sig_share: b64u(scalarToBytes(BigInt(++k + 1))) } as Round2Response),
      });
      const c = coord(fx, [fake(fx.svcs[0]!), fake(fx.svcs[1]!)], { newSessionId: () => 'S2' });
      const first = await failure(c.sign(MSG, fx.allow()));
      expect(first.message).toContain('frostAggregate: invalid signature share from participant');
      const second = await failure(c.sign(MSG, fx.allow()));
      expect(second.message).toBe('coordinator: round 2 produced 0 share(s), need t=2');
      expect(second.refusals.map((r) => r.reason)).toEqual([
        "equivocation: signer 1 sent two different messages for session 'S2' round 2",
        "equivocation: signer 2 sent two different messages for session 'S2' round 2",
      ]);
    });
    it('round 2: a non-equivocation guard failure is reported generically', async () => {
      const fx = fixture();
      const fake = (svc: GuardianSignerService): SignerTransport => ({
        identifier: svc.identifier,
        round1: (req) => Promise.resolve(svc.round1(req)),
        round2: () => Promise.resolve({ ok: true, identifier: 0, sig_share: 'x' } as Round2Response),
      });
      const e = await failure(coord(fx, [fake(fx.svcs[0]!), fake(fx.svcs[1]!)]).sign(MSG, fx.allow()));
      expect(e.message).toBe('coordinator: round 2 produced 0 share(s), need t=2');
      expect(e.refusals).toEqual([
        { identifier: 0, reason: 'equivocation check failed' },
        { identifier: 0, reason: 'equivocation check failed' },
      ]);
    });
  });
  it('missing a verification share for a signer in the set (duplicate records) is a typed error', async () => {
    const fx = fixture();
    const c = new NetworkCoordinator({
      groupPublicKey: fx.kg.groupPublicKey,
      threshold: 2,
      signers: fx.svcs.map(inProcessTransport),
      verificationShares: [...fx.verificationShares, fx.verificationShares[0]!],
    });
    const e = await failure(c.sign(MSG, fx.allow()));
    expect(e).toBeInstanceOf(CoordinatorError);
    expect(e.message).toBe('coordinator: missing a verification share for a signer in the set');
  });
  it('round 2: refusals and unreachable signers are recorded; threshold message is exact', async () => {
    const fx = fixture();
    const bad = issueAllowToken(generateKeyPair().secretKey, { message: MSG, groupPublicKey: fx.kg.groupPublicKey });
    const e = await failure(coord(fx, fx.svcs.map(inProcessTransport)).sign(MSG, bad));
    expect(e.message).toBe('coordinator: round 2 produced 0 share(s), need t=2');
    expect(e.refusals).toEqual([
      { identifier: 1, reason: 'policy authorization failed: allow token not signed by the trusted policy authority' },
      { identifier: 2, reason: 'policy authorization failed: allow token not signed by the trusted policy authority' },
    ]);
    const fx2 = fixture();
    const ts = [
      wrap(fx2.svcs[0]!, { round2: () => Promise.reject(new Error('hung up')) }),
      wrap(fx2.svcs[1]!, { round2: () => Promise.reject(42) }),
    ];
    const e2 = await failure(coord(fx2, ts).sign(MSG, fx2.allow()));
    expect(e2.refusals).toEqual([
      { identifier: 1, reason: 'hung up' },
      { identifier: 2, reason: 'unreachable' },
    ]);
  });
  it('round 2: a malformed signature share is dropped with its own refusal', async () => {
    const fx = fixture();
    const ts = [
      wrap(fx.svcs[0]!),
      wrap(fx.svcs[1]!, {
        round2: async (r) => {
          const x = fx.svcs[1]!.round2(r);
          return x.ok ? { ...x, sig_share: 'zz' } : x;
        },
      }),
    ];
    const e = await failure(coord(fx, ts).sign(MSG, fx.allow()));
    expect(e.message).toBe('coordinator: round 2 produced 1 share(s), need t=2');
    expect(e.refusals).toEqual([{ identifier: 2, reason: 'malformed signature share' }]);
  });
  it('aggregation verifies each share and names the bad participant', async () => {
    const fx = fixture();
    const ts = [
      wrap(fx.svcs[0]!),
      wrap(fx.svcs[1]!, {
        round2: async (r) => {
          const x = fx.svcs[1]!.round2(r);
          if (!x.ok) return x;
          const s = bytesToScalar(Uint8Array.from(Buffer.from(x.sig_share, 'base64url')));
          return { ...x, sig_share: b64u(scalarToBytes(s + 1n)) };
        },
      }),
    ];
    const e = await failure(coord(fx, ts).sign(MSG, fx.allow()));
    expect(e.message).toBe('frostAggregate: invalid signature share from participant 2');
  });
  it('the aggregate is verified against only the set (extra verification shares are harmless)', async () => {
    const fx = fixture(2, 4);
    const res = await coord(fx, fx.svcs.map(inProcessTransport)).sign(MSG, fx.allow());
    expect(res.signers).toEqual([1, 2]);
  });

  describe('deadline', () => {
    const hang = (svc: GuardianSignerService): SignerTransport => wrap(svc, { round1: () => new Promise<never>(() => undefined) });
    it('constructor-level timeout aborts with a typed error carrying the window', async () => {
      const fx = fixture();
      const c = coord(fx, [hang(fx.svcs[0]!), hang(fx.svcs[1]!)], { timeoutMs: 30 });
      const e = (await failure(c.sign(MSG, fx.allow()))) as CoordinatorTimeoutError;
      expect(e).toBeInstanceOf(CoordinatorTimeoutError);
      expect(e).toBeInstanceOf(CoordinatorError);
      expect(e.name).toBe('CoordinatorTimeoutError');
      expect(e.message).toBe('coordinator: signing session did not reach threshold within 30ms');
      expect(e.timeoutMs).toBe(30);
      expect(e.refusals).toEqual([]);
    });
    it('per-call timeout overrides the constructor value', async () => {
      const fx = fixture();
      const c = coord(fx, [hang(fx.svcs[0]!), hang(fx.svcs[1]!)], { timeoutMs: 60_000 });
      const e = (await failure(c.sign(MSG, fx.allow(), { timeoutMs: 25 }))) as CoordinatorTimeoutError;
      expect(e.timeoutMs).toBe(25);
    });
    it('CoordinatorError default refusals is empty', () => {
      expect(new CoordinatorError('x').refusals).toEqual([]);
      expect(new CoordinatorTimeoutError('x', 5).refusals).toEqual([]);
      expect(new CoordinatorTimeoutError('x', 5, [{ identifier: 1, reason: 'r' }]).refusals).toEqual([{ identifier: 1, reason: 'r' }]);
    });
    it('a non-positive or non-finite per-call window means no deadline', async () => {
      for (const w of [0, -5, NaN, Infinity]) {
        const fx = fixture();
        const res = await coord(fx, fx.svcs.map(inProcessTransport)).sign(MSG, fx.allow(), { timeoutMs: w });
        expect(res.signature.length).toBe(64);
      }
    });
    it('the deadline timer is cleared after a successful run', async () => {
      const handles: unknown[] = [];
      const realSet = globalThis.setTimeout;
      vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms: number, ...a: unknown[]) => {
        const h = (realSet as (...x: unknown[]) => unknown)(fn, ms, ...a);
        if (ms === 4321) handles.push(h);
        return h;
      }) as never);
      const cleared: unknown[] = [];
      const realClear = globalThis.clearTimeout;
      vi.spyOn(globalThis, 'clearTimeout').mockImplementation(((h: never) => {
        cleared.push(h);
        return realClear(h);
      }) as never);
      const fx = fixture();
      await coord(fx, fx.svcs.map(inProcessTransport), { timeoutMs: 4321 }).sign(MSG, fx.allow());
      expect(handles.length).toBe(1);
      expect(cleared).toContain(handles[0]);
    });
    it('late settlement of the aborted run is swallowed (no unhandled rejection)', async () => {
      const fx = fixture();
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      const slow = (svc: GuardianSignerService): SignerTransport =>
        wrap(svc, { round1: async () => { await gate; throw new Error('late'); } });
      const unhandled: unknown[] = [];
      const h = (e: unknown) => unhandled.push(e);
      process.on('unhandledRejection', h);
      try {
        const c = coord(fx, [slow(fx.svcs[0]!), slow(fx.svcs[1]!)], { timeoutMs: 20 });
        await failure(c.sign(MSG, fx.allow()));
        release();
        await new Promise((r) => setTimeout(r, 50));
        expect(unhandled).toEqual([]);
      } finally {
        process.off('unhandledRejection', h);
      }
    });
  });
});
