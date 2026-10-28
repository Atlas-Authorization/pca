/** Every fail-closed row of the README table, with the exact reason, plus the signature-counter rule. */
import { ed25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { b64u } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { type Assertion, type VerifyExpectations, verifyAssertion } from './index';

const RP = 'login.example.com';
const ORIGIN = 'https://login.example.com';
const CHALLENGE = new Uint8Array(32).fill(5);
const enc = (o: unknown) => new TextEncoder().encode(typeof o === 'string' ? o : JSON.stringify(o));

function authData(flags: number, signCount: number, rp = RP): Uint8Array {
  const out = new Uint8Array(37);
  out.set(sha256(enc(rp)), 0);
  out[32] = flags;
  new DataView(out.buffer).setUint32(33, signCount, false);
  return out;
}
const sk = p256.utils.randomPrivateKey();
const pub = p256.getPublicKey(sk, false);
const JWK = { kty: 'EC' as const, crv: 'P-256' as const, x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33)) };

interface Opts { flags?: number; signCount?: number; client?: unknown; rp?: string }
/** A valid ES256 assertion; each row mutates one thing and re-signs (unless it is testing the signature). */
function build(o: Opts = {}): { a: Assertion; e: VerifyExpectations } {
  const ad = authData(o.flags ?? 0x05, o.signCount ?? 1, o.rp);
  const cd = enc(o.client ?? { type: 'webauthn.get', challenge: b64u(CHALLENGE), origin: ORIGIN, crossOrigin: false });
  const sig = p256.sign(sha256(new Uint8Array([...ad, ...sha256(cd)])), sk).toDERRawBytes();
  return { a: { authenticatorData: ad, clientDataJSON: cd, signature: sig, publicKey: JWK }, e: { expectedChallenge: CHALLENGE, rpId: RP, origins: [ORIGIN], requireUV: true, storedSignCount: 0 } };
}
const run = (a: Assertion, e: VerifyExpectations) => verifyAssertion(a, e);
const no = (reason: string) => ({ ok: false, reason });
const cd = (over: Record<string, unknown>) => ({ type: 'webauthn.get', challenge: b64u(CHALLENGE), origin: ORIGIN, crossOrigin: false, ...over });

describe('failure modes (exact reasons)', () => {
  it('the baseline is accepted', () => {
    const { a, e } = build();
    expect(run(a, e)).toEqual({ ok: true, alg: 'ES256', signCount: 1, flags: { up: true, uv: true, be: false, bs: false, at: false, ed: false } });
  });

  it.each([
    ['authenticatorData not bytes', (b: ReturnType<typeof build>) => ({ ...b, a: { ...b.a, authenticatorData: 'x' as unknown as Uint8Array } }), 'authenticatorData is not bytes'],
    ['clientDataJSON not bytes', (b: ReturnType<typeof build>) => ({ ...b, a: { ...b.a, clientDataJSON: 'x' as unknown as Uint8Array } }), 'clientDataJSON is not bytes'],
    ['signature not bytes', (b: ReturnType<typeof build>) => ({ ...b, a: { ...b.a, signature: null as unknown as Uint8Array } }), 'signature is not bytes'],
    ['authenticatorData oversize', (b: ReturnType<typeof build>) => ({ ...b, a: { ...b.a, authenticatorData: new Uint8Array(4097) } }), 'authenticatorData is too large'],
    ['clientDataJSON oversize', (b: ReturnType<typeof build>) => ({ ...b, a: { ...b.a, clientDataJSON: new Uint8Array(8193) } }), 'clientDataJSON is too large'],
    ['signature oversize', (b: ReturnType<typeof build>) => ({ ...b, a: { ...b.a, signature: new Uint8Array(1025) } }), 'signature is too large'],
    ['empty rpId', (b: ReturnType<typeof build>) => ({ ...b, e: { ...b.e, rpId: '' } }), 'rpId is required'],
    ['empty origins', (b: ReturnType<typeof build>) => ({ ...b, e: { ...b.e, origins: [] } }), 'origins allowlist is empty'],
    ['undecodable expectedChallenge string', (b: ReturnType<typeof build>) => ({ ...b, e: { ...b.e, expectedChallenge: '!!' } }), 'expectedChallenge is not decodable'],
  ])('%s', (_n, mut, reason) => {
    const m = mut(build());
    expect(run(m.a, m.e)).toEqual(no(reason));
  });

  it.each([
    ['clientDataJSON not UTF-8', new Uint8Array([0xff, 0xfe]), 'clientDataJSON is not valid UTF-8'],
    ['clientDataJSON not JSON', enc('{nope'), 'clientDataJSON is not valid JSON'],
    ['clientDataJSON a JSON array', enc('[]'), 'clientDataJSON is not a JSON object'],
    ['clientDataJSON JSON null', enc('null'), 'clientDataJSON is not a JSON object'],
    ['type webauthn.create', enc(cd({ type: 'webauthn.create' })), 'clientData.type is not "webauthn.get" (webauthn.create)'],
    ['type missing', enc(cd({ type: undefined })), 'clientData.type is not "webauthn.get" (undefined)'],
    ['challenge missing', enc(cd({ challenge: undefined })), 'clientData.challenge is missing or not canonical base64url'],
    ['challenge not a string', enc(cd({ challenge: 5 })), 'clientData.challenge is missing or not canonical base64url'],
    ['challenge for another action', enc(cd({ challenge: b64u(new Uint8Array(32).fill(6)) })), 'clientData.challenge does not match the step-up challenge'],
    ['challenge truncated', enc(cd({ challenge: b64u(CHALLENGE.slice(0, 31)) })), 'clientData.challenge does not match the step-up challenge'],
    ['origin missing', enc(cd({ origin: undefined })), 'clientData.origin is missing'],
    ['origin a look-alike', enc(cd({ origin: 'https://login.example.com.evil.test' })), 'clientData.origin "https://login.example.com.evil.test" is not in the allowlist'],
    ['origin differs by port', enc(cd({ origin: 'https://login.example.com:8443' })), 'clientData.origin "https://login.example.com:8443" is not in the allowlist'],
  ])('%s', (_n, clientDataJSON, reason) => {
    const { a, e } = build();
    expect(run({ ...a, clientDataJSON }, e)).toEqual(no(reason));
  });

  it('crossOrigin true is refused by default; rejectCrossOrigin:false opts out; non-boolean values are refused', () => {
    const { a, e } = build({ client: cd({ crossOrigin: true }) });
    expect(run(a, e)).toEqual(no('clientData.crossOrigin is true'));
    expect(run(a, { ...e, rejectCrossOrigin: true })).toEqual(no('clientData.crossOrigin is true'));
    expect(run(a, { ...e, rejectCrossOrigin: false }).ok).toBe(true);
    for (const v of ['false', 0, null, 'true', 1]) {
      const b = build({ client: cd({ crossOrigin: v }) });
      expect(run(b.a, b.e), String(v)).toEqual(no('clientData.crossOrigin is not a boolean'));
      expect(run(b.a, { ...b.e, rejectCrossOrigin: false }).ok, String(v)).toBe(true);
    }
    const absent = build({ client: { type: 'webauthn.get', challenge: b64u(CHALLENGE), origin: ORIGIN } });
    expect(run(absent.a, absent.e).ok).toBe(true);
  });

  it('authenticatorData rows: short, wrong rpId, UP unset, UV missing when required', () => {
    let b = build();
    expect(run({ ...b.a, authenticatorData: b.a.authenticatorData.slice(0, 36) }, b.e)).toEqual(no('authenticatorData is too short (< 37 bytes)'));
    b = build({ rp: 'evil.test' });
    expect(run(b.a, b.e)).toEqual(no('rpIdHash does not match sha256(rpId)'));
    b = build({ flags: 0x04 });
    expect(run(b.a, b.e)).toEqual(no('User Present (UP) flag is not set'));
    b = build({ flags: 0x01 });
    expect(run(b.a, b.e)).toEqual(no('User Verified (UV) flag is required but not set'));
    expect(run(b.a, { ...b.e, requireUV: false }).ok).toBe(true);
  });

  it('signature rows: tampered, signed over other data, wrong key, wrong algorithm for the key', () => {
    const { a, e } = build();
    const bad = a.signature.slice();
    bad[bad.length - 1] = (bad[bad.length - 1] ?? 0) ^ 1;
    expect(run({ ...a, signature: bad }, e)).toEqual(no('assertion signature did not verify'));
    const other = build({ signCount: 2 });
    expect(run({ ...a, signature: other.a.signature }, e)).toEqual(no('assertion signature did not verify'));
    const otherPub = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
    const wrongKey = { kty: 'EC' as const, crv: 'P-256' as const, x: b64u(otherPub.slice(1, 33)), y: b64u(otherPub.slice(33)) };
    expect(run({ ...a, publicKey: wrongKey }, e)).toEqual(no('assertion signature did not verify'));
    // alg confusion: an Ed25519 signature presented against the P-256 credential key
    const edSk = ed25519.utils.randomPrivateKey();
    const edSig = ed25519.sign(new Uint8Array([...a.authenticatorData, ...sha256(a.clientDataJSON)]), edSk);
    expect(run({ ...a, signature: edSig }, e)).toEqual(no('assertion signature did not verify'));
    // and the reverse: a P-256 signature against an Ed25519 credential key
    const edPub = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: b64u(ed25519.getPublicKey(edSk)) };
    expect(run({ ...a, publicKey: edPub }, e)).toEqual(no('assertion signature did not verify'));
  });

  it.each([
    ['unsupported curve', { kty: 'EC', crv: 'P-384', x: 'AA', y: 'AA' }, 'public key could not be resolved: resolveKey: EC JWK is not P-256'],
    ['bad coordinates', { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }, 'public key could not be resolved: resolveKey: invalid EC JWK coordinates'],
    ['RSA', { kty: 'RSA', n: 'AA', e: 'AQ' }, 'public key could not be resolved: resolveKey: unsupported public key'],
    ['OKP not Ed25519', { kty: 'OKP', crv: 'X25519', x: 'AA' }, 'public key could not be resolved: resolveKey: OKP JWK is not Ed25519'],
  ])('credential key: %s', (_n, key, reason) => {
    const { a, e } = build();
    expect(run({ ...a, publicKey: key as unknown as Assertion['publicKey'] }, e)).toEqual(no(reason));
  });
});

describe('signature counter (clone detection)', () => {
  const ok = (signCount: number) => ({ ok: true, alg: 'ES256', signCount, flags: { up: true, uv: true, be: false, bs: false, at: false, ed: false } });
  it('absent storedSignCount is refused (the verifier keeps no counter state)', () => {
    const { a, e } = build({ signCount: 0 });
    const { storedSignCount: _omit, ...rest } = e;
    void _omit;
    const msg = 'storedSignCount is required (use 0 for a credential never used)';
    expect(run(a, rest as VerifyExpectations)).toEqual(no(msg));
    expect(run(a, { ...e, storedSignCount: undefined } as unknown as VerifyExpectations)).toEqual(no(msg));
    expect(run(a, { ...e, storedSignCount: null } as unknown as VerifyExpectations)).toEqual(no('storedSignCount is not a uint32'));
    expect(run(a, { ...e, storedSignCount: '0' } as unknown as VerifyExpectations)).toEqual(no('storedSignCount is not a uint32'));
    expect(run(a, e)).toEqual(ok(0));
  });
  it('increase passes; equal or lower is refused with the exact reason', () => {
    const msg = 'signCount did not increase (possible cloned authenticator)';
    const up = build({ signCount: 6 });
    expect(run(up.a, { ...up.e, storedSignCount: 5 })).toEqual(ok(6));
    for (const reported of [5, 4]) {
      const { a, e } = build({ signCount: reported });
      expect(run(a, { ...e, storedSignCount: 5 })).toEqual(no(msg));
    }
  });
  it('both zero means no counter and passes; stored non-zero with reported zero is a regression', () => {
    const { a, e } = build({ signCount: 0 });
    expect(run(a, { ...e, storedSignCount: 0 })).toEqual(ok(0));
    expect(run(a, { ...e, storedSignCount: 3 })).toEqual(no('signCount did not increase (possible cloned authenticator)'));
    const b = build({ signCount: 1 });
    expect(run(b.a, { ...b.e, storedSignCount: 0 })).toEqual(ok(1));
  });
  it('the hook gets the exact numbers, once, and only when the signature verified', () => {
    const calls: unknown[] = [];
    const { a, e } = build({ signCount: 2 });
    run(a, { ...e, storedSignCount: 9, onSignCountRegression: (i) => calls.push(i) });
    expect(calls).toEqual([{ storedSignCount: 9, reportedSignCount: 2 }]);
    calls.length = 0;
    const bad = a.signature.slice();
    bad[bad.length - 1] = (bad[bad.length - 1] ?? 0) ^ 1;
    run({ ...a, signature: bad }, { ...e, storedSignCount: 9, onSignCountRegression: (i) => calls.push(i) });
    expect(calls).toEqual([]);
  });
  it('a throwing hook still fails closed', () => {
    const { a, e } = build({ signCount: 2 });
    const r = run(a, { ...e, storedSignCount: 9, onSignCountRegression: () => { throw new Error('boom'); } });
    expect(r).toEqual(no('verification error (fail closed): boom'));
  });
  it.each([-1, 1.5, 2 ** 32, Number.NaN])('invalid storedSignCount %s is refused', (bad) => {
    const { a, e } = build();
    expect(run(a, { ...e, storedSignCount: bad })).toEqual(no('storedSignCount is not a uint32'));
  });
  it('uint32 max reported counter passes against a lower stored value', () => {
    const { a, e } = build({ signCount: 0xffffffff });
    expect(run(a, { ...e, storedSignCount: 0xfffffffe })).toEqual(ok(0xffffffff));
  });
});
