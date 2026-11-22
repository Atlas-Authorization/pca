import { createHash } from 'node:crypto';
import { CompactSign, SignJWT, exportJWK, generateKeyPair as joseGen, type JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { verifyPcaSdJwt } from './index';

const NON_FINITE = { ok: false, reason: 'now, clockToleranceSec and kbMaxAgeSec must be finite' };

const b64u = (s: string | Uint8Array) => Buffer.from(s).toString('base64url');
const sha = (s: string) => createHash('sha256').update(s, 'ascii').digest().toString('base64url');
const NOW = 1_800_000_000; // seconds

type JoseKeyPair = Awaited<ReturnType<typeof joseGen>>;
let ISS: JoseKeyPair;
let HOLD: JoseKeyPair & { jwk: JWK };
beforeAll(async () => {
  ISS = await joseGen('EdDSA', { extractable: true });
  const h = await joseGen('EdDSA', { extractable: true });
  HOLD = { privateKey: h.privateKey, publicKey: h.publicKey, jwk: await exportJWK(h.publicKey) };
});

async function withKb(): Promise<string> {
  const dB = b64u(JSON.stringify(['sb', 'b', 2]));
  const payload = { iss: 'https://iss', aud: 'rs', iat: NOW, exp: NOW + 3600, _sd_alg: 'sha-256', _sd: [sha(dB)], cnf: { jwk: HOLD.jwk } };
  const jwt = await new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', typ: 'pca+sd-jwt' } as never).sign(ISS.privateKey);
  const sd = [jwt, dB].join('~') + '~';
  const kb = await new SignJWT({ iat: NOW, aud: 'rs', sd_hash: sha(sd), nonce: 'n1' }).setProtectedHeader({ alg: 'EdDSA', typ: 'kb+jwt' } as never).sign(HOLD.privateKey);
  return sd + kb;
}
const verify = async (sd: string, o: Record<string, unknown>) => verifyPcaSdJwt(sd, { issuerKey: ISS.publicKey, now: NOW * 1000, kbMaxAgeSec: 100, ...o } as never);

describe('a KB-JWT freshness check with a non-finite clock or tolerance never admits', () => {
  it('a finite clock admits the fresh KB-JWT', async () => {
    expect((await verify(await withKb(), {})).ok).toBe(true);
  });
  // pre-fix: `iat - nowSec > tolerance` was false for a NaN operand, so the future-iat check was skipped
  it('clockToleranceSec of NaN', async () => {
    expect(await verify(await withKb(), { clockToleranceSec: Number.NaN })).toEqual(NON_FINITE);
  });
  it.each([Number.NaN, Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY])('now of %s', async (now) => {
    expect(await verify(await withKb(), { now })).toEqual(NON_FINITE);
  });
  // old code: with an infinite tolerance and a -Infinity clock both KB-JWT checks and the issuer expiry check passed
  it('an infinite tolerance is refused, alone or with an infinite clock', async () => {
    for (const o of [{ clockToleranceSec: Number.POSITIVE_INFINITY }, { clockToleranceSec: Number.POSITIVE_INFINITY, now: Number.NEGATIVE_INFINITY }]) {
      expect(await verify(await withKb(), o)).toEqual(NON_FINITE);
    }
  });
  // old code: an infinite window disabled the age limit
  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.NaN])('kbMaxAgeSec of %s', async (kbMaxAgeSec) => {
    expect(await verify(await withKb(), { kbMaxAgeSec })).toEqual(NON_FINITE);
  });
});

describe('an unrepresentable clock and a non-finite KB-JWT iat never admit', () => {
  // pre-fix: new Date(1e300) is an invalid Date, which jose read as no clock (ok: true)
  it.each([1e300, -1e300, 8.64e15 + 1])('now of %s', async (now) => {
    expect(await verify(await withKb(), { now })).toEqual({ ok: false, reason: 'now is not a representable time' });
  });
  // pre-fix: nowSec - Infinity > window was false
  it.each(['1e999', '-1e999'])('a KB-JWT iat of %s', async (iat) => {
    const dB = b64u(JSON.stringify(['sb', 'b', 2]));
    const payload = { iss: 'https://iss', aud: 'rs', iat: NOW, exp: NOW + 3600, _sd_alg: 'sha-256', _sd: [sha(dB)], cnf: { jwk: HOLD.jwk } };
    const jwt = await new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', typ: 'pca+sd-jwt' } as never).sign(ISS.privateKey);
    const sd = [jwt, dB].join('~') + '~';
    const body = `{"iat":${iat},"aud":"rs","sd_hash":"${sha(sd)}","nonce":"n1"}`;
    const kb = await new CompactSign(new TextEncoder().encode(body)).setProtectedHeader({ alg: 'EdDSA', typ: 'kb+jwt' } as never).sign(HOLD.privateKey);
    expect((await verify(sd + kb, {})).ok).toBe(false);
  });
});
