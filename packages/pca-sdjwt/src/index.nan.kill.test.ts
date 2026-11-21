import { createHash } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair as joseGen, type JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { verifyPcaSdJwt } from './index';

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
    expect(await verify(await withKb(), { clockToleranceSec: Number.NaN })).toEqual({ ok: false, reason: 'KB-JWT iat is in the future' });
  });
  it('clockToleranceSec of +Infinity', async () => {
    expect(await verify(await withKb(), { clockToleranceSec: Number.POSITIVE_INFINITY })).toEqual({ ok: false, reason: 'KB-JWT iat is in the future' });
  });
  it('kbMaxAgeSec of +Infinity (an unbounded window admits any age)', async () => {
    expect(await verify(await withKb(), { kbMaxAgeSec: Number.POSITIVE_INFINITY })).toEqual({ ok: false, reason: 'KB-JWT is older than the accepted window' });
  });
  it.each([Number.NaN, Number.NEGATIVE_INFINITY])('now of %s', async (now) => {
    expect((await verify(await withKb(), { now })).ok).toBe(false);
  });
});
