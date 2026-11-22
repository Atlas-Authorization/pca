import { beforeAll, describe, expect, it } from 'vitest';
import { SignJWT, generateKeyPair, type JWTPayload, type KeyLike } from 'jose';
import { IDJAG_AUTHORITY_CAVEAT, IdJagVerificationError, isIdJagAuthorityCaveat, jwtBearerAssertion, tokenExchangeRequest, verifyIdJag, type VerifyIdJagOptions } from './index';

const ISS = 'https://idp.example.com';
const AUD = 'https://resource.example.com';
let priv: KeyLike;
let pub: KeyLike;
beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA', { extractable: true });
  priv = kp.privateKey;
  pub = kp.publicKey;
});
const mint = (over: Record<string, unknown> = {}) => {
  const now = Math.floor(Date.now() / 1000);
  const claims: JWTPayload = { iss: ISS, sub: 'u', aud: AUD, iat: now, exp: now + 300, jti: 'j1', client_id: 'rc', act: { sub: 'ag' }, scope: 'a b', ...over };
  return new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', typ: 'oauth-id-jag+jwt' }).sign(priv);
};
const loose = (o: Partial<VerifyIdJagOptions> = {}): VerifyIdJagOptions => ({ issuer: ISS, audience: AUD, key: pub, strictDraft: false, ...o });

describe('single-audience refusal', () => {
  it('names the rule when a second audience is present', async () => {
    const err = await verifyIdJag(await mint({ aud: [AUD, 'https://extra.example.com'], azp: AUD }), loose()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IdJagVerificationError);
    expect((err as IdJagVerificationError).code).toBe('audience');
    expect((err as Error).message).toBe('ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)');
  });
});

describe('scope parsing keeps only real strings', () => {
  const scopes = async (over: Record<string, unknown>) => (await verifyIdJag(await mint(over), loose())).scopes;
  it('drops arrays, objects with a length and null from the scope array', async () => {
    expect(await scopes({ scope: ['a', ['x'], { length: 3 }, null, 'b'] })).toEqual(['a', 'b']);
  });
  it('drops arrays, objects with a length and null from the scopes array', async () => {
    expect(await scopes({ scope: undefined, scopes: ['x', ['z'], { length: 3 }, null, 'y'] })).toEqual(['x', 'y']);
  });
});

describe('isIdJagAuthorityCaveat audience', () => {
  it('requires a string audience, not a non-empty array or array-like', () => {
    const ok = { type: IDJAG_AUTHORITY_CAVEAT, scopes: ['a'], aud: 'x' };
    expect(isIdJagAuthorityCaveat(ok)).toBe(true);
    expect(isIdJagAuthorityCaveat({ ...ok, aud: ['x'] })).toBe(false);
    expect(isIdJagAuthorityCaveat({ ...ok, aud: { length: 1 } })).toBe(false);
  });
});

describe('the scope parameter of the request builders keeps only real strings', () => {
  it('drops non-string members before joining', () => {
    const scope = ['a', ['x'], { length: 3 }, 'b'] as unknown as string[];
    expect(tokenExchangeRequest({ tokenEndpoint: 'https://idp.example/token', subjectToken: 'st', scope }).params.scope).toBe('a b');
    expect(jwtBearerAssertion({ tokenEndpoint: 'https://idp.example/token', assertion: 'as', scope }).request.params.scope).toBe('a b');
  });
});
