import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { signRequest, verifySignedRequest, buildKeyDirectory, jwkThumbprint } from './index';

const key = generateKeyPair();
const keyid = jwkThumbprint(key.publicKey);
const jwks = buildKeyDirectory([{ publicKey: key.publicKey, keyid }]);
const now = 1_800_000_000;

describe('RFC 9421 §2.2.5 @request-target', () => {
  it('is the origin-form target: path plus query', async () => {
    const url = 'https://api.example.com/foo?param=Value&Pet=dog';
    const s = signRequest({ method: 'GET', url, key, keyid, created: now, components: ['@authority', '@method', '@request-target'] });
    expect(s.covered).toEqual(['@authority', '@method', '@request-target']);
    const opts = { jwks, now, requiredComponents: ['@authority', '@method', '@request-target'] };
    expect((await verifySignedRequest({ method: 'GET', url, headers: s.headers }, opts)).valid).toBe(true);
    // A different query or path is a different request target.
    expect((await verifySignedRequest({ method: 'GET', url: 'https://api.example.com/foo?param=Value&Pet=cat', headers: s.headers }, opts)).valid).toBe(false);
    expect((await verifySignedRequest({ method: 'GET', url: 'https://api.example.com/bar?param=Value&Pet=dog', headers: s.headers }, opts)).valid).toBe(false);
  });

  it('is "/" for an empty path and carries no "?" without a query', async () => {
    const s = signRequest({ method: 'GET', url: 'https://api.example.com', key, keyid, created: now, components: ['@authority', '@request-target'] });
    const opts = { jwks, now, requiredComponents: ['@authority', '@request-target'] };
    expect((await verifySignedRequest({ method: 'GET', url: 'https://api.example.com/', headers: s.headers }, opts)).valid).toBe(true);
    expect((await verifySignedRequest({ method: 'GET', url: 'https://api.example.com/?', headers: s.headers }, opts)).valid).toBe(true);
    expect((await verifySignedRequest({ method: 'GET', url: 'https://api.example.com/?a=1', headers: s.headers }, opts)).valid).toBe(false);
  });
});
