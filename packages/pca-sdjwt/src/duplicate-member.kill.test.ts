import { describe, expect, it } from 'vitest';
import { present } from './index';

// present() reads the issuer JWT payload without verifying it: a duplicate member there must be refused, not last-wins.
const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
const sdjwt = (payload: string) => `${b64u('{"alg":"EdDSA"}')}.${b64u(payload)}.${Buffer.alloc(64, 1).toString('base64url')}~`;

describe('pca-sdjwt issuer payload duplicate members', () => {
  it('is refused with the exact message', async () => {
    await expect(present(sdjwt('{"_sd":[],"_sd":["x"]}'), [])).rejects.toThrow('pca-sdjwt: issuer JWT payload is not valid base64url JSON');
  });
  it('accepts non-canonical numbers (8.0, 1e3)', async () => {
    await expect(present(sdjwt('{"a":8.0,"b":1e3,"_sd":[]}'), [])).resolves.toBe(sdjwt('{"a":8.0,"b":1e3,"_sd":[]}'));
  });
});
