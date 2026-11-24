import { describe, expect, it } from 'vitest';
import { present } from './index';

// present() reads the issuer JWT payload without verifying it: a duplicate member there must be refused, not last-wins.
const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
const sdjwt = (payload: string) => `${b64u('{"alg":"EdDSA"}')}.${b64u(payload)}.${Buffer.alloc(64, 1).toString('base64url')}~`;

// present() runs the canonical compact-JWS gate on the issuer JWT first (strict profile): a duplicate member, and a
// non-canonical number, are refused there, before the duplicate-only payload parse behind it.
const GATE = 'non-canonical compact JWS: bad-json (strict JSON: ';

describe('pca-sdjwt issuer payload duplicate members', () => {
  it('is refused by the canonical gate', async () => {
    await expect(present(sdjwt('{"_sd":[],"_sd":["x"]}'), [])).rejects.toThrow(`${GATE}duplicate key "_sd"`);
  });
  it('non-canonical numbers (8.0, 1e3) are refused by the canonical gate too', async () => {
    await expect(present(sdjwt('{"a":8.0,"_sd":[]}'), [])).rejects.toThrow(GATE);
    await expect(present(sdjwt('{"b":1e3,"_sd":[]}'), [])).rejects.toThrow(GATE);
  });
  it('the same payload written canonically is presented', async () => {
    await expect(present(sdjwt('{"a":8,"_sd":[]}'), [])).resolves.toBe(sdjwt('{"a":8,"_sd":[]}'));
  });
});
