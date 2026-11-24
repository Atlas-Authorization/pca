import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseAuthenticatorData, verifyAssertion } from './index';

// Assertions captured from real authenticators (fixtures/captured-authenticators.json, from the MIT-licensed test fixtures
// of SimpleWebAuthn; see fixtures/LICENSE-simplewebauthn-fixtures). Every row is judged by this package AND by an
// independent library (libraryVerdict); they must agree, with exact whole-result outcomes.

interface Row {
  name: string;
  rpId: string;
  origin: string;
  challenge: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  publicKey: string;
  storedSignCount: number;
  libraryVerdict: boolean;
}
const rows = (JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'captured-authenticators.json'), 'utf8')) as { cases: Row[] }).cases;
const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const run = (r: Row, over: Record<string, unknown> = {}) =>
  verifyAssertion(
    { authenticatorData: bytes(r.authenticatorData), clientDataJSON: bytes(r.clientDataJSON), signature: bytes(r.signature), publicKey: bytes(r.publicKey) },
    { expectedChallenge: r.challenge, rpId: r.rpId, origins: [r.origin], requireUV: false, storedSignCount: r.storedSignCount, ...over },
  );

const EXPECT = [
  { ok: true, alg: 'ES256', signCount: 144, flags: { up: true, uv: false, be: false, bs: false, at: false, ed: false } },
  { ok: true, alg: 'ES256', signCount: 0, flags: { up: true, uv: false, be: false, bs: false, at: false, ed: false } },
  { ok: false, reason: 'assertion signature did not verify' },
  { ok: true, alg: 'ES256', signCount: 1643868837, flags: { up: true, uv: true, be: false, bs: false, at: false, ed: false } },
];

describe('real-authenticator assertions', () => {
  it('the fixture has the four rows', () => {
    expect(rows.length).toBe(4);
    expect(rows.map((r) => r.libraryVerdict)).toEqual([true, true, false, true]);
  });
  rows.forEach((r, i) => {
    it(`agrees with the independent library, exact result: ${r.name}`, () => {
      const res = run(r);
      expect(res).toEqual(EXPECT[i]);
      expect(res.ok).toBe(r.libraryVerdict);
    });
  });

  it('a UV-requiring relying party refuses the two UP-only authenticators', () => {
    for (const i of [0, 1]) expect(run(rows[i]!, { requireUV: true })).toEqual({ ok: false, reason: 'User Verified (UV) flag is required but not set' });
  });

  it('a replay of the counter-bearing assertion is refused once its counter is stored', () => {
    expect(run(rows[0]!, { storedSignCount: 144 })).toEqual({ ok: false, reason: 'signCount did not increase (possible cloned authenticator)' });
    expect(run(rows[0]!, { storedSignCount: 143 }).ok).toBe(true);
  });

  it('the wrong relying party, origin or challenge is refused', () => {
    const r = rows[0]!;
    expect(run(r, { rpId: 'other.example' })).toEqual({ ok: false, reason: 'rpIdHash does not match sha256(rpId)' });
    expect(run(r, { origins: ['https://evil.example'] })).toEqual({ ok: false, reason: 'clientData.origin "https://dev.dontneeda.pw" is not in the allowlist' });
    expect(run(r, { expectedChallenge: rows[1]!.challenge })).toEqual({ ok: false, reason: 'clientData.challenge does not match the step-up challenge' });
  });

  it('a flipped bit anywhere in the signature or authenticator data is refused', () => {
    const r = rows[0]!;
    const sig = bytes(r.signature);
    sig[10] = (sig[10] ?? 0) ^ 1;
    const res = verifyAssertion(
      { authenticatorData: bytes(r.authenticatorData), clientDataJSON: bytes(r.clientDataJSON), signature: sig, publicKey: bytes(r.publicKey) },
      { expectedChallenge: r.challenge, rpId: r.rpId, origins: [r.origin], requireUV: false, storedSignCount: 143 },
    );
    expect(res.ok).toBe(false);
  });

  it('the Android row carries extension data (ED) that the header parser reports without decoding it', () => {
    const p = parseAuthenticatorData(bytes(rows[2]!.authenticatorData));
    expect(p?.flags).toEqual({ up: true, uv: true, be: false, bs: false, at: false, ed: true });
    expect(p?.signCount).toBe(0);
  });
});
