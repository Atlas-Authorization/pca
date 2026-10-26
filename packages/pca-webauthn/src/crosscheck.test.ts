/**
 * Agreement with an established library: fixtures/simplewebauthn.json holds assertions (ES256 and EdDSA, valid and
 * tampered) with the verdict @simplewebauthn/server gave each one. Our verifier must reach the same verdict on every row.
 * Regenerate with crosscheck/gen-simplewebauthn.mjs.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifyAssertion } from './index';

interface Row {
  name: string; authenticatorData: string; clientDataJSON: string; signature: string; cose: string;
  expectedChallenge: string; origin: string; rpId: string; requireUV: boolean; storedSignCount: number; simplewebauthn: boolean;
}
const fx = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', 'simplewebauthn.json'), 'utf8')) as { library: string; version: string; cases: Row[] };
const bytes = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

describe(`verdicts agree with ${fx.library}`, () => {
  it('fixture is non-trivial (both accepts and rejects, both algorithms)', () => {
    expect(fx.cases.length).toBe(26);
    expect(fx.cases.filter((c) => c.simplewebauthn).length).toBe(6);
  });
  it.each(fx.cases.map((c) => [c.name, c] as const))('%s', (_n, c) => {
    const r = verifyAssertion(
      { authenticatorData: bytes(c.authenticatorData), clientDataJSON: bytes(c.clientDataJSON), signature: bytes(c.signature), publicKey: bytes(c.cose) },
      { expectedChallenge: c.expectedChallenge, rpId: c.rpId, origins: [c.origin], requireUV: c.requireUV, storedSignCount: c.storedSignCount },
    );
    expect(r.ok).toBe(c.simplewebauthn);
  });
});
