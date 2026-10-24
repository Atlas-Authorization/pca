/**
 * r12 mutation kill for attest-proved.ts: when the expected binding cannot be built because something other than an Error is
 * thrown, the refusal still names the cause as 'invalid' (an Error keeps its own message).
 */
import { describe, expect, it } from 'vitest';
import { verifyAttestationProved } from './attest-proved';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';

const T = 5_000_000;
const expectedThrowing = (thrown: unknown): ExpectedAttestationBinding =>
  ({
    get holderPub(): string {
      throw thrown;
    },
    grantRef: 'grant-ref-1',
    epoch: 1,
    nonce: 'q3Vx8mZ0aT7bLk2RwYp9Hs',
    nonceIssuedAt: T - 1000,
  }) as never;
const run = (expected: ExpectedAttestationBinding) =>
  verifyAttestationProved({ document: { nonce: 'n' } as unknown as AttestationDocument, ctx: {}, expected, nowMs: T, trustedAttestorKeys: [] });

describe('attest-proved: binding-construction refusal reason', () => {
  it('a non-Error thrown while building the binding is reported as invalid', async () => {
    const v = await run(expectedThrowing('boom'));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('attestation binding not constructible: invalid');
  });
  it('an Error keeps its own message', async () => {
    const v = await run(expectedThrowing(new Error('bad holder')));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('attestation binding not constructible: bad holder');
  });
});
