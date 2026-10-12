/** Site kill (index.ts:455): verifyRequestSignature's outer catch returns exactly false (never undefined). */
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyRequestSignature } from './index';

describe('verifyRequestSignature fail-closed catch', () => {
  it('malformed @signature-params (parseComponents throws) gives false', () => {
    const { publicKey } = generateKeyPairSync('ed25519');
    const args = { method: 'GET', url: 'https://api.example/x', headers: {}, signatureInput: 'sig1=bad', signature: 'sig1=:AA==:' };
    expect(verifyRequestSignature(args, publicKey)).toBe(false);
    expect(verifyRequestSignature({ ...args, signatureInput: 'sig1=(bad)' }, publicKey)).toBe(false);
  });
});
