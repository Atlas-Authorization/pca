/** keys.ts residual mutants: verify() only takes Uint8Array keys (noble would accept a hex string) and never throws. */
import { describe, expect, it } from 'vitest';
import { generateKeyPair, sign, verify } from './keys';

const kp = generateKeyPair();
const msg = new TextEncoder().encode('keys-mk');
const sig = sign(kp.secretKey, msg);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

describe('verify', () => {
  it('control: a valid signature verifies', () => {
    expect(verify(kp.publicKey, msg, sig)).toBe(true);
  });
  it('a hex-string public key is refused (only Uint8Array keys are accepted)', () => {
    expect(verify(hex(kp.publicKey) as never, msg, sig)).toBe(false);
  });
  it('a message that is not bytes is false, not a throw', () => {
    expect(verify(kp.publicKey, 'not hex' as never, sig)).toBe(false);
    expect(verify(kp.publicKey, { length: 3 } as never, sig)).toBe(false);
  });
});
