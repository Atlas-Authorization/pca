import { describe, expect, it } from 'vitest';
import { canonicalBytesStrict, encodeKey, encodeSig, generateKeyPair, sign } from '@atlasauth/pca';
import { RUNTIME_CLAIM_DOMAIN, passportDigest, verifiedRuntimeClass, type ClaimTrust } from './index';

const kp = generateKeyPair();
const PD = passportDigest({ agent: 'a1' });
const trust = (over: Partial<ClaimTrust> = {}): ClaimTrust => ({ pinnedAttestors: [encodeKey(kp.publicKey)], passportDigest: PD, verifiedEvidenceDigests: ['ev1'], now: 1, ...over });
const FULL = { v: 1, class: 'wasi_no_ambient', passport_digest: PD, evidence_digest: 'ev1', iat: 0, exp: 10, attestor: encodeKey(kp.publicKey) };
/** Signed over exactly the members of `unsigned`. */
function signed(unsigned: Record<string, unknown>): Record<string, unknown> {
  const d = new TextEncoder().encode(RUNTIME_CLAIM_DOMAIN);
  return { ...unsigned, sig: encodeSig(sign(kp.secretKey, Uint8Array.from([...d, ...canonicalBytesStrict(unsigned)]))) };
}

describe('verifiedRuntimeClass claim shape', () => {
  it('the control claim proves its class', () => {
    expect(verifiedRuntimeClass(signed(FULL), trust())).toBe('wasi_no_ambient');
  });
  it('a function carrying the eight members is not a claim object', () => {
    const asFunction = Object.assign(() => undefined, signed(FULL));
    expect(verifiedRuntimeClass(asFunction, trust())).toBe('none');
  });
  it('members read from the prototype do not complete a claim that has fewer than eight own members', () => {
    const { exp, ...rest } = FULL;
    const own = signed(rest);
    const viaProto = Object.assign(Object.create({ exp }), own);
    expect(Object.keys(viaProto)).toHaveLength(7);
    expect(viaProto.exp).toBe(10);
    expect(verifiedRuntimeClass(viaProto, trust())).toBe('none');
  });
  it('an evidence digest that is not a string is refused even when the trust list holds that very value', () => {
    expect(verifiedRuntimeClass(signed({ ...FULL, evidence_digest: 5 }), trust({ verifiedEvidenceDigests: [5 as never] }))).toBe('none');
  });
});
