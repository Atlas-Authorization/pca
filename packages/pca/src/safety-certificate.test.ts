import { describe, expect, it } from 'vitest';
import {
  SAFETY_CERT_VERSION,
  decodeSafetyCertificate,
  encodeSafetyCertificate,
  issueSafetyCertificate,
  safetyCertificateBound,
  verifySafetyCertificate,
} from './safety-certificate';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY, type RiskPolicy } from './risk';

const G = generateKeyPair();
const policy = (over: Partial<RiskPolicy> = {}): RiskPolicy => ({ ...DEFAULT_RISK_POLICY, ...over });

describe('safety certificate — the provable bound', () => {
  it('certifies exactly B_max / κ', () => {
    const cert = issueSafetyCertificate({ policy: policy({ bMax: 3, kappa: 2 }), guardianSecret: G.secretKey, issuedAt: 1 });
    expect(cert.v).toBe(SAFETY_CERT_VERSION);
    expect(cert.bound).toBe(1.5);
    expect(cert.blastRadiusPerCheckpoint).toBe(1.5);
    expect(safetyCertificateBound({ bMax: 3, kappa: 2 })).toBe(1.5);
    expect(cert.guardian).toBe(encodeKey(G.publicKey));
    expect(cert.statement).toContain('1.5');
  });

  it('verifies and round-trips through encode/decode', () => {
    const cert = issueSafetyCertificate({ policy: policy(), guardianSecret: G.secretKey, grantRef: 'g1', instance: 'ins-1', issuedAt: 1 });
    const v = verifySafetyCertificate(cert);
    expect(v.ok).toBe(true);
    expect(v.recomputedBound).toBe(1); // bMax 1 / κ 1
    const wire = encodeSafetyCertificate(cert);
    const back = decodeSafetyCertificate(wire);
    expect(back).toEqual(cert);
    expect(verifySafetyCertificate(back!).ok).toBe(true);
  });

  it('issuing is deterministic (Ed25519 + canonical body)', () => {
    const a = issueSafetyCertificate({ policy: policy({ bMax: 2, kappa: 1 }), guardianSecret: G.secretKey, grantRef: 'g', issuedAt: 7 });
    const b = issueSafetyCertificate({ policy: policy({ bMax: 2, kappa: 1 }), guardianSecret: G.secretKey, grantRef: 'g', issuedAt: 7 });
    expect(a).toEqual(b);
  });
});

describe('safety certificate — tamper evidence', () => {
  const cert = issueSafetyCertificate({ policy: policy({ bMax: 2, kappa: 2 }), guardianSecret: G.secretKey, issuedAt: 1 });

  it('verifies the untouched certificate', () => {
    expect(verifySafetyCertificate(cert).ok).toBe(true);
    expect(cert.bound).toBe(1);
  });

  it('tampering a bound-determining parameter breaks the recomputed-bound check', () => {
    expect(verifySafetyCertificate({ ...cert, params: { ...cert.params, bMax: 99 } }).ok).toBe(false);
    expect(verifySafetyCertificate({ ...cert, params: { ...cert.params, kappa: 1 } }).ok).toBe(false);
  });

  it('tampering the stated bound is rejected', () => {
    const v = verifySafetyCertificate({ ...cert, bound: 999 });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/bound/);
    expect(verifySafetyCertificate({ ...cert, blastRadiusPerCheckpoint: 999 }).ok).toBe(false);
  });

  it('tampering a NON-bound parameter breaks the guardian signature (sig covers every parameter)', () => {
    const v = verifySafetyCertificate({ ...cert, params: { ...cert.params, theta1: 0.01 } });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/signature/);
    expect(verifySafetyCertificate({ ...cert, params: { ...cert.params, weights: { ...cert.params.weights, alpha: 0.99 } } }).ok).toBe(false);
  });

  it('tampering the signature or forging the guardian is rejected', () => {
    const flipped = cert.sig.slice(0, -1) + (cert.sig.endsWith('A') ? 'B' : 'A');
    expect(verifySafetyCertificate({ ...cert, sig: flipped }).ok).toBe(false);
    expect(verifySafetyCertificate(cert, { guardian: encodeKey(generateKeyPair().publicKey) }).ok).toBe(false);
    expect(verifySafetyCertificate(cert, { guardian: cert.guardian }).ok).toBe(true);
  });

  it('malformed input / policy is handled without throwing', () => {
    expect(() => issueSafetyCertificate({ policy: policy({ kappa: 0 }), guardianSecret: G.secretKey })).toThrow();
    expect(decodeSafetyCertificate('not json')).toBeNull();
    expect(decodeSafetyCertificate('{"v":2}')).toBeNull();
    expect(verifySafetyCertificate({} as never).ok).toBe(false);
  });
});

describe('safety certificate — monotonicity (stricter κ ⇒ tighter bound)', () => {
  it('a larger κ yields a strictly smaller certified blast radius', () => {
    const loose = issueSafetyCertificate({ policy: policy({ bMax: 1, kappa: 1 }), guardianSecret: G.secretKey, issuedAt: 1 });
    const strict = issueSafetyCertificate({ policy: policy({ bMax: 1, kappa: 2 }), guardianSecret: G.secretKey, issuedAt: 1 });
    const stricter = issueSafetyCertificate({ policy: policy({ bMax: 1, kappa: 4 }), guardianSecret: G.secretKey, issuedAt: 1 });
    expect(loose.bound).toBe(1);
    expect(strict.bound).toBe(0.5);
    expect(stricter.bound).toBe(0.25);
    expect(strict.bound).toBeLessThan(loose.bound);
    expect(stricter.bound).toBeLessThan(strict.bound);
    expect(verifySafetyCertificate(loose).ok).toBe(true);
    expect(verifySafetyCertificate(strict).ok).toBe(true);
    expect(verifySafetyCertificate(stricter).ok).toBe(true);
  });
});
