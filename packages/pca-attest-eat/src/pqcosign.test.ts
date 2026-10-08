import { describe, it, expect } from 'vitest';
import {
  mlDsa65Keygen,
  mlDsa87Keygen,
  generateKeyPair,
  type MeasuredIdentity,
  type SuiteSecretKeys,
} from '@atlasauth/pca';
import {
  PQCOSIGN_DOMAIN,
  DEFAULT_PQ_COSIGN_SUITE,
  PQ_COSIGN_SUITES,
  isPqCoSignSuite,
  canonicalVerdictBytes,
  verdictFromAppraisal,
  coSignAttestation,
  verifyCoSignedAttestation,
  type AttestationVerdict,
  type CoSignOptions,
  type PqCoSignedAttestation,
  type PqCoSignerPublicKey,
} from './pqcosign';
import { appraise, type EatClaims } from './index';

/**
 * Build a value of a declared type from a JSON literal WITHOUT a suppression cast: `JSON.parse` is typed
 * `any`, so assigning its result to a typed variable is a clean, cast-free way to construct the deliberately
 * malformed / out-of-type inputs these fail-closed tests need (no `as`, no written `any`).
 */
function fromJson<T>(json: string): T {
  const parsed: T = JSON.parse(json);
  return parsed;
}

// ── Fixtures ──────────────────────────────────────────────────────────────────────────────────

const MEASURED: MeasuredIdentity = {
  model_id: 'gpt-forge-7b',
  weights_digest: 'a'.repeat(64),
  weights_measured: true,
  runtime_measurement: 'b'.repeat(96),
  operator: 'c'.repeat(128),
};

const VERDICT: AttestationVerdict = {
  tier: 'affirming-hw-rooted',
  trustworthy: true,
  measured: MEASURED,
  measurement: 'b'.repeat(96),
  nonce: 'nonce-abc.123',
  iat: 1_700_000_000,
  issuer: 'atlas-verifier',
};

/** A fresh ML-DSA-65 key pair from random seed bytes. */
function mlDsaKeys(): SuiteSecretKeys {
  return { mlDsa: mlDsa65Keygen(new Uint8Array(32).map(() => Math.floor(Math.random() * 256))) };
}

/** ML-DSA-65 + an Ed25519 secret, for the hybrid suites. */
function hybridKeys(): SuiteSecretKeys {
  const ed = generateKeyPair();
  return { edSecret: ed.secretKey, mlDsa: mlDsa65Keygen(new Uint8Array(32).map(() => Math.floor(Math.random() * 256))) };
}

const NOW = 1_700_000_500_000;

// ── Registry / constants ────────────────────────────────────────────────────────────────────────

describe('PQ co-sign suite registry', () => {
  it('defaults to pure post-quantum ml-dsa-65', () => {
    expect(DEFAULT_PQ_COSIGN_SUITE).toBe('ml-dsa-65');
    expect(PQ_COSIGN_SUITES).toContain('ml-dsa-65');
  });

  it('refuses the classical-only ed25519 suite and unknown names', () => {
    expect(isPqCoSignSuite('ml-dsa-65')).toBe(true);
    expect(isPqCoSignSuite('hybrid-ed25519-ml-dsa-65')).toBe(true);
    expect(isPqCoSignSuite('ed25519')).toBe(false);
    expect(isPqCoSignSuite('nope')).toBe(false);
    expect(isPqCoSignSuite(42)).toBe(false);
    expect(isPqCoSignSuite(undefined)).toBe(false);
  });
});

// ── Canonical encoding ────────────────────────────────────────────────────────────────────────

describe('canonicalVerdictBytes', () => {
  it('is deterministic and domain-separated', () => {
    const a = canonicalVerdictBytes(VERDICT, NOW);
    const b = canonicalVerdictBytes({ ...VERDICT }, NOW);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
    const text = Buffer.from(a).toString('utf8');
    expect(text.startsWith(`{"typ":"${PQCOSIGN_DOMAIN}"`)).toBe(true);
    expect(JSON.parse(text).cosignedAt).toBe(NOW);
  });

  it('changes when any security-relevant field changes', () => {
    const base = Buffer.from(canonicalVerdictBytes(VERDICT, NOW));
    expect(base.equals(Buffer.from(canonicalVerdictBytes({ ...VERDICT, tier: 'affirming' }, NOW)))).toBe(false);
    expect(base.equals(Buffer.from(canonicalVerdictBytes({ ...VERDICT, trustworthy: false }, NOW)))).toBe(false);
    expect(base.equals(Buffer.from(canonicalVerdictBytes({ ...VERDICT, nonce: 'other' }, NOW)))).toBe(false);
    expect(base.equals(Buffer.from(canonicalVerdictBytes(VERDICT, NOW + 1)))).toBe(false);
  });
});

// ── Round-trip ──────────────────────────────────────────────────────────────────────────────────

describe('coSignAttestation / verifyCoSignedAttestation round-trip', () => {
  it('co-signs and verifies under ml-dsa-65 (default, pure PQ)', () => {
    const keys = mlDsaKeys();
    const signed = coSignAttestation(VERDICT, { secretKey: keys, now: NOW });
    expect(signed.suite).toBe('ml-dsa-65');
    expect(signed.cosig.pq_sig).toBeUndefined(); // pure PQ => single sig
    expect(signed.signer_pub.ed).toBeUndefined();
    const res = verifyCoSignedAttestation(signed, { now: NOW });
    expect(res.ok).toBe(true);
    expect(res.suite).toBe('ml-dsa-65');
    expect(res.verdict?.tier).toBe('affirming-hw-rooted');
  });

  it('co-signs and verifies under a hybrid suite (classical + PQ, both required)', () => {
    const keys = hybridKeys();
    const signed = coSignAttestation(VERDICT, { suite: 'hybrid-ed25519-ml-dsa-65', secretKey: keys, now: NOW });
    expect(signed.suite).toBe('hybrid-ed25519-ml-dsa-65');
    expect(typeof signed.cosig.pq_sig).toBe('string'); // hybrid => classical sig + pq_sig
    expect(typeof signed.signer_pub.ed).toBe('string');
    expect(verifyCoSignedAttestation(signed, { now: NOW }).ok).toBe(true);
  });

  it('co-signs and verifies under the nested-hybrid (SUF-CMA) suite', () => {
    const keys = hybridKeys();
    const signed = coSignAttestation(VERDICT, { suite: 'hybrid-nested-ed25519-ml-dsa-65', secretKey: keys, now: NOW });
    expect(verifyCoSignedAttestation(signed, { now: NOW }).ok).toBe(true);
  });

  it('co-signs and verifies under a category-5 suite (ml-dsa-87)', () => {
    const keys: SuiteSecretKeys = { mlDsa87: mlDsa87Keygen(new Uint8Array(32).map(() => Math.floor(Math.random() * 256))) };
    const signed = coSignAttestation(VERDICT, { suite: 'ml-dsa-87', secretKey: keys, now: NOW });
    expect(verifyCoSignedAttestation(signed, { now: NOW }).ok).toBe(true);
  });

  it('builds a verdict from an appraise() result + EAT claims and co-signs it', () => {
    const claims: EatClaims = {
      iss: 'atlas-verifier',
      iat: 1_700_000_000,
      eat_nonce: 'nonce-abc.123',
      measured: MEASURED,
    };
    const result = appraise(claims, { measurements: ['b'.repeat(96)] }, { issuers: ['atlas-verifier'] });
    const verdict = verdictFromAppraisal(result, claims);
    expect(verdict.tier).toBe(result.tier);
    expect(verdict.issuer).toBe('atlas-verifier');
    expect(verdict.nonce).toBe('nonce-abc.123');
    const signed = coSignAttestation(verdict, { secretKey: mlDsaKeys(), now: NOW });
    expect(verifyCoSignedAttestation(signed, { now: NOW }).ok).toBe(true);
  });
});

// ── Fail-closed cases ─────────────────────────────────────────────────────────────────────────

describe('verifyCoSignedAttestation fails closed', () => {
  it('rejects a tampered verdict field', () => {
    const signed = coSignAttestation(VERDICT, { secretKey: mlDsaKeys(), now: NOW });
    const tampered: PqCoSignedAttestation = { ...signed, verdict: { ...signed.verdict, tier: 'rejected' } };
    const res = verifyCoSignedAttestation(tampered, { now: NOW });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/does not verify/);
  });

  it('rejects a tampered trustworthy bit', () => {
    const signed = coSignAttestation(VERDICT, { secretKey: mlDsaKeys(), now: NOW });
    const tampered: PqCoSignedAttestation = { ...signed, verdict: { ...signed.verdict, trustworthy: false } };
    expect(verifyCoSignedAttestation(tampered, { now: NOW }).ok).toBe(false);
  });

  it('rejects a tampered co-sign timestamp (bound into the signature)', () => {
    const signed = coSignAttestation(VERDICT, { secretKey: mlDsaKeys(), now: NOW });
    const tampered: PqCoSignedAttestation = { ...signed, cosig: { ...signed.cosig, cosignedAt: NOW + 1 } };
    expect(verifyCoSignedAttestation(tampered, { now: NOW }).ok).toBe(false);
  });

  it('rejects a wrong public key (sig does not match the embedded key)', () => {
    const signed = coSignAttestation(VERDICT, { secretKey: mlDsaKeys(), now: NOW });
    const other = mlDsaKeys();
    const otherSigned = coSignAttestation(VERDICT, { secretKey: other, now: NOW });
    const swapped: PqCoSignedAttestation = { ...signed, signer_pub: otherSigned.signer_pub };
    const res = verifyCoSignedAttestation(swapped, { now: NOW });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/does not verify/);
  });

  it('rejects a stale co-signature beyond maxAgeMs', () => {
    const signed = coSignAttestation(VERDICT, { secretKey: mlDsaKeys(), now: NOW });
    const fresh = verifyCoSignedAttestation(signed, { now: NOW + 1000, maxAgeMs: 5000 });
    expect(fresh.ok).toBe(true);
    const stale = verifyCoSignedAttestation(signed, { now: NOW + 10_000, maxAgeMs: 5000 });
    expect(stale.ok).toBe(false);
    expect(stale.reason).toMatch(/stale/);
    expect(stale.ageMs).toBe(10_000);
  });

  it('rejects a co-signature with a future timestamp under a staleness gate', () => {
    const signed = coSignAttestation(VERDICT, { secretKey: mlDsaKeys(), now: NOW });
    const res = verifyCoSignedAttestation(signed, { now: NOW - 1000, maxAgeMs: 5000 });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/future/);
  });

  it('rejects an expectedSigner mismatch', () => {
    const signed = coSignAttestation(VERDICT, { secretKey: mlDsaKeys(), now: NOW });
    const other = coSignAttestation(VERDICT, { secretKey: mlDsaKeys(), now: NOW });
    const res = verifyCoSignedAttestation(signed, { now: NOW, expectedSigner: other.signer_pub.pq });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/expected signer/);
  });

  it('accepts a matching expectedSigner (string PQ key and full object)', () => {
    const keys = hybridKeys();
    const signed = coSignAttestation(VERDICT, { suite: 'hybrid-ed25519-ml-dsa-65', secretKey: keys, now: NOW });
    expect(verifyCoSignedAttestation(signed, { now: NOW, expectedSigner: signed.signer_pub.pq }).ok).toBe(true);
    const full: PqCoSignerPublicKey = signed.signer_pub;
    expect(verifyCoSignedAttestation(signed, { now: NOW, expectedSigner: full }).ok).toBe(true);
  });

  it('rejects a malformed artifact and a classical-only suite without throwing', () => {
    const signed = coSignAttestation(VERDICT, { secretKey: mlDsaKeys(), now: NOW });
    const badSuite = fromJson<PqCoSignedAttestation>(JSON.stringify({ ...signed, suite: 'ed25519' }));
    const res = verifyCoSignedAttestation(badSuite, { now: NOW });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/not an accepted post-quantum co-sign suite/);
    const noVerdict = fromJson<PqCoSignedAttestation>('{}');
    expect(verifyCoSignedAttestation(noVerdict, { now: NOW }).ok).toBe(false);
  });
});

describe('coSignAttestation fails closed on misconfiguration', () => {
  it('throws on a classical-only / unknown suite', () => {
    const opts: CoSignOptions = { suite: fromJson<'ml-dsa-65'>('"ed25519"'), secretKey: mlDsaKeys() };
    expect(() => coSignAttestation(VERDICT, opts)).toThrow(/not an accepted post-quantum co-sign suite/);
  });

  it('throws when the suite key material is missing', () => {
    expect(() => coSignAttestation(VERDICT, { secretKey: {} })).toThrow(/mlDsa/);
    expect(() => coSignAttestation(VERDICT, { suite: 'hybrid-ed25519-ml-dsa-65', secretKey: { mlDsa: mlDsaKeys().mlDsa } })).toThrow(/edSecret/);
  });
});
