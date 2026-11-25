/**
 * Azure MAA / GCP Confidential Space / MAA key trust / attestation hook: vendor labels, the x5c profile on a chain
 * anchored by an external root, key-strength reasons, persisted-state zero timestamps, and the attestation hook label
 * read from the configured hardware verifier.
 */
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { assuranceLabelOf, setAssuranceLabel } from './assurance';
import { createAttestationVerifierProved } from './attest-proved';
import { createAttestationVerifier, type AttestationVerifierOpts, type HardwareAttestationVerifier } from './attestation';
import { createAzureMaaVerifier, verifyX5cChain, type MaaJwks } from './attest-azure-maa';
import { createGcpConfidentialSpaceVerifier } from './attest-gcp-confidential-space';
import { createMaaKeyTrust, createMemoryMaaKeyStateStore, evaluateMaaJwks } from './attest-maa-keys';
import { bitString, ext, forgeCert, forgeKey, integer, nul, oid, seq, type ForgeKey } from './test-support/forge-x509';

const FROM = new Date(Date.UTC(2020, 0, 1));
const TO = new Date(Date.UTC(2040, 0, 1));
const NOW = Date.UTC(2026, 5, 1);
const DAY = 86_400_000;

describe('vendor labels', () => {
  it('Azure MAA', () => {
    const v = createAzureMaaVerifier({ trustedIssuers: ['https://maa.example.net'], trustAnchors: { rootSpkiSha256: ['00'.repeat(32)] }, policy: { tdxMrtds: ['aa'.repeat(48)] } });
    expect(assuranceLabelOf(v)).toEqual({ level: 'hardware', vendor: 'azure-maa' });
  });
  it('GCP Confidential Space', () => {
    const v = createGcpConfidentialSpaceVerifier({ trustedIssuers: ['https://cs.example.com'], trustAnchors: { trustedKeySpki: ['00'.repeat(32)] }, policy: { imageDigests: [`sha256:${'a'.repeat(64)}`] } });
    expect(assuranceLabelOf(v)).toEqual({ level: 'hardware', vendor: 'gcp-confidential-space' });
  });
});

describe('MAA x5c chain anchored by an external root certificate', () => {
  const rootKey = forgeKey('r4-maa-root', 'P-384');
  const midKey = forgeKey('r4-maa-mid', 'P-384');
  const leafKey = forgeKey('r4-maa-leaf', 'P-384');
  const CA = [ext.basicConstraints(true), ext.keyUsage(['keyCertSign', 'cRLSign'])];
  const root = forgeCert({ subject: [['CN', 'R4 Root']], issuer: [['CN', 'R4 Root']], subjectKey: rootKey, signer: rootKey, serial: 1n, notBefore: FROM, notAfter: TO, extensions: CA });
  const mid = forgeCert({ subject: [['CN', 'R4 Mid']], issuer: [['CN', 'R4 Root']], subjectKey: midKey, signer: rootKey, serial: 2n, notBefore: FROM, notAfter: TO, extensions: CA });
  const leafWith = (leafExt: Uint8Array[]) =>
    forgeCert({ subject: [['CN', 'R4 Leaf']], issuer: [['CN', 'R4 Mid']], subjectKey: leafKey, signer: midKey, serial: 3n, notBefore: FROM, notAfter: TO, extensions: leafExt });
  const b64 = (der: Uint8Array) => Buffer.from(der).toString('base64');
  const anchors = { rootCertsPem: [root.pem] };

  it('control: leaf + intermediate, the root supplied only as a trust anchor, verifies', async () => {
    const r = await verifyX5cChain([b64(leafWith([ext.basicConstraints(false), ext.keyUsage(['digitalSignature'])]).der), b64(mid.der)], anchors, { nowMs: NOW });
    expect(r.ok).toBe(true);
  });
  it('a profile violation is refused with the exact reason', async () => {
    const r = await verifyX5cChain([b64(leafWith([ext.basicConstraints(true), ext.keyUsage(['digitalSignature'])]).der), b64(mid.der)], anchors, { nowMs: NOW });
    expect(r).toEqual({ ok: false, reason: 'x5c chain profile: leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)' });
  });
});

describe('MAA key trust', () => {
  const ISSUER = 'https://maa.example.net';
  const policy = { trustedIssuers: [ISSUER], allowTrustOnFirstUse: true, builtinPins: false };

  it('an RSA signing key with an even public exponent is rejected with the exponent reason', () => {
    const signer = forgeKey('r4-maa-rsa-signer', 'P-256');
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const n = Buffer.from(publicKey.export({ format: 'jwk' }).n!, 'base64url');
    const spki = seq(seq(oid('1.2.840.113549.1.1.1'), nul()), bitString(seq(integer(new Uint8Array(n)), integer(4))));
    const cert = forgeCert({ subject: [['CN', ISSUER]], issuer: [['CN', ISSUER]], subjectKey: { ...signer, spki } as ForgeKey, signer, serial: 9n, notBefore: FROM, notAfter: TO });
    expect(new X509Certificate(cert.der).publicKey.asymmetricKeyDetails).toEqual({ modulusLength: 2048, publicExponent: 4n });
    const jwks = { keys: [{ kid: 'k', x5c: [Buffer.from(cert.der).toString('base64')] }] } as unknown as MaaJwks;
    expect(evaluateMaaJwks(jwks, ISSUER, policy, NOW)).toEqual({ accepted: [], rejected: [{ kid: 'k', reason: 'RSA public exponent must be odd, at least 3 and at most 32 bits' }] });
  });

  it('a persisted anchor with zero (positive) timestamps is valid state, served from cache', async () => {
    const store = createMemoryMaaKeyStateStore();
    const t = createMaaKeyTrust({ policy, store, fetch: (async () => { throw new Error('no network in this test'); }) as typeof fetch });
    const spki = 'ab'.repeat(32);
    await store.set(ISSUER, { v: 1, issuer: ISSUER, fetchedAtMs: NOW, anchors: [{ spki, kind: 'self-signed', notBeforeMs: 0, notAfterMs: NOW + DAY, firstSeenMs: 0 }] });
    const r = await t.getTrustAnchors(ISSUER, { nowMs: NOW + 1000 });
    expect(r.ok && r.source).toBe('cache');
    expect(r.ok && r.trustAnchors.rootSpkiSha256).toEqual([spki]);
  });
});

describe('attestation hook label comes from the configured hardware verifier', () => {
  it('reads the verifier it checked, not an earlier read', () => {
    let reads = 0;
    const labelled = (n: number): HardwareAttestationVerifier =>
      setAssuranceLabel({ verify: async () => ({ ok: false, reason: 'unused' }) }, { level: 'hardware', vendor: `read-${n}` }) as HardwareAttestationVerifier;
    const opts = (): AttestationVerifierOpts =>
      ({
        trustedAttestorKeys: [],
        expectedBinding: () => ({ holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n' }),
        get hardwareVerifier() {
          reads += 1;
          return labelled(reads);
        },
      }) as AttestationVerifierOpts;
    reads = 0;
    createAttestationVerifierProved(opts());
    const byProved = reads;
    reads = 0;
    const hook = createAttestationVerifier(opts());
    // reads after the proved core: the presence check, then the label source
    expect(assuranceLabelOf(hook)).toEqual({ level: 'hardware', vendor: `read-${byProved + 2}` });
  });
});
