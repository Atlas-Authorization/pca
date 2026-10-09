/**
 * Intel PCS collateral verification against the GENUINE Azure DCAP TDX quote and REAL Intel PCS collateral
 * captured 2026-10-08 (fixtures/real-tdx-collateral/). Deterministic: a fixed clock inside the collateral's
 * validity window. Negatives mutate real bytes or build synthetic CRLs with node:crypto.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { X509Certificate, createSign, generateKeyPairSync, createHash, type KeyObject } from 'node:crypto';
import { parseDcapQuote } from './attest-intel-tdx';
import { DEFAULT_ACCEPTED_STATUSES, decodeIssuerChainHeader, verifyCrl, serialIsRevoked, verifyIntelTdxCollateral, type IntelTdxCollateral } from './attest-intel-collateral';

const fx = (d: string, f: string) => readFileSync(resolve(__dirname, '..', 'fixtures', d, f));
const QUOTE = new Uint8Array(fx('real-tdx', 'azure-intel-tdx-dcap-quote.bin'));
const col = (f: string) => fx('real-tdx-collateral', f);
const NOW = new Date('2026-10-20T00:00:00Z'); // inside every collateral validity window (issued 2026-10-08)

function realCollateral(): IntelTdxCollateral {
  return {
    tcbInfoJson: col('tdx-tcbinfo.json').toString('utf8'),
    tcbInfoIssuerChainPem: col('tdx-tcbinfo-issuer-chain.pem').toString('utf8'),
    qeIdentityJson: col('tdx-qeidentity.json').toString('utf8'),
    qeIdentityIssuerChainPem: col('tdx-qeidentity-issuer-chain.pem').toString('utf8'),
    pckCrlDer: new Uint8Array(col('pckcrl-platform.der')),
    rootCrlDer: new Uint8Array(col('IntelSGXRootCA.crl.der')),
  };
}

// ── minimal DER builders for a synthetic CRL ──
const len = (n: number) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const der = (tag: number, ...parts: Buffer[]) => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), len(body.length), body]);
};
const ECDSA_SHA256 = der(0x30, Buffer.from('06082a8648ce3d040302', 'hex'));
function utc(d: Date): Buffer {
  const p = (n: number) => String(n).padStart(2, '0');
  return der(0x17, Buffer.from(`${String(d.getUTCFullYear()).slice(2)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`));
}
/** Build a CRL signed by `key`, naming `serialsHex` as revoked. */
function buildCrl(key: KeyObject, serialsHex: string[], nextUpdate: Date): Uint8Array {
  const entries = serialsHex.map((s) => {
    let b = Buffer.from(s.length % 2 ? `0${s}` : s, 'hex');
    if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return der(0x30, der(0x02, b), utc(new Date('2026-10-01T00:00:00Z')));
  });
  const tbs = der(0x30, der(0x02, Buffer.from([1])), ECDSA_SHA256, der(0x30), utc(new Date('2026-10-01T00:00:00Z')), utc(nextUpdate), der(0x30, ...entries));
  const sig = createSign('sha256').update(tbs).sign(key);
  return new Uint8Array(der(0x30, tbs, ECDSA_SHA256, der(0x03, Buffer.from([0]), sig)));
}

const quoteCerts = () => parseDcapQuote(QUOTE).pckChainPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)!.map((b) => new X509Certificate(b));

describe('attest-intel-collateral: REAL Intel PCS collateral vs the GENUINE Azure TDX quote', () => {
  it('evaluates the real platform: TCB UpToDate, QE UpToDate, TDX module TDX_01 UpToDate', async () => {
    const r = await verifyIntelTdxCollateral({ quote: QUOTE, collateral: realCollateral(), now: NOW });
    expect(r.reason).toBeUndefined();
    expect(r.fmspc).toBe('90c06f000000');
    expect(r.platformStatus).toBe('UpToDate');
    expect(r.tdxModuleStatus).toBe('UpToDate');
    expect(r.qeStatus).toBe('UpToDate');
    expect(r.status).toBe('UpToDate');
    expect(r.advisoryIds).toEqual([]);
    expect(r.tcbEvaluationDataNumber).toBe(20);
    expect(r.ok).toBe(true);
  });

  it('policy: an accept-list that excludes the real status rejects it, and exposes the status', async () => {
    const r = await verifyIntelTdxCollateral({ quote: QUOTE, collateral: realCollateral(), now: NOW, policy: { acceptStatuses: ['SWHardeningNeeded'] } });
    expect(r.ok).toBe(false);
    expect(r.status).toBe('UpToDate');
    expect(r.reason).toMatch(/not accepted by policy/);
    expect(DEFAULT_ACCEPTED_STATUSES).toEqual(['UpToDate', 'SWHardeningNeeded']);
  });

  it('policy: minTcbEvaluationDataNumber above the collateral rejects', async () => {
    const r = await verifyIntelTdxCollateral({ quote: QUOTE, collateral: realCollateral(), now: NOW, policy: { minTcbEvaluationDataNumber: 21 } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/tcbEvaluationDataNumber/);
  });

  it('decodes the PCS URL-encoded issuer-chain header form', () => {
    expect(decodeIssuerChainHeader('-----BEGIN%20CERTIFICATE-----%0AAA%3D%3D%0A-----END%20CERTIFICATE-----')).toBe('-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----');
  });
});

describe('attest-intel-collateral: fail-closed negatives', () => {
  const run = (c: IntelTdxCollateral, now = NOW, trust?: string) => verifyIntelTdxCollateral({ quote: QUOTE, collateral: c, now, trustAnchorRootCaSpkiSha256: trust });

  it('rejects a tampered tcbInfo (status flipped)', async () => {
    const c = realCollateral();
    const t = (c.tcbInfoJson as string).replace('"tcbDate":"2025-08-13T00:00:00Z","tcbStatus":"UpToDate"', '"tcbDate":"2025-08-13T00:00:00Z","tcbStatus":"Revoked"');
    expect(t).not.toBe(c.tcbInfoJson);
    const r = await run({ ...c, tcbInfoJson: t });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/signature does not verify/);
  });

  it('rejects a tampered signature', async () => {
    const c = realCollateral();
    const t = (c.tcbInfoJson as string).replace(/"signature":"(.)/, (_m, d: string) => `"signature":"${d === '0' ? '1' : '0'}`);
    const r = await run({ ...c, tcbInfoJson: t });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/signature/);
  });

  it('rejects a missing signature', async () => {
    const c = realCollateral();
    const r = await run({ ...c, qeIdentityJson: (c.qeIdentityJson as string).replace(/,"signature":"[0-9a-f]+"/, '') });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/signature missing/);
  });

  it('rejects a wrong pinned root', async () => {
    const r = await run(realCollateral(), NOW, createHash('sha256').update('not intel').digest('hex'));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/pinned/);
  });

  it('rejects an issuer chain signed by a different root (attacker-built chain)', async () => {
    const c = realCollateral();
    // swap the TCB-info chain for the PCK CA + root: wrong signer for the tcbInfo signature
    const r = await run({ ...c, tcbInfoIssuerChainPem: c.qeIdentityIssuerChainPem.split('-----END CERTIFICATE-----')[1]! + '-----END CERTIFICATE-----' });
    expect(r.ok).toBe(false);
  });

  it('rejects expired collateral (clock past nextUpdate)', async () => {
    const r = await run(realCollateral(), new Date('2026-12-01T00:00:00Z'));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/stale/);
  });

  it('rejects a clock before issuance', async () => {
    const r = await run(realCollateral(), new Date('2026-10-01T00:00:00Z'));
    expect(r.ok).toBe(false);
  });

  it('rejects a mismatched QE identity (different MRSIGNER) — and the tamper is caught by its signature', async () => {
    const c = realCollateral();
    const r = await run({ ...c, qeIdentityJson: (c.qeIdentityJson as string).replace('DC9E2A7C', 'AC9E2A7C') });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/signature/);
  });

  it('rejects the wrong enclave identity document (TCB info passed as QE identity)', async () => {
    const c = realCollateral();
    const r = await run({ ...c, qeIdentityJson: c.tcbInfoJson, qeIdentityIssuerChainPem: c.tcbInfoIssuerChainPem });
    expect(r.ok).toBe(false);
  });

  it('rejects missing collateral', async () => {
    const c = realCollateral();
    expect((await run({ ...c, pckCrlDer: new Uint8Array(0) })).reason).toMatch(/incomplete/);
    expect((await run({ ...c, tcbInfoJson: '' })).reason).toMatch(/incomplete/);
  });

  it('rejects the processor-CA PCK CRL (not signed by this quote\'s PCK CA)', async () => {
    const c = realCollateral();
    const r = await run({ ...c, pckCrlDer: new Uint8Array(col('pckcrl-processor.der')) });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/PCK CRL: CRL signature/);
  });

  it('rejects garbage CRL bytes and a corrupted root CRL signature', async () => {
    const c = realCollateral();
    expect((await run({ ...c, pckCrlDer: new Uint8Array([1, 2, 3]) })).reason).toMatch(/CRL: CRL parse failed/);
    const bad = new Uint8Array(c.rootCrlDer);
    bad[bad.length - 3] = (bad[bad.length - 3] ?? 0) ^ 0xff;
    const r = await run({ ...c, rootCrlDer: bad });
    expect(r.ok).toBe(false);
  });

  it('a synthetic CRL naming the PCK leaf serial is rejected (signature check blocks the forgery, no PCK CA key available)', async () => {
    // Without Intel's PCK CA private key a forged CRL cannot verify; this proves a forged "clean" or "revoked" CRL is refused.
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const [leaf] = quoteCerts();
    const crl = buildCrl(privateKey, [leaf!.serialNumber], new Date('2027-01-01T00:00:00Z'));
    const r = await run({ ...realCollateral(), pckCrlDer: crl });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/PCK CRL: CRL signature/);
  });

  it('REVOKED serial: a CRL signed by the issuer key lists the leaf serial; wrong key / stale CRL are refused', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const [leaf] = quoteCerts();
    const crl = buildCrl(privateKey, [leaf!.serialNumber, '0a0b'], new Date('2027-01-01T00:00:00Z'));
    const ok = verifyCrl(crl, publicKey, NOW);
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(serialIsRevoked(ok.revoked, leaf!.serialNumber)).toBe(true);
      expect(serialIsRevoked(ok.revoked, '0A0B')).toBe(true);
      expect(serialIsRevoked(ok.revoked, '0c')).toBe(false);
    }
    expect(verifyCrl(crl, other.publicKey, NOW).ok).toBe(false);
    expect(verifyCrl(crl, publicKey, new Date('2027-02-01T00:00:00Z')).ok).toBe(false);
  });

  it('real CRLs parse and verify under the real chain keys, and do not revoke the chain', () => {
    const [leaf, ca, root] = quoteCerts();
    const p = verifyCrl(new Uint8Array(col('pckcrl-platform.der')), ca!.publicKey, NOW);
    const r = verifyCrl(new Uint8Array(col('IntelSGXRootCA.crl.der')), root!.publicKey, NOW);
    expect(p.ok && r.ok).toBe(true);
    if (p.ok && r.ok) {
      expect(p.revoked.size).toBeGreaterThan(0);
      expect(serialIsRevoked(p.revoked, leaf!.serialNumber)).toBe(false);
      expect(serialIsRevoked(r.revoked, ca!.serialNumber)).toBe(false);
    }
  });

  it('expired PCK CRL is rejected', async () => {
    const r = await run(realCollateral(), new Date('2026-11-09T00:00:00Z'));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/stale/);
  });
});
