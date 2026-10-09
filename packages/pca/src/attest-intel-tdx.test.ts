/**
 * Tests for the Intel TDX/DCAP quote primitives (`attest-intel-tdx.ts`), run against a GENUINE Intel DCAP
 * v4 TDX quote captured from an Azure confidential VM (fixtures/real-tdx/): real PCK X.509 chain to the
 * pinned Intel SGX Root CA, real P-256 QE/AK/quote signatures. CLASSICAL ECDSA-P256, not post-quantum.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  INTEL_SGX_ROOT_CA_SPKI_SHA256,
  extractPckFmspcAndTcb,
  parseDcapQuote,
  parseDcapTdReport,
  toHex,
  verifyGenuineTdxQuote,
  verifyIntelPckChainX509,
} from './attest-intel-tdx';
import type { ExpectedAttestationBinding } from './attestation';
import { encodeKey, generateKeyPair } from './keys';

const T = 1_000_000;
const A = generateKeyPair();
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: encodeKey(A.publicKey),
  grantRef: 'grant-tdx-1',
  epoch: 1,
  nonce: 'nonce-tdx-1',
  nonceIssuedAt: T - 1000,
};

// ════════════════════════════════════════════════════════════════════════════════════════════════
// GENUINE SILICON — a REAL Intel DCAP ECDSA TDX quote captured from Azure (fixtures/real-tdx/). This is
// A real Intel PCK X.509 chain (PCK leaf → Intel SGX PCK Platform CA → Intel SGX Root CA)
// and real P-256 QE/AK/quote signatures, verified end-to-end to the PINNED Intel SGX Root CA. report_data
// here is Azure's default (SHA-256(vTPM-AK)), NOT a PCA binding, so `expected` is intentionally omitted.
// ════════════════════════════════════════════════════════════════════════════════════════════════

const REAL_QUOTE = new Uint8Array(readFileSync(resolve(__dirname, '..', 'fixtures', 'real-tdx', 'azure-intel-tdx-dcap-quote.bin')));
// Ground truth captured from the fixture (see fixtures/real-tdx/README.md).
const REAL_MRTD = '6f3e84c54ac6377614d4c139473db575a83b5db41bd845eecb4eedaf2788ea881309a410c4ceae9641406411f3f639b8';
const REAL_FMSPC = '90c06f000000';

describe('attest-intel-tdx: GENUINE Azure DCAP quote — structural parse', () => {
  it('parses the v4 / ECDSA-P256 / TDX quote header + sections', () => {
    const q = parseDcapQuote(REAL_QUOTE);
    expect(q.version).toBe(4);
    expect(q.attKeyType).toBe(2);
    expect(q.teeType).toBe(0x81);
    expect(q.header.length).toBe(48);
    expect(q.tdReportBody.length).toBe(584);
    expect(q.quoteSignature.length).toBe(64);
    expect(q.akPubRaw.length).toBe(64);
    expect(q.qeReportBody.length).toBe(384);
    expect(q.qeReportSignature.length).toBe(64);
    expect(q.pckChainPem.match(/BEGIN CERTIFICATE/g)?.length).toBe(3);
  });

  it('parses the TD10 report body (MRTD at offset 136)', () => {
    const q = parseDcapQuote(REAL_QUOTE);
    const r = parseDcapTdReport(q.tdReportBody);
    expect(toHex(r.mrTd)).toBe(REAL_MRTD);
    expect(r.teeTcbSvn.length).toBe(16);
    expect(r.reportData.length).toBe(64);
  });

  it('the real TD is not a DEBUG TD (TD_ATTRIBUTES bit 0 clear)', () => {
    const q = parseDcapQuote(REAL_QUOTE);
    expect(parseDcapTdReport(q.tdReportBody).tdAttributes[0]! & 1).toBe(0);
  });

  it('rejects a quote with a corrupted version (fail closed)', () => {
    const bad = REAL_QUOTE.slice();
    bad[0] = 0x09;
    expect(() => parseDcapQuote(bad)).toThrow(/unsupported quote version/);
  });
});

describe('attest-intel-tdx: GENUINE Azure DCAP quote — real X.509 PCK chain', () => {
  it('verifies the embedded PCK chain to the PINNED Intel SGX Root CA (depth 3)', async () => {
    const q = parseDcapQuote(REAL_QUOTE);
    const chain = await verifyIntelPckChainX509({ pckChainPem: q.pckChainPem });
    expect(chain.ok).toBe(true);
    expect(chain.depth).toBe(3);
    expect(chain.leafKey?.point.length).toBe(65);
    expect(chain.leafDer).toBeInstanceOf(Uint8Array);
  });

  it('extracts the real FMSPC + PCK TCB (PCESVN 13) from the Intel SGX extension', async () => {
    const q = parseDcapQuote(REAL_QUOTE);
    const chain = await verifyIntelPckChainX509({ pckChainPem: q.pckChainPem });
    const tcb = extractPckFmspcAndTcb(chain.leafDer!);
    expect(toHex(tcb.fmspc)).toBe(REAL_FMSPC);
    expect(tcb.sgxTcbComponents.length).toBe(16);
    expect(tcb.sgxTcbComponents[0]).toBe(5);
    expect(tcb.pcesvn).toBe(13);
    expect(tcb.cpusvn.length).toBe(16);
  });

  it('rejects the chain under a WRONG pinned Root CA (fail closed)', async () => {
    const q = parseDcapQuote(REAL_QUOTE);
    const chain = await verifyIntelPckChainX509({ pckChainPem: q.pckChainPem, trustAnchorRootCaSpkiSha256: '00'.repeat(32) });
    expect(chain.ok).toBe(false);
    expect(chain.reason).toMatch(/Root CA does not match the pinned trust anchor/);
  });
});

describe('attest-intel-tdx: GENUINE Azure DCAP quote — full end-to-end verify', () => {
  it('ACCEPTS the real quote: chain + QE sig + AK binding + TD quote sig all verify', async () => {
    const r = await verifyGenuineTdxQuote({ quote: REAL_QUOTE });
    expect(r.ok).toBe(true);
    expect(r.chainDepth).toBe(3);
    expect(r.fmspc).toBe(REAL_FMSPC);
    expect(r.report?.mrTd && toHex(r.report.mrTd)).toBe(REAL_MRTD);
    expect(r.measured?.runtime_measurement).toBe(REAL_MRTD);
    expect(r.akPub?.point.length).toBe(65);
    expect(r.pckTcb?.pcesvn).toBe(13);
  });

  it('enforces the MRTD + FMSPC policy against the real quote', async () => {
    const ok = await verifyGenuineTdxQuote({ quote: REAL_QUOTE, policy: { mrtds: [REAL_MRTD], fmspcs: [REAL_FMSPC] } });
    expect(ok.ok).toBe(true);
    const badMrtd = await verifyGenuineTdxQuote({ quote: REAL_QUOTE, policy: { mrtds: ['00'.repeat(48)] } });
    expect(badMrtd.ok).toBe(false);
    expect(badMrtd.reason).toMatch(/MRTD not in policy allowlist/);
    const badFmspc = await verifyGenuineTdxQuote({ quote: REAL_QUOTE, policy: { fmspcs: ['aabbccddeeff'] } });
    expect(badFmspc.ok).toBe(false);
    expect(badFmspc.reason).toMatch(/FMSPC not in policy allowlist/);
  });

  it('TAMPER: flipping a TD-report byte breaks the TD quote signature (fail closed)', async () => {
    const tampered = REAL_QUOTE.slice();
    flipByte(tampered, 48 + 136); // flip the first MRTD byte (inside the AK-signed region)
    const r = await verifyGenuineTdxQuote({ quote: tampered });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/TD quote signature does not verify/);
  });

  it('TAMPER: corrupting the QE report breaks the QE-report signature (fail closed)', async () => {
    // QE report starts at 48 + 584 + 4 + 64 + 64 + 6 = 770.
    const tampered = REAL_QUOTE.slice();
    flipByte(tampered, 770);
    const r = await verifyGenuineTdxQuote({ quote: tampered });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/QE report signature does not verify under the PCK leaf/);
  });

  it('TAMPER: a PCK leaf cert byte breaks the X.509 chain (fail closed)', async () => {
    // Corrupt a byte well inside the first PEM block's base64 body.
    const tampered = REAL_QUOTE.slice();
    const pemStart = indexOfSub(tampered, strBytes('-----BEGIN CERTIFICATE-----'));
    expect(pemStart).toBeGreaterThan(0);
    tampered[pemStart + 60] = tampered[pemStart + 60] === 0x41 ? 0x42 : 0x41; // flip a base64 char
    const r = await verifyGenuineTdxQuote({ quote: tampered });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/PCK chain invalid/);
  });

  it('rejects a PCA nonce binding against the real quote (report_data is Azure vTPM-AK, not a PCA binding)', async () => {
    const r = await verifyGenuineTdxQuote({ quote: REAL_QUOTE, expected: EXPECTED });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/report_data does not bind/);
  });

  it('exposes the known Intel SGX Root CA pin', () => {
    expect(INTEL_SGX_ROOT_CA_SPKI_SHA256).toBe('a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e');
  });
});

function flipByte(buf: Uint8Array, i: number): void {
  buf[i] = (buf[i] ?? 0) ^ 0xff;
}
function strBytes(s: string): Uint8Array {
  return Uint8Array.from(s.split('').map((c) => c.charCodeAt(0)));
}
function indexOfSub(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}
