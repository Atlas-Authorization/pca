/**
 * Tests for the Intel DCAP `HardwareAttestationVerifier`. Evidence is GENUINE: the PCA-bound Intel TDX quote and
 * runtime-data JSON captured from an Azure DC4es_v6 confidential VM (fixtures/real-azure-maa), and real Intel PCS
 * collateral (fixtures/real-tdx-collateral). The PCA binding is checked directly against Intel's signature — no
 * Microsoft service is in this trust path.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { createIntelDcapVerifier, checkAzureRuntimeDataBinding, type IntelDcapEvidence } from './attest-intel-dcap';
import { parseDcapQuote, parseDcapTdReport } from './attest-intel-tdx';
import { attestationBinding } from './attestation';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';
import type { IntelTdxCollateral } from './attest-intel-collateral';

const fx = (...p: string[]) => readFileSync(resolve(__dirname, '..', 'fixtures', ...p));
const QUOTE = new Uint8Array(fx('real-azure-maa', 'pcabound-tdx-dcap-quote.bin'));
const RUNTIME = new Uint8Array(fx('real-azure-maa', 'pcabound-runtime-data.json'));
const col = (f: string) => fx('real-tdx-collateral', f);
const COLLATERAL: IntelTdxCollateral = {
  tcbInfoJson: col('tdx-tcbinfo.json').toString('utf8'),
  tcbInfoIssuerChainPem: col('tdx-tcbinfo-issuer-chain.pem').toString('utf8'),
  qeIdentityJson: col('tdx-qeidentity.json').toString('utf8'),
  qeIdentityIssuerChainPem: col('tdx-qeidentity-issuer-chain.pem').toString('utf8'),
  pckCrlDer: new Uint8Array(col('pckcrl-platform.der')),
  rootCrlDer: new Uint8Array(col('IntelSGXRootCA.crl.der')),
};

const EXPECTED: ExpectedAttestationBinding = {
  holderPub: 'pca-realsilicon-azure-tdx-holder',
  grantRef: 'grant_pca_azure_maa_realsilicon',
  epoch: 1,
  nonce: 'srv-nonce-maa-5d3b8e1f9a27c604',
};
const NOW_MS = Date.parse('2026-10-20T00:00:00Z'); // inside every collateral validity window (issued 2026-10-08)
const MRTD = Buffer.from(parseDcapTdReport(parseDcapQuote(QUOTE).tdReportBody).mrTd).toString('hex');
const DOC = {} as unknown as AttestationDocument;
const CTX = {} as never;

function verifier(over: { ev?: Partial<IntelDcapEvidence>; mrtds?: string[]; binding?: 'report-data' | 'azure-runtime-data'; allowMissing?: boolean; pin?: string; fmspcs?: string[] } = {}) {
  const ev: IntelDcapEvidence = { quote: QUOTE, runtimeData: RUNTIME, collateral: COLLATERAL, ...over.ev };
  return createIntelDcapVerifier({
    binding: over.binding ?? 'azure-runtime-data',
    policy: { mrtds: over.mrtds ?? [MRTD], ...(over.fmspcs ? { fmspcs: over.fmspcs } : {}) },
    ...(over.pin ? { trustAnchorRootCaSpkiSha256: over.pin } : {}),
    ...(over.allowMissing ? { allowMissingCollateral: true } : {}),
    resolveEvidence: () => ev,
  });
}
const run = (v: ReturnType<typeof verifier>, expected = EXPECTED, nowMs = NOW_MS) => v.verify({ document: DOC, ctx: CTX, nowMs, expected });

describe('Intel DCAP root — REAL Azure TDX quote + real Intel PCS collateral', () => {
  it('verifies end to end: Intel-signed quote + runtime-data binding + collateral (TCB UpToDate)', async () => {
    const r = await run(verifier());
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.bound).toBe(true);
      expect(r.measured?.runtime_measurement).toBe(MRTD);
      expect(r.hostAsserted?.attestation_type).toBe('tdx-dcap');
      expect(r.hostAsserted?.tcb_status).toBe('UpToDate');
      expect(r.hostAsserted?.fmspc).toMatch(/^[0-9a-f]{12}$/);
    }
  });

  it('the binding relation holds on the raw evidence: sha256(runtime JSON) is report_data[0:32], user-data is the PCA binding', () => {
    const rd = parseDcapTdReport(parseDcapQuote(QUOTE).tdReportBody).reportData;
    expect(createHash('sha256').update(RUNTIME).digest('hex')).toBe(Buffer.from(rd.subarray(0, 32)).toString('hex'));
    expect(checkAzureRuntimeDataBinding(rd, RUNTIME, EXPECTED)).toBeUndefined();
  });

  it('fails closed: relayed binding (any of holder / grant / epoch / nonce)', async () => {
    for (const bad of [{ ...EXPECTED, holderPub: 'x' }, { ...EXPECTED, grantRef: 'g' }, { ...EXPECTED, epoch: 2 }, { ...EXPECTED, nonce: 'n' }]) {
      const r = await run(verifier(), bad);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toContain('does not bind');
    }
  });

  it('fails closed: runtime data not matching the hash, wrong user-data, not JSON, missing', async () => {
    const tampered = new Uint8Array(RUNTIME);
    tampered[RUNTIME.length - 3] = (tampered[RUNTIME.length - 3] ?? 0) ^ 0x01;
    const a = await run(verifier({ ev: { runtimeData: tampered } }));
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.reason).toContain('sha256(runtime data)');
    const rd = parseDcapTdReport(parseDcapQuote(QUOTE).tdReportBody).reportData;
    expect(checkAzureRuntimeDataBinding(rd, new TextEncoder().encode('not json'), EXPECTED)).toBeDefined();
    expect((await run(verifier({ ev: { runtimeData: undefined } }))).ok).toBe(false);
    // direct report-data mode cannot hold on Azure (report_data is a runtime-data hash)
    const direct = await run(verifier({ binding: 'report-data' }));
    expect(direct.ok).toBe(false);
    if (!direct.ok) expect(direct.reason).toContain('report_data does not bind');
  });

  it('fails closed: tampered quote (signature), wrong MRTD allowlist, wrong FMSPC allowlist, wrong root pin', async () => {
    const q = new Uint8Array(QUOTE);
    q[60] = (q[60] ?? 0) ^ 0x01; // inside the TD report body, covered by the AK signature
    expect((await run(verifier({ ev: { quote: q } }))).ok).toBe(false);
    expect((await run(verifier({ mrtds: ['00'.repeat(48)] }))).ok).toBe(false);
    expect((await run(verifier({ fmspcs: ['ffffffffffff'] }))).ok).toBe(false);
    expect((await run(verifier({ pin: '00'.repeat(32) }))).ok).toBe(false);
  });

  it('collateral is REQUIRED by default; allowMissingCollateral is an explicit, labelled opt-out', async () => {
    const none = await run(verifier({ ev: { collateral: undefined } }));
    expect(none.ok).toBe(false);
    if (!none.ok) expect(none.reason).toContain('collateral required');
    const optOut = await run(verifier({ ev: { collateral: undefined }, allowMissing: true }));
    expect(optOut.ok).toBe(true);
    if (optOut.ok) expect(optOut.hostAsserted?.tcb_status).toBe('unevaluated');
  });

  it('fails closed on bad collateral: tampered TCB info, stale clock, and a policy that rejects the real status', async () => {
    const bad: IntelTdxCollateral = { ...COLLATERAL, tcbInfoJson: String(COLLATERAL.tcbInfoJson).replace('"tcbEvaluationDataNumber":20', '"tcbEvaluationDataNumber":21') };
    expect(String(bad.tcbInfoJson)).not.toBe(String(COLLATERAL.tcbInfoJson));
    expect((await run(verifier({ ev: { collateral: bad } }))).ok).toBe(false);
    expect((await run(verifier(), EXPECTED, Date.parse('2031-01-01T00:00:00Z'))).ok).toBe(false);
    const strict = createIntelDcapVerifier({
      binding: 'azure-runtime-data',
      policy: { mrtds: [MRTD], collateral: { acceptStatuses: ['SWHardeningNeeded'] } },
      resolveEvidence: () => ({ quote: QUOTE, runtimeData: RUNTIME, collateral: COLLATERAL }),
    });
    const r = await run(strict);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('Intel collateral');
  });

  it('refuses accept-all construction and bad options', () => {
    const base = { binding: 'azure-runtime-data' as const };
    expect(() => createIntelDcapVerifier({ ...base, policy: { mrtds: [] } })).toThrow();
    expect(() => createIntelDcapVerifier({ ...base, policy: { mrtds: ['abc'] } })).toThrow();
    expect(() => createIntelDcapVerifier({ binding: 'nope' as never, policy: { mrtds: [MRTD] } })).toThrow();
  });

  it('fails closed with no resolver / no evidence', async () => {
    const noRes = createIntelDcapVerifier({ binding: 'azure-runtime-data', policy: { mrtds: [MRTD] } });
    expect((await run(noRes)).ok).toBe(false);
    const none = createIntelDcapVerifier({ binding: 'azure-runtime-data', policy: { mrtds: [MRTD] }, resolveEvidence: () => undefined });
    expect((await run(none)).ok).toBe(false);
  });
});

describe('binding helper sanity', () => {
  it('attestationBinding is 64 bytes (the user-data width)', () => {
    expect(attestationBinding(EXPECTED).length).toBe(64);
  });
});
