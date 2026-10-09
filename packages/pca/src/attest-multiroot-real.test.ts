/**
 * REAL multi-root corroboration. One Azure TDX boot, one PCA binding, TWO independent roots:
 *   - `intel-dcap`  — verifies the raw Intel-signed quote (+ Intel PCS collateral). Trust: Intel.
 *   - `azure-maa`   — verifies Microsoft's signed token over that same quote. Trust: Microsoft.
 * Both must corroborate (2-of-2). Everything is genuine hardware evidence; negatives are by mutation.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import { createMultiRootVerifier } from './attestation';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';
import { createIntelDcapVerifier } from './attest-intel-dcap';
import { createAzureMaaVerifier, parseMaaJwt, type MaaJwks } from './attest-azure-maa';
import { parseDcapQuote, parseDcapTdReport } from './attest-intel-tdx';
import type { IntelTdxCollateral } from './attest-intel-collateral';

const fx = (...p: string[]) => readFileSync(resolve(__dirname, '..', 'fixtures', ...p));
const QUOTE = new Uint8Array(fx('real-azure-maa', 'pcabound-tdx-dcap-quote.bin'));
const RUNTIME = new Uint8Array(fx('real-azure-maa', 'pcabound-runtime-data.json'));
const TOKEN = fx('real-azure-maa', 'pcabound-tdxvm-token.jwt').toString('utf8').trim();
const JWKS = JSON.parse(fx('real-azure-maa', 'maa-signing-certs.json').toString('utf8')) as MaaJwks;
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
const MRTD = Buffer.from(parseDcapTdReport(parseDcapQuote(QUOTE).tdReportBody).mrTd).toString('hex');
const claims = parseMaaJwt(TOKEN).payload as Record<string, unknown>;
// inside the MAA token window (iat 22:41Z, +8h) AND after the Intel collateral was issued (2026-10-08)
const NOW_MS = ((claims['iat'] as number) + 2 * 3600) * 1000;
const SIGNER_SPKI = 'fe4fa28d5b2e89f088d484f260363a12bcab53d9a9e0d6725507336fc8b6a71e';

function policy(over: { quote?: Uint8Array; token?: string; threshold?: number; requireIntel?: boolean } = {}) {
  const intel = createIntelDcapVerifier({
    binding: 'azure-runtime-data',
    policy: { mrtds: [MRTD] },
    resolveEvidence: () => ({ quote: over.quote ?? QUOTE, runtimeData: RUNTIME, collateral: COLLATERAL }),
  });
  const maa = createAzureMaaVerifier({
    trustedIssuers: ['https://sharedwus.wus.attest.azure.net'],
    trustAnchors: { rootSpkiSha256: [SIGNER_SPKI] },
    policy: { tdxMrtds: [MRTD], runtimeUserDataBinding: true },
    resolveEvidence: () => ({ token: over.token ?? TOKEN, jwks: JWKS }),
  });
  return createMultiRootVerifier({
    threshold: over.threshold ?? 2,
    roots: [
      { id: 'intel-dcap', verifier: intel, suite: 'ecdsa-p256', ...(over.requireIntel ? { required: true } : {}) },
      { id: 'azure-maa', verifier: maa, suite: 'rs256' },
    ],
  });
}
const run = (v: ReturnType<typeof policy>) => v.verify({ document: {} as unknown as AttestationDocument, ctx: {} as never, nowMs: NOW_MS, expected: EXPECTED });

describe('REAL 2-of-2: Intel-signed quote + Microsoft-signed token over the same Azure TDX boot', () => {
  it('both independent roots corroborate and their identities reconcile (same MRTD)', async () => {
    const r = await run(policy());
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.bound).toBe(true);
      expect(r.measured?.runtime_measurement).toBe(MRTD);
      expect(r.hostAsserted?.['intel-dcap.tcb_status']).toBe('UpToDate');
      expect(r.hostAsserted?.['azure-maa.tcb_status']).toBe('UpToDate');
    }
  });

  it('breaking either root drops below threshold (a forged Intel quote cannot ride on Microsoft, nor vice versa)', async () => {
    const q = new Uint8Array(QUOTE);
    q[60] = (q[60] ?? 0) ^ 0x01;
    const noIntel = await run(policy({ quote: q }));
    expect(noIntel.ok).toBe(false);
    if (!noIntel.ok) expect(noIntel.reason).toContain('below threshold (1/2');
    const [h, p, s] = TOKEN.split('.');
    const sig = Buffer.from(s!, 'base64url');
    sig[0] = (sig[0] ?? 0) ^ 0x01;
    const noMaa = await run(policy({ token: `${h}.${p}.${sig.toString('base64url')}` }));
    expect(noMaa.ok).toBe(false);
    if (!noMaa.ok) expect(noMaa.reason).toContain('below threshold (1/2');
  });

  it('a required root that fails denies even when the other corroborates; 1-of-2 accepts with a labelled single root', async () => {
    const q = new Uint8Array(QUOTE);
    q[60] = (q[60] ?? 0) ^ 0x01;
    const req = await run(policy({ quote: q, threshold: 1, requireIntel: true }));
    expect(req.ok).toBe(false);
    if (!req.ok) expect(req.reason).toContain("required attestation root 'intel-dcap'");
    const one = await run(policy({ quote: q, threshold: 1 }));
    expect(one.ok).toBe(true);
    if (one.ok) expect(Object.keys(one.hostAsserted ?? {}).some((k) => k.startsWith('azure-maa.'))).toBe(true);
  });

  it('a relayed binding fails BOTH roots', async () => {
    const v = policy();
    const r = await v.verify({ document: {} as unknown as AttestationDocument, ctx: {} as never, nowMs: NOW_MS, expected: { ...EXPECTED, nonce: 'other' } });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('below threshold (0/2');
  });
});
