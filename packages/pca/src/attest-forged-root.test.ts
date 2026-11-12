/**
 * T-028 / listed gap 7: a COMPROMISED vendor root. One root of a multi-root policy signs a forged quote with a
 * chain that validates (here an Intel DCAP quote and PCK chain minted under a root whose SPKI the policy trusts, so
 * every cryptographic check passes) while the real hardware, attested by a second independent root, runs something else.
 * The second root is genuine recorded Azure evidence (Microsoft-signed MAA token over a real Intel TDX quote).
 * Every assertion is on the exact outcome.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { assuranceLabelOf } from './assurance';
import { attestationBinding, createMultiRootVerifier, type AttestationDocument, type ExpectedAttestationBinding } from './attestation';
import { createAzureMaaVerifier, parseMaaJwt, type MaaJwks } from './attest-azure-maa';
import { createIntelDcapVerifier } from './attest-intel-dcap';
import { toHex } from './attest-intel-tdx';
import { forgeTdxCollateral, forgeTdxQuote } from './test-support/forge-dcap';

const fx = (f: string) => readFileSync(resolve(__dirname, '..', 'fixtures', 'real-azure-maa', f));
const TOKEN = fx('pcabound-tdxvm-token.jwt').toString('utf8').trim();
const JWKS = JSON.parse(fx('maa-signing-certs.json').toString('utf8')) as MaaJwks;
const claims = parseMaaJwt(TOKEN).payload as Record<string, unknown>;
const REAL_MRTD = String(claims['tdx_mrtd']);
const SIGNER_SPKI = 'fe4fa28d5b2e89f088d484f260363a12bcab53d9a9e0d6725507336fc8b6a71e';
const NOW_MS = ((claims['iat'] as number) + 2 * 3600) * 1000;
const EXPECTED: ExpectedAttestationBinding = { holderPub: 'pca-realsilicon-azure-tdx-holder', grantRef: 'grant_pca_azure_maa_realsilicon', epoch: 1, nonce: 'srv-nonce-maa-5d3b8e1f9a27c604' };
const ALLOWED = 'a1'.repeat(48); // the image the relying server allowlists; the real VM is NOT running it
const OTHER_ALLOWED = 'b2'.repeat(48);

/** The compromised root: forged chain, valid-looking, claiming `claimMrtd`, bound to the server's expected binding. */
function forgedIntel(claimMrtd: string, allow: string[]) {
  const q = forgeTdxQuote({ seed: 'compromised-intel', td: { mrTd: Uint8Array.from(Buffer.from(claimMrtd, 'hex')), reportData: attestationBinding(EXPECTED) } });
  const v = createIntelDcapVerifier({
    binding: 'report-data',
    policy: { mrtds: allow },
    trustAnchorRootCaSpkiSha256: q.rootSpkiSha256, // the attacker controls this root: its signatures chain to the pinned SPKI
    resolveEvidence: () => ({ quote: q.quote, collateral: forgeTdxCollateral(q) }),
  });
  return v;
}
const genuineMaa = (allow: string[]) =>
  createAzureMaaVerifier({
    trustedIssuers: ['https://sharedwus.wus.attest.azure.net'],
    trustAnchors: { rootSpkiSha256: [SIGNER_SPKI] },
    policy: { tdxMrtds: allow, runtimeUserDataBinding: true },
    resolveEvidence: () => ({ token: TOKEN, jwks: JWKS }),
  });
const policy = (a: ReturnType<typeof forgedIntel>, b: ReturnType<typeof genuineMaa>, o: { threshold?: number; requireMaa?: boolean } = {}) =>
  createMultiRootVerifier({
    threshold: o.threshold ?? 2,
    roots: [
      { id: 'intel-dcap', verifier: a },
      { id: 'azure-maa', verifier: b, ...(o.requireMaa ? { required: true } : {}) },
    ],
  });
const run = (v: ReturnType<typeof policy>) => v.verify({ document: {} as unknown as AttestationDocument, ctx: {} as never, nowMs: NOW_MS, expected: EXPECTED });

describe('T-028: one compromised root of several cannot carry the policy', () => {
  it('sanity: the forged root really passes on its own (its chain is valid-looking and it is bound)', async () => {
    const r = await forgedIntel(ALLOWED, [ALLOWED]).verify({ document: {} as unknown as AttestationDocument, ctx: {} as never, nowMs: NOW_MS, expected: EXPECTED });
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
    expect(r.ok && r.measured?.runtime_measurement).toBe(ALLOWED);
  });

  it('2-of-2: the forged quote claims the allowlisted image, the genuine root sees the real (non-allowlisted) VM: DENY below threshold', async () => {
    const r = await run(policy(forgedIntel(ALLOWED, [ALLOWED]), genuineMaa([ALLOWED])));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('multi-root attestation below threshold (1/2 independent roots corroborated)');
  });

  it('2-of-2 with the genuine root required: DENY and the reason names the genuine root', async () => {
    const r = await run(policy(forgedIntel(ALLOWED, [ALLOWED]), genuineMaa([ALLOWED]), { requireMaa: true }));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("required attestation root 'azure-maa' failed: TDX MRTD not in policy allowlist");
  });

  it('both roots verify but disagree on the measured identity (forged root claims another allowlisted image): DENY', async () => {
    const r = await run(policy(forgedIntel(OTHER_ALLOWED, [OTHER_ALLOWED]), genuineMaa([REAL_MRTD])));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("multi-root attestation identity conflict: roots 'intel-dcap' and 'azure-maa' disagree on runtime_measurement");
  });

  it('the forged root claims the REAL image and the genuine root agrees: accepted (the genuine root corroborates, nothing was forged)', async () => {
    const r = await run(policy(forgedIntel(REAL_MRTD, [REAL_MRTD]), genuineMaa([REAL_MRTD])));
    expect(r.ok).toBe(true);
    expect(r.ok && r.measured?.runtime_measurement).toBe(REAL_MRTD);
  });

  it('RESIDUAL RISK, pinned: with threshold 1 the compromised root alone is enough, and the label says only `hardware`, never `multi_root`', async () => {
    const v = policy(forgedIntel(ALLOWED, [ALLOWED]), genuineMaa([ALLOWED]), { threshold: 1 });
    const r = await run(v);
    expect(r.ok).toBe(true);
    expect(assuranceLabelOf(v)).toEqual({ level: 'hardware', vendor: 'multi-root:intel-dcap+azure-maa' });
    expect(assuranceLabelOf(policy(forgedIntel(ALLOWED, [ALLOWED]), genuineMaa([ALLOWED])))).toEqual({ level: 'multi_root', vendor: 'multi-root:intel-dcap+azure-maa' });
  });

  it('the forged root bound to a DIFFERENT nonce is rejected by the root itself (a replayed forged quote does not bind)', async () => {
    const v = forgedIntel(ALLOWED, [ALLOWED]);
    const r = await v.verify({ document: {} as unknown as AttestationDocument, ctx: {} as never, nowMs: NOW_MS, expected: { ...EXPECTED, nonce: 'another-nonce' } });
    expect(r.ok).toBe(false);
  });
});
