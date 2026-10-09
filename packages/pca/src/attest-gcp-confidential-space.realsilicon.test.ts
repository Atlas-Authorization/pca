/**
 * REAL-SILICON fixture test for the GCP Confidential Space attestation root.
 *
 * Unlike the synthetic-key coverage in `attest-gcp-confidential-space.test.ts`, this exercises the verifier
 * against GENUINE Google-signed Confidential Space attestation tokens captured from a REAL AMD SEV
 * Confidential VM on Google Cloud (n2d-standard-2, us-central1-c) on 2026-10-08. The workload asked the
 * Confidential Space launcher's teeserver for an OIDC attestation token bound to a PCA nonce
 * (`hex(sha256(attestationBinding(EXPECTED)))`); the token is verified here against a PINNED snapshot of
 * Google's real Confidential Space JWKS (`signer@confidentialspace-sign.iam.gserviceaccount.com`), with a
 * fixed clock inside the tokens' validity window — so the test is deterministic and OFFLINE (no network,
 * no live key rotation) while verifying real P-256/RS256 signatures over genuine silicon evidence.
 *
 * Two tokens are pinned:
 *   - `prod-token.jwt`  — PRODUCTION Confidential Space image → `dbgstat: disabled-since-boot`
 *                         (verifies with `allowDebug: false`, the strong claim).
 *   - `debug-token.jwt` — DEBUG image → `dbgstat: enabled` (used to prove the debug gate rejects it unless
 *                         `allowDebug: true`).
 * See `fixtures/real-gcp-cs/README.md` for the full capture method.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import {
  createGcpConfidentialSpaceVerifier,
  parseGcpCsJwt,
  GCP_CS_DEFAULT_ISSUER,
  type GcpJwks,
} from './attest-gcp-confidential-space';
import type { AttestationDocument, ExpectedAttestationBinding } from './attestation';

const read = (f: string) => readFileSync(resolve(__dirname, '..', 'fixtures', 'real-gcp-cs', f), 'utf8').trim();

const PROD_TOKEN = read('prod-token.jwt');
const DEBUG_TOKEN = read('debug-token.jwt');
const TDX_TOKEN = read('prod-tdx-token.jwt');
const JWKS = JSON.parse(read('google-cs-jwks.json')) as GcpJwks;

/** The exact binding context used to derive the capture nonce (see README / scratch-gcp-nonce). */
const EXPECTED: ExpectedAttestationBinding = {
  holderPub: 'pca-realsilicon-gcp-holder-ed25519',
  grantRef: 'grant_pca_gcp_cs_realsilicon',
  epoch: 1,
  nonce: 'srv-nonce-9f2c7a1e4b8d0536',
};
/** The measured workload image digest (Cloud Build), present as submods.container.image_digest. */
const IMAGE = 'sha256:b1c058a8092d56dd77ec351b9e00b2565fba5e413d0cb08d260a1e40e64ca46e';
/** The workload image digest in the TDX capture (a later rebuild of the same Dockerfile). */
const TDX_IMAGE = 'sha256:6597f3b7a7e742c2098782ea04ae9dd091fa0995ae662708e357a7730540d154';
/** Fixed clock inside both tokens' validity window (prod iat 1791496644 / exp 1791500244). */
const NOW_MS = 1_791_498_000_000;
/** Fixed clock inside the TDX token's validity window (iat 1791500836 / exp 1791504436 — no overlap with the SEV tokens). */
const NOW_TDX_MS = 1_791_502_000_000;

const DOC = {} as unknown as AttestationDocument;
const CTX = {} as never;

function verifier(token: string, over: { allowDebug?: boolean; images?: string[]; issuers?: string[]; tee?: ('sev-snp' | 'tdx')[] } = {}) {
  return createGcpConfidentialSpaceVerifier({
    trustedIssuers: over.issuers ?? [GCP_CS_DEFAULT_ISSUER],
    trustAnchors: { trustedJwks: JWKS }, // trust rooted in Google's REAL published keys (pinned snapshot)
    policy: {
      imageDigests: over.images ?? [IMAGE],
      nonceHash: 'sha256',
      allowDebug: over.allowDebug ?? false,
      ...(over.tee ? { allowedTeeTypes: over.tee } : {}),
    },
    resolveEvidence: () => ({ token, jwks: JWKS }),
  });
}

describe('GCP Confidential Space — REAL silicon (genuine Google-signed tokens, pinned JWKS)', () => {
  it('the pinned JWKS carries the key that signed the captured tokens', () => {
    const kid = parseGcpCsJwt(PROD_TOKEN).header.kid;
    expect(JWKS.keys.some((k) => k.kid === kid)).toBe(true);
  });

  it('PROD token (disabled-since-boot) verifies end-to-end with allowDebug:false', async () => {
    const r = await verifier(PROD_TOKEN).verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected: EXPECTED });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.bound).toBe(true);
      expect(r.hostAsserted?.attestation_type).toBe('sev-snp');
      expect(r.hostAsserted?.hwmodel).toBe('GCP_AMD_SEV');
      expect(r.measured?.runtime_measurement).toBe(IMAGE);
    }
  });

  it('PROD token: tampered signature fails closed', async () => {
    const s = PROD_TOKEN.split('.');
    const sig = Buffer.from(s[2]!, 'base64url');
    sig[0] = (sig[0] ?? 0) ^ 0x01;
    const tampered = `${s[0]}.${s[1]}.${sig.toString('base64url')}`;
    const r = await verifier(tampered).verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected: EXPECTED });
    expect(r.ok).toBe(false);
  });

  it('PROD token: a different holder (wrong binding) fails closed', async () => {
    const r = await verifier(PROD_TOKEN).verify({
      document: DOC, ctx: CTX, nowMs: NOW_MS,
      expected: { ...EXPECTED, holderPub: 'different-holder' },
    });
    expect(r.ok).toBe(false);
  });

  it('PROD token: an image not in the allowlist fails closed', async () => {
    const r = await verifier(PROD_TOKEN, { images: [`sha256:${'0'.repeat(64)}`] })
      .verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected: EXPECTED });
    expect(r.ok).toBe(false);
  });

  it('PROD token: an untrusted issuer fails closed', async () => {
    const r = await verifier(PROD_TOKEN, { issuers: ['https://evil.example'] })
      .verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected: EXPECTED });
    expect(r.ok).toBe(false);
  });

  it('DEBUG token (dbgstat enabled): rejected with allowDebug:false, accepted with allowDebug:true', async () => {
    const rejected = await verifier(DEBUG_TOKEN, { allowDebug: false })
      .verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected: EXPECTED });
    expect(rejected.ok).toBe(false);

    const accepted = await verifier(DEBUG_TOKEN, { allowDebug: true })
      .verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected: EXPECTED });
    expect(accepted.ok).toBe(true);
  });

  // ── Intel TDX (c3-standard-4, TDX) — the second isolation technology Google attests ──
  it('INTEL TDX production token verifies end-to-end (hwmodel GCP_INTEL_TDX → tdx, dbgstat disabled-since-boot)', async () => {
    const r = await verifier(TDX_TOKEN, { images: [TDX_IMAGE] }).verify({ document: DOC, ctx: CTX, nowMs: NOW_TDX_MS, expected: EXPECTED });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.hostAsserted?.attestation_type).toBe('tdx');
      expect(r.hostAsserted?.hwmodel).toBe('GCP_INTEL_TDX');
      expect(r.measured?.runtime_measurement).toBe(TDX_IMAGE);
    }
  });

  it('isolation-type pinning works on real tokens in both directions (SEV token vs TDX policy and vice versa)', async () => {
    const tdxOnly = verifier(PROD_TOKEN, { tee: ['tdx'] });
    const sevAsTdx = await tdxOnly.verify({ document: DOC, ctx: CTX, nowMs: NOW_MS, expected: EXPECTED });
    expect(sevAsTdx.ok).toBe(false);
    if (!sevAsTdx.ok) expect(sevAsTdx.reason).toContain('allowlist'); // rejected for the hardware type, not for the clock
    const sevOnly = verifier(TDX_TOKEN, { images: [TDX_IMAGE], tee: ['sev-snp'] });
    const tdxAsSev = await sevOnly.verify({ document: DOC, ctx: CTX, nowMs: NOW_TDX_MS, expected: EXPECTED });
    expect(tdxAsSev.ok).toBe(false);
    if (!tdxAsSev.ok) expect(tdxAsSev.reason).toContain('allowlist');
  });

  it('TDX token: wrong image allowlist (the SEV image digest) and a relayed binding both fail closed', async () => {
    expect((await verifier(TDX_TOKEN, { images: [IMAGE] }).verify({ document: DOC, ctx: CTX, nowMs: NOW_TDX_MS, expected: EXPECTED })).ok).toBe(false);
    const relayed = await verifier(TDX_TOKEN, { images: [TDX_IMAGE] }).verify({ document: DOC, ctx: CTX, nowMs: NOW_TDX_MS, expected: { ...EXPECTED, epoch: 9 } });
    expect(relayed.ok).toBe(false);
  });
});
