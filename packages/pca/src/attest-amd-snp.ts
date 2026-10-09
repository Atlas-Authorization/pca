/**
 * L0 HARDWARE backend — AMD SEV-SNP, REAL report → `HardwareAttestationVerifier` with per-family ARK pins.
 *
 * `hardware-sevsnp.ts` verifies a genuine SEV-SNP report (`verifyGenuineSevSnpReport`: VCEK → ASK → ARK chain,
 * ECDSA-P384 report signature, VCEK↔report binding) but only as a free function, with an ARK default that is
 * MILAN-ONLY. Real silicon showed why that matters: Azure DCasv5 in italynorth is **Genoa**, and AMD publishes a
 * separate root key per processor family. This module is the glue that makes the real AMD root a first-class member
 * of the N-of-M policy, mirroring `attest-intel-dcap.ts`.
 *
 * ── ROOT PINS ─────────────────────────────────────────────────────────────────────────────────────
 * `AMD_ARK_SPKI_SHA384` holds the SPKI SHA-384 of each family's ARK as published by AMD's key distribution service
 * (`https://kdsintf.amd.com/vcek/v1/<Family>/cert_chain`), captured 2026-10-08. The Milan value is byte-identical to
 * the constant `hardware-sevsnp.ts` already carries, and the Genoa value is identical to the chain Azure's metadata
 * service served to a real Genoa CVM. The family is a REQUIRED option: the verifier never infers which root to trust
 * from the evidence.
 *
 * ── BINDING (explicit modes) ──────────────────────────────────────────────────────────────────────
 *   - `report-data`        — report_data === attestationBinding(expected) (guests that control report_data).
 *   - `azure-runtime-data` — Azure CVMs: report_data[0:32] = sha256(runtime-data JSON), [32:64] = 0, and the guest's
 *                            64-byte `user-data` inside that JSON must equal the PCA binding. Trust comes from AMD's
 *                            signature alone — no Microsoft service in the path.
 *
 * HONEST SCOPE: classical (ECDSA-P384 / RSA-PSS chain); not post-quantum. A NON-EMPTY measurement allowlist is
 * required (no accept-all). VCEK revocation / TCB-floor policy beyond `minReportedTcb` is the caller's.
 */
import type { AttestationDocument, ExpectedAttestationBinding, HardwareAttestationResult, HardwareAttestationVerifier } from './attestation';
import { verifyGenuineSevSnpReport, toHex } from './hardware-sevsnp';
import type { SevSnpPolicy } from './hardware-sevsnp';
import { checkAzureRuntimeDataBinding } from './attest-intel-dcap';
import type { VerifyContext } from './pcactn';

export const AMD_SNP_SUITE = 'amd-sev-snp-ecdsa-p384' as const;

export type AmdFamily = 'milan' | 'genoa' | 'turin';
export type AmdSnpBinding = 'report-data' | 'azure-runtime-data';

/** SPKI SHA-384 (lowercase hex) of each family's ARK, from AMD KDS `cert_chain`, captured 2026-10-08. */
export const AMD_ARK_SPKI_SHA384: Readonly<Record<AmdFamily, string>> = {
  milan: '1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e',
  genoa: '32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880',
  turin: '3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5',
};

export interface AmdSnpEvidence {
  /** The raw 1184-byte SEV-SNP ATTESTATION_REPORT (on Azure: HCL report bytes [32, 32+1184)). */
  report: Uint8Array;
  /** The VCEK certificate, DER. */
  vcekDer: Uint8Array;
  /** ASK + ARK, PEM bundle. */
  askArkPem: string;
  /** `azure-runtime-data` mode: the exact runtime-data JSON bytes whose sha256 is in report_data. */
  runtimeData?: Uint8Array;
}

export interface AmdSnpVerifierOptions {
  family: AmdFamily;
  binding: AmdSnpBinding;
  /** `measurements` is REQUIRED + NON-EMPTY (lowercase hex of the 48-byte launch measurement). */
  policy: SevSnpPolicy;
  /** Tolerated clock skew (ms) on the certificate validity windows. Default 0. */
  clockSkewMs?: number;
  resolveEvidence?: (document: AttestationDocument, ctx: VerifyContext) => AmdSnpEvidence | undefined | Promise<AmdSnpEvidence | undefined>;
}

/** Convert a single PEM certificate to DER. */
export function pemToDer(pem: string): Uint8Array {
  const m = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  if (!m?.[1]) throw new RangeError('pemToDer: no certificate found');
  return new Uint8Array(Buffer.from(m[1].replace(/\s+/g, ''), 'base64'));
}

/** Build a `HardwareAttestationVerifier` for genuine AMD SEV-SNP reports. Fails closed. */
export function createAmdSnpVerifier(opts: AmdSnpVerifierOptions): HardwareAttestationVerifier {
  const pin = opts?.family ? AMD_ARK_SPKI_SHA384[opts.family] : undefined;
  if (!pin) throw new TypeError("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'");
  if (opts.binding !== 'report-data' && opts.binding !== 'azure-runtime-data') throw new TypeError("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'");
  if (!Array.isArray(opts.policy?.measurements) || opts.policy.measurements.length === 0) {
    throw new TypeError('createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
  }

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no AMD SEV-SNP evidence resolver configured (fail closed)');
        const ev = await opts.resolveEvidence(input.document, input.ctx);
        if (!ev || !(ev.report instanceof Uint8Array) || !(ev.vcekDer instanceof Uint8Array) || typeof ev.askArkPem !== 'string') return fail('no AMD SEV-SNP evidence for this action');
        if (!input.expected) return fail('no expected attestation binding supplied');
        const expected: ExpectedAttestationBinding = input.expected;

        const direct = opts.binding === 'report-data';
        const r = await verifyGenuineSevSnpReport({
          report: ev.report,
          vcekDer: ev.vcekDer,
          askArkPem: ev.askArkPem,
          trustAnchorArkSpkiSha384: pin,
          nowMs: input.nowMs,
          ...(opts.clockSkewMs !== undefined ? { clockSkewMs: opts.clockSkewMs } : {}),
          policy: opts.policy,
          ...(direct ? { expected } : {}),
        });
        if (!r.ok || !r.report || !r.measured) return fail(`SEV-SNP report invalid: ${r.reason ?? 'unknown'}`);

        if (!direct) {
          if (!(ev.runtimeData instanceof Uint8Array)) return fail('azure-runtime-data binding needs the runtime-data JSON bytes');
          const why = checkAzureRuntimeDataBinding(r.report.report_data, ev.runtimeData, expected);
          if (why) return fail(why);
        }

        return {
          ok: true,
          bound: true,
          measured: r.measured,
          hostAsserted: { attestation_type: 'amd-sev-snp', family: opts.family, measurement: toHex(r.report.measurement) },
        };
      } catch (e) {
        return fail(`amd-snp verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}
