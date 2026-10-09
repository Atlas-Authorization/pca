/**
 * L0 HARDWARE backend — Intel TDX, REAL DCAP quote → `HardwareAttestationVerifier`.
 *
 * `attest-intel-tdx.ts` verifies a genuine DCAP v4 TDX quote (`verifyGenuineTdxQuote`) and
 * `attest-intel-collateral.ts` evaluates Intel PCS collateral (`verifyIntelTdxCollateral`), but both are free
 * functions. THIS module is the glue that makes the real Intel root a first-class
 * `HardwareAttestationVerifier` and a member of the N-of-M multi-root policy.
 *
 * ── WHAT IS VERIFIED (all offline, all vetted primitives) ──────────────────────────────────────────
 *   1. The DCAP quote end to end: PCK chain to the pinned Intel SGX Root CA, QE report under the PCK leaf, the
 *      attestation key endorsed by the QE, the TD quote signature under that key.
 *   2. The PCA binding, in one of two explicit modes:
 *        - `report-data`  — the TD's 64-byte `report_data` equals `attestationBinding(expected)` (guests that control
 *                           report_data: bare-metal / most TDX clouds).
 *        - `azure-runtime-data` — Azure CVMs: the paravisor sets `report_data[0:32] = sha256(runtime-data JSON)` and
 *                           `report_data[32:64] = 0`, and the guest's 64-byte `user-data` lives inside that JSON.
 *                           The verifier checks both the hash AND that `user-data == attestationBinding(expected)`.
 *                           Trust comes from Intel's quote signature alone — no Microsoft service in the path.
 *   3. A NON-EMPTY MRTD allowlist (no accept-all), optional FMSPC / RTMR0 allowlists.
 *   4. Intel PCS collateral: signed TCB info + QE identity + CRLs → evaluated TCB status, accepted by policy
 *      (default UpToDate / SWHardeningNeeded). Collateral is REQUIRED unless `allowMissingCollateral: true` is
 *      set explicitly, in which case the result is labelled `tcb_status: unevaluated`.
 *
 * HONEST SCOPE: classical (ECDSA-P256); not post-quantum. Collateral fetching is the caller's business (see the
 * guarded fetch helpers in attest-intel-collateral's fixtures README for the PCS URLs).
 */
import { createHash } from 'node:crypto';
import { attestationBinding } from './attestation';
import type { AttestationDocument, HardwareAttestationResult, HardwareAttestationVerifier, ExpectedAttestationBinding } from './attestation';
import { verifyGenuineTdxQuote, INTEL_SGX_ROOT_CA_SPKI_SHA256 } from './attest-intel-tdx';
import { verifyIntelTdxCollateral } from './attest-intel-collateral';
import type { IntelCollateralPolicy, IntelTdxCollateral } from './attest-intel-collateral';
import type { VerifyContext } from './pcactn';

export const INTEL_DCAP_SUITE = 'intel-tdx-dcap-ecdsa-p256' as const;

export type IntelDcapBinding = 'report-data' | 'azure-runtime-data';

export interface IntelDcapEvidence {
  /** The raw DCAP quote (v4, ECDSA-P256, TDX). */
  quote: Uint8Array;
  /** `azure-runtime-data` mode: the exact runtime-data JSON bytes whose sha256 is in the quote's report_data. */
  runtimeData?: Uint8Array;
  /** Intel PCS collateral for the quote's FMSPC. */
  collateral?: IntelTdxCollateral;
}

export interface IntelDcapPolicy {
  /** REQUIRED + NON-EMPTY: accepted MRTD values (lowercase hex of the 48-byte TD measurement). */
  mrtds: string[];
  fmspcs?: string[];
  rtmrs?: string[];
  /** Accepted MRSEAM values (hex of the 48-byte TDX-module measurement). Omitted => not gated; if given it must be non-empty. */
  mrSeams?: string[];
  /** Accepted MRSIGNERSEAM values (hex, 48 bytes). Omitted => not gated; if given it must be non-empty. */
  mrSignerSeams?: string[];
  /** INSECURE opt-in: accept a TD with TD_ATTRIBUTES.DEBUG set. Default false. */
  allowDebug?: boolean;
  /** Collateral policy (accepted statuses, minimum tcbEvaluationDataNumber). */
  collateral?: IntelCollateralPolicy;
}

export interface IntelDcapVerifierOptions {
  binding: IntelDcapBinding;
  policy: IntelDcapPolicy;
  /** Pinned Intel SGX Root CA SPKI SHA-256 (hex). Default: Intel's published root. */
  trustAnchorRootCaSpkiSha256?: string;
  /** Explicit opt-out of Intel PCS collateral evaluation. Default false (collateral required). */
  allowMissingCollateral?: boolean;
  /** Evidence seam; if omitted the verifier fails closed. */
  resolveEvidence?: (document: AttestationDocument, ctx: VerifyContext) => IntelDcapEvidence | undefined | Promise<IntelDcapEvidence | undefined>;
}

const HEX = /^[0-9a-f]+$/i;

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
}

/** Check the Azure runtime-data binding: hash relation + `user-data` equality. Returns a failure reason or undefined. */
export function checkAzureRuntimeDataBinding(reportData: Uint8Array, runtimeData: Uint8Array, expected: ExpectedAttestationBinding): string | undefined {
  if (reportData.length !== 64) return 'report_data is not 64 bytes';
  if (!reportData.subarray(32).every((b) => b === 0)) return 'report_data[32:64] is not zero (not an Azure runtime-data hash)';
  const digest = createHash('sha256').update(runtimeData).digest();
  if (!equalBytes(new Uint8Array(digest), reportData.subarray(0, 32))) return 'sha256(runtime data) does not equal the quote report_data';
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(runtimeData).toString('utf8'));
  } catch {
    return 'runtime data is not valid JSON';
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return 'runtime data is not a JSON object';
  const userData = (parsed as Record<string, unknown>)['user-data'];
  if (typeof userData !== 'string' || userData.length !== 128 || !HEX.test(userData)) return 'runtime data carries no 64-byte hex user-data';
  let want: Uint8Array;
  try {
    want = attestationBinding(expected);
  } catch (e) {
    return `binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`;
  }
  if (!equalBytes(new Uint8Array(Buffer.from(userData, 'hex')), want)) return 'runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)';
  return undefined;
}

/** Build a `HardwareAttestationVerifier` for genuine Intel TDX DCAP quotes. Fails closed. */
export function createIntelDcapVerifier(opts: IntelDcapVerifierOptions): HardwareAttestationVerifier {
  if (opts?.binding !== 'report-data' && opts?.binding !== 'azure-runtime-data') throw new TypeError("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'");
  if (!Array.isArray(opts.policy?.mrtds) || opts.policy.mrtds.length === 0) throw new TypeError('createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)');
  const mrtds = opts.policy.mrtds.map((m) => m.toLowerCase());
  if (mrtds.some((m) => !HEX.test(m) || m.length !== 96)) throw new TypeError('createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)');
  for (const [name, list] of [['mrSeams', opts.policy.mrSeams], ['mrSignerSeams', opts.policy.mrSignerSeams]] as const) {
    if (list === undefined) continue;
    if (!Array.isArray(list) || list.length === 0) throw new TypeError(`createIntelDcapVerifier: policy.${name}, if given, must be a NON-EMPTY list`);
    if (list.some((m) => typeof m !== 'string' || !HEX.test(m) || m.length !== 96)) throw new TypeError(`createIntelDcapVerifier: every ${name} entry must be 96 hex chars (48 bytes)`);
  }
  const pin = (opts.trustAnchorRootCaSpkiSha256 ?? INTEL_SGX_ROOT_CA_SPKI_SHA256).toLowerCase();

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no Intel DCAP evidence resolver configured (fail closed)');
        const ev = await opts.resolveEvidence(input.document, input.ctx);
        if (!ev || !(ev.quote instanceof Uint8Array)) return fail('no Intel DCAP quote for this action');
        if (!input.expected) return fail('no expected attestation binding supplied');

        const q = await verifyGenuineTdxQuote({
          quote: ev.quote,
          trustAnchorRootCaSpkiSha256: pin,
          nowMs: input.nowMs,
          policy: { mrtds, ...(opts.policy.mrSeams ? { mrSeams: opts.policy.mrSeams } : {}), ...(opts.policy.mrSignerSeams ? { mrSignerSeams: opts.policy.mrSignerSeams } : {}), ...(opts.policy.fmspcs ? { fmspcs: opts.policy.fmspcs } : {}), ...(opts.policy.rtmrs ? { rtmrs: opts.policy.rtmrs } : {}), ...(opts.policy.allowDebug === true ? { allowDebug: true } : {}) },
        });
        if (!q.ok || !q.report || !q.measured || !q.fmspc) return fail(`DCAP quote invalid: ${q.reason ?? 'unknown'}`);

        // PCA binding
        if (opts.binding === 'report-data') {
          let want: Uint8Array;
          try {
            want = attestationBinding(input.expected);
          } catch (e) {
            return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
          }
          if (!equalBytes(q.report.reportData, want)) return fail('report_data does not bind holder/grant/epoch/nonce');
        } else {
          if (!(ev.runtimeData instanceof Uint8Array)) return fail('azure-runtime-data binding needs the runtime-data JSON bytes');
          const why = checkAzureRuntimeDataBinding(q.report.reportData, ev.runtimeData, input.expected);
          if (why) return fail(why);
        }

        // Intel PCS collateral → TCB status
        const hostAsserted: Record<string, string> = { attestation_type: 'tdx-dcap', fmspc: q.fmspc };
        if (ev.collateral) {
          const c = await verifyIntelTdxCollateral({
            quote: ev.quote,
            collateral: ev.collateral,
            now: new Date(input.nowMs),
            trustAnchorRootCaSpkiSha256: pin,
            ...(opts.policy.allowDebug === true ? { allowDebug: true } : {}),
            ...(opts.policy.collateral ? { policy: opts.policy.collateral } : {}),
          });
          if (c.status) hostAsserted.tcb_status = c.status;
          if (c.advisoryIds && c.advisoryIds.length > 0) hostAsserted.advisory_ids = c.advisoryIds.join(',');
          if (!c.ok) return fail(`Intel collateral: ${c.reason ?? 'rejected'}`);
        } else if (opts.allowMissingCollateral === true) {
          hostAsserted.tcb_status = 'unevaluated';
        } else {
          return fail('Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)');
        }

        return { ok: true, bound: true, measured: q.measured, hostAsserted };
      } catch (e) {
        return fail(`intel-dcap verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}
