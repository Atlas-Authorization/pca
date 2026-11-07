/**
 * Language-neutral wire form of the vendor attestation verifiers (conformance/attestation-evidence-vectors.json) and the
 * TypeScript REFERENCE that turns a serialisable `(vendor, config, evidence)` triple into a real verifier run.
 * TEST/TOOLING ONLY: the native SDKs (Go, Rust, Python) implement the same `verifier_from_config(vendor, config)` factory
 * from `VERIFIER_CONFIG_SCHEMA` and must answer every vector exactly as {@link runAttestationVector} does here.
 *
 * Conventions (also written into the vector file header):
 *   - bytes are standard base64 (RFC 4648, padded) strings; hex is lowercase; PEM and JSON documents stay strings;
 *   - 64-bit integers that exceed 2^53 (SEV-SNP TCB floors) are decimal strings;
 *   - any string in `config` / `evidence` may be replaced by `{"$blob": "<id>"}`; `hydrateBlobs` undoes that (the file
 *     stores every long value once under `blobs`);
 *   - `identity_overrides` is the data form of the TypeScript `deriveIdentity` callbacks: after a successful verification
 *     the keys of that object replace the same keys of the verifier's `measured` identity.
 */
import { createAmdSnpVerifier, AMD_ARK_SPKI_SHA384 } from '../attest-amd-snp';
import { createAzureMaaVerifier } from '../attest-azure-maa';
import { createGcpConfidentialSpaceVerifier } from '../attest-gcp-confidential-space';
import { createIntelDcapVerifier } from '../attest-intel-dcap';
import { createNvidiaSpdmVerifier } from '../attest-nvidia-spdm';
import { nvidiaCollateralHook } from '../attest-nvidia-rim';
import type { AttestationDocument, ExpectedAttestationBinding, HardwareAttestationResult, HardwareAttestationVerifier } from '../attestation';
import { derValidityMs, parseDerTime } from '../x509-validity';
import { checkChainRoles, parseCertExtensions, parseTbsExtensions, readCertRoleInfo, tbsOfCertificate, unrecognisedCriticalExtension } from '../x509-strict';

export type Vendor = 'amd-sev-snp' | 'intel-tdx-dcap' | 'azure-maa' | 'gcp-confidential-space' | 'nvidia-gpu-spdm';
export const VENDORS: readonly Vendor[] = ['amd-sev-snp', 'intel-tdx-dcap', 'azure-maa', 'gcp-confidential-space', 'nvidia-gpu-spdm'];

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
export type JsonObject = { [k: string]: Json };

export interface WireBinding {
  holderPub: string;
  grantRef: string;
  epoch: number;
  nonce: string;
}

/** The verdict a native verifier must reproduce (TypeScript `HardwareAttestationResult`, JSON-normalised) or a construction refusal. */
export type WireResult = { construct_error: string } | { ok: boolean; bound?: boolean; reason?: string; measured?: JsonObject; hostAsserted?: Record<string, string> };

export const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');
export const unb64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64'));
const optBytes = (v: unknown): Uint8Array | undefined => (typeof v === 'string' ? unb64(v) : undefined);

// ───────────────────────────────────────────────────────────── blobs
export interface BlobDoc {
  blobs: Record<string, string>;
}
/** Replace every `{"$blob": id}` in `x` with the string stored under `blobs[id]` (throws on an unknown id). */
export function hydrateBlobs<T>(x: T, blobs: Record<string, string>): T {
  if (Array.isArray(x)) return x.map((e) => hydrateBlobs(e, blobs)) as unknown as T;
  if (x !== null && typeof x === 'object') {
    const o = x as Record<string, unknown>;
    const keys = Object.keys(o);
    if (keys.length === 1 && keys[0] === '$blob') {
      const v = blobs[o['$blob'] as string];
      if (v === undefined) throw new Error(`unknown blob ${String(o['$blob'])}`);
      return v as unknown as T;
    }
    return Object.fromEntries(keys.map((k) => [k, hydrateBlobs(o[k], blobs)])) as unknown as T;
  }
  return x;
}

// ───────────────────────────────────────────────────────────── the verifier configuration schema (documentation + natives' contract)
type Field = { type: string; required?: boolean; desc: string };
export const VERIFIER_CONFIG_SCHEMA: Record<Vendor, { suite: string; label: { level: 'hardware'; vendor: string }; config: Record<string, Field>; evidence: Record<string, Field> }> = {
  'amd-sev-snp': {
    suite: 'amd-sev-snp-ecdsa-p384',
    label: { level: 'hardware', vendor: 'amd-sev-snp' },
    config: {
      family: { type: "'milan'|'genoa'|'turin'", required: true, desc: "Selects the pinned ARK (SPKI SHA-384). Any other value: construct_error \"createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'\"." },
      binding: { type: "'report-data'|'azure-runtime-data'", required: true, desc: 'report-data: report_data == attestationBinding(expected). azure-runtime-data: report_data[0:32] == sha256(runtimeData), [32:64] == 0 and runtimeData JSON user-data == the binding.' },
      'policy.measurements': { type: 'hex[]', required: true, desc: 'NON-EMPTY allowlist of the 48-byte launch measurement (case-insensitive). Empty or missing: construct_error.' },
      'policy.hostData': { type: 'hex[]', desc: 'Optional HOST_DATA allowlist (empty/omitted: not gated).' },
      'policy.chipIds': { type: 'hex[]', desc: 'Optional CHIP_ID allowlist (empty/omitted: not gated).' },
      'policy.allowDebug': { type: 'bool', desc: 'Accept a guest policy with DEBUG bit 19 set (default false).' },
      'policy.minGuestSvn': { type: 'int', desc: 'Minimum GUEST_SVN.' },
      'policy.minReportedTcb': { type: 'decimal string (u64)', desc: 'Minimum REPORTED_TCB as a whole u64.' },
      'policy.minCommittedTcb': { type: 'decimal string (u64)', desc: 'Minimum COMMITTED_TCB.' },
      'policy.minLaunchTcb': { type: 'decimal string (u64)', desc: 'Minimum LAUNCH_TCB.' },
      'policy.requireVmpl': { type: "int|'any'", desc: 'Required VMPL (default 0).' },
      'policy.requireEcdsaP384': { type: 'bool', desc: 'Require SIGNATURE_ALGO == 1 (default true; false only disables that check).' },
      clockSkewMs: { type: 'int', desc: 'Skew applied to both ends of every certificate validity window (default 0; negative or non-finite: chain refused).' },
      trustAnchorArkSpkiSha384: { type: 'hex', desc: 'CONFORMANCE HARNESS ONLY: replaces the built-in pin of `family` (the synthetic AMD-format chains are rooted in a test ARK). The TypeScript production API has no such option; the reference swaps the family pin at construction.' },
      identity_overrides: { type: 'object', desc: 'Keys merged over the default measured identity {model_id:"", weights_digest:"", weights_measured:false, runtime_measurement:hex(measurement), operator:hex(chip_id)}.' },
    },
    evidence: {
      report: { type: 'base64', required: true, desc: 'The raw ATTESTATION_REPORT (exactly 1184 bytes to verify).' },
      vcekDer: { type: 'base64', required: true, desc: 'VCEK certificate, DER.' },
      askArkPem: { type: 'string', required: true, desc: 'ASK then ARK, PEM bundle.' },
      runtimeData: { type: 'base64', desc: 'azure-runtime-data mode: the exact runtime-data JSON bytes.' },
    },
  },
  'intel-tdx-dcap': {
    suite: 'intel-tdx-dcap-ecdsa-p256',
    label: { level: 'hardware', vendor: 'intel-dcap' },
    config: {
      binding: { type: "'report-data'|'azure-runtime-data'", required: true, desc: 'As for SEV-SNP, on the TD report_data.' },
      'policy.mrtds': { type: 'hex[]', required: true, desc: 'NON-EMPTY, every entry 96 hex chars (lowercased). Else construct_error.' },
      'policy.fmspcs': { type: 'hex[]', desc: 'Optional FMSPC allowlist (omitted: not gated).' },
      'policy.rtmrs': { type: 'hex[]', desc: 'Optional RTMR0 allowlist (omitted: not gated).' },
      'policy.mrSeams': { type: 'hex[]', desc: 'Optional MRSEAM allowlist; if present it must be a non-empty list of 96-hex entries.' },
      'policy.mrSignerSeams': { type: 'hex[]', desc: 'Optional MRSIGNERSEAM allowlist; same rule.' },
      'policy.allowDebug': { type: 'bool', desc: 'Accept TD_ATTRIBUTES.DEBUG (default false). Also forwarded to the collateral check.' },
      'policy.collateral.acceptStatuses': { type: 'string[]', desc: 'Accepted TCB statuses (default UpToDate, SWHardeningNeeded).' },
      'policy.collateral.minTcbEvaluationDataNumber': { type: 'int', desc: 'Minimum tcbEvaluationDataNumber of TCB info and QE identity.' },
      trustAnchorRootCaSpkiSha256: { type: 'hex', desc: "Pinned Intel SGX Root CA SPKI SHA-256 (default Intel's published root a0af0312...a49e). Also pins the collateral issuer chains." },
      allowMissingCollateral: { type: 'bool', desc: 'Explicit opt-out of PCS collateral (default false: collateral required).' },
      identity_overrides: { type: 'object', desc: 'Merged over the default measured identity (runtime_measurement = hex(MRTD), other fields empty/false).' },
    },
    evidence: {
      quote: { type: 'base64', required: true, desc: 'Raw DCAP v4 TDX quote.' },
      runtimeData: { type: 'base64', desc: 'azure-runtime-data mode.' },
      collateral: { type: 'object', desc: '{tcbInfoJson, tcbInfoIssuerChainPem, qeIdentityJson, qeIdentityIssuerChainPem (strings), pckCrlDer, rootCrlDer (base64)}.' },
    },
  },
  'azure-maa': {
    suite: 'azure-maa-jwt',
    label: { level: 'hardware', vendor: 'azure-maa' },
    config: {
      trustedIssuers: { type: 'string[]', required: true, desc: 'The token iss must equal one entry exactly. Non-empty.' },
      'trustAnchors.rootSpkiSha256': { type: 'hex[]', desc: 'SPKI SHA-256 pins; a chain cert matching one is the anchor.' },
      'trustAnchors.rootCertsPem': { type: 'PEM[]', desc: 'External root certificates; the chain top must be signed by one. At least one of the two anchor lists must be non-empty.' },
      'policy.sevSnpMeasurements': { type: 'hex[]', desc: 'Accepted launch measurements (sevsnpvm tokens).' },
      'policy.tdxMrtds': { type: 'hex[]', desc: 'Accepted MRTDs (tdxvm tokens). At least one of the two lists non-empty.' },
      'policy.sevSnpHostData': { type: 'hex[]', desc: 'Optional host-data allowlist.' },
      'policy.tdxRtmrs': { type: 'hex[]', desc: 'Optional RTMR0 allowlist.' },
      'policy.sevSnpMinTcb': { type: '{bootloader?,snp?,microcode?,tee?: int}', desc: 'Minimum SVN claims; a configured floor needs the claim present and an integer.' },
      'policy.allowDebug': { type: 'bool', desc: 'Accept debuggable guests (default false).' },
      'policy.runtimeUserDataBinding': { type: 'bool', desc: 'Bind through x-ms-runtime.user-data instead of the report-data claim.' },
      'policy.tdxAllowedTcbStatuses': { type: 'string[]', desc: 'Accepted attester_tcb_status values (default UpToDate, SWHardeningNeeded); applied only when the claim is present.' },
      'policy.reportDataHash': { type: "'none'|'sha256'|'sha512'", desc: 'Hash applied to the binding before comparing with the report-data claim.' },
      clockSkewMs: { type: 'int', desc: 'Skew for the token window (rounded up to whole seconds) and certificate validity (default 0).' },
      identity_overrides: { type: 'object', desc: 'Merged over the default measured identity (runtime_measurement = the measurement/MRTD claim lowercased).' },
    },
    evidence: {
      token: { type: 'string', required: true, desc: 'Compact JWS.' },
      jwks: { type: '{keys:[{kid,kty,alg,x5c[]}]}', desc: 'Instance JWKS; without it the header x5c is used.' },
    },
  },
  'gcp-confidential-space': {
    suite: 'gcp-confidential-space-jwt',
    label: { level: 'hardware', vendor: 'gcp-confidential-space' },
    config: {
      trustedIssuers: { type: 'string[]', required: true, desc: 'Exact iss match. Non-empty.' },
      'trustAnchors.trustedJwks': { type: '{keys:[JWK]}', desc: 'Pinned signing keys (RSA n/e, EC x/y or x5c leaf), matched by kid.' },
      'trustAnchors.trustedKeySpki': { type: 'hex[]', desc: 'SPKI SHA-256 pins.' },
      'trustAnchors.rootCertsPem': { type: 'PEM[]', desc: 'Roots for an x5c chain. At least one anchor of any kind is required.' },
      'policy.imageDigests': { type: 'string[]', required: true, desc: 'NON-EMPTY allowlist of submods.container.image_digest (case-insensitive).' },
      'policy.allowedTeeTypes': { type: "('sev-snp'|'tdx')[]", desc: 'Optional pin; when present it must be non-empty.' },
      'policy.expectedSwName': { type: 'string', desc: "Default 'CONFIDENTIAL_SPACE'." },
      'policy.allowedSwVersions': { type: 'string[]', desc: 'Any intersection with swversion accepts.' },
      'policy.allowDebug': { type: 'bool', desc: "Accept dbgstat other than 'disabled-since-boot'." },
      'policy.nonceHash': { type: "'none'|'sha256'|'sha512'", desc: 'Hash applied to the binding before comparing with eat_nonce.' },
      clockSkewMs: { type: 'int', desc: 'As for MAA.' },
      identity_overrides: { type: 'object', desc: 'Merged over the default measured identity (runtime_measurement = image_digest).' },
    },
    evidence: {
      token: { type: 'string', required: true, desc: 'Compact JWS.' },
      jwks: { type: '{keys:[JWK]}', desc: 'Issuer JWKS; a key found only here must corroborate an anchor.' },
    },
  },
  'nvidia-gpu-spdm': {
    suite: 'nvidia-gpu-spdm-ecdsa-p384-sha384',
    label: { level: 'hardware', vendor: 'nvidia-spdm' },
    config: {
      rootSpkiSha256: { type: 'hex[]', required: true, desc: 'Pinned NVIDIA Device Identity CA root SPKI SHA-256. Non-empty.' },
      'policy.measurements': { type: '{ "<block index>": hex digest }', desc: 'Pinned SPDM measurement blocks (SHA-384). May be empty ONLY when `collateral` is configured.' },
      'policy.leafSubjectIncludes': { type: 'string', desc: 'Required substring of the device leaf subject.' },
      'collateral.rimRootSpkiSha256': { type: 'hex[]', desc: 'Installs the RIM/CRL/OCSP post-verification hook (tag collateral:*). Non-empty pins required.' },
      'collateral.revocation': { type: "'crl'|'ocsp'|'both'", desc: "Revocation evidence REQUIRED (default 'crl'); supplied evidence is always enforced." },
      'collateral.requireCrls': { type: 'bool', desc: 'Legacy: false makes CRLs optional when `revocation` is absent.' },
      'collateral.requireCrlIssuers': { type: 'string[]', desc: 'Issuer subject substrings that must have a verified CRL.' },
      'collateral.firmware': { type: '{minDriverVersion?, minVbiosVersion?, denyDriverVersions?, denyVbiosVersions?}', desc: 'Firmware floor / deny list on the GPU-reported versions.' },
      identity_overrides: { type: 'object', desc: 'Merged over the default (all-empty) measured identity.' },
    },
    evidence: {
      evidence: { type: 'base64', required: true, desc: 'SPDM request || response transcript.' },
      certChainPem: { type: 'string', required: true, desc: 'Device chain PEM, leaf first.' },
      collateral: { type: 'object', desc: '{driverRimXml, vbiosRimXml (strings), crls?: base64[], ocsp?: base64[]} handed to the collateral hook; absent while `collateral` is configured: "no RIM collateral supplied for this report".' },
    },
  },
};

// ───────────────────────────────────────────────────────────── building a verifier from the wire config
type Obj = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const big = (v: unknown): bigint | undefined => (v === undefined ? undefined : BigInt(v as string));

function amdPolicy(p: Obj): Obj {
  const out: Obj = { ...p };
  for (const k of ['minReportedTcb', 'minCommittedTcb', 'minLaunchTcb']) if (p[k] !== undefined) out[k] = big(p[k]);
  return out;
}

export function evidenceFor(vendor: Vendor, ev: Obj | null | undefined): unknown {
  if (ev === null || ev === undefined) return undefined;
  switch (vendor) {
    case 'amd-sev-snp':
      return { ...(ev['report'] !== undefined ? { report: unb64(ev['report']) } : {}), ...(ev['vcekDer'] !== undefined ? { vcekDer: unb64(ev['vcekDer']) } : {}), ...(ev['askArkPem'] !== undefined ? { askArkPem: ev['askArkPem'] } : {}), ...(optBytes(ev['runtimeData']) ? { runtimeData: optBytes(ev['runtimeData']) } : {}) };
    case 'intel-tdx-dcap': {
      const c = ev['collateral'] as Obj | undefined;
      return {
        ...(ev['quote'] !== undefined ? { quote: unb64(ev['quote']) } : {}),
        ...(optBytes(ev['runtimeData']) ? { runtimeData: optBytes(ev['runtimeData']) } : {}),
        ...(c ? { collateral: { tcbInfoJson: c['tcbInfoJson'], tcbInfoIssuerChainPem: c['tcbInfoIssuerChainPem'], qeIdentityJson: c['qeIdentityJson'], qeIdentityIssuerChainPem: c['qeIdentityIssuerChainPem'], pckCrlDer: unb64(c['pckCrlDer']), rootCrlDer: unb64(c['rootCrlDer']) } } : {}),
      };
    }
    case 'azure-maa':
    case 'gcp-confidential-space':
      return { ...(ev['token'] !== undefined ? { token: ev['token'] } : {}), ...(ev['jwks'] !== undefined ? { jwks: ev['jwks'] } : {}) };
    case 'nvidia-gpu-spdm':
      return { ...(ev['evidence'] !== undefined ? { evidence: unb64(ev['evidence']) } : {}), ...(ev['certChainPem'] !== undefined ? { certChainPem: ev['certChainPem'] } : {}) };
  }
}

/**
 * Build the TypeScript reference verifier for `(vendor, config)`. `evidence` (the wire object, or null for "no evidence for
 * this action") is what the verifier's evidence resolver answers. Throws the constructor's own error for a refused config.
 */
export function verifierFromConfig(vendor: Vendor, config: Obj, evidence: Obj | null | undefined): HardwareAttestationVerifier {
  const resolveEvidence = () => evidenceFor(vendor, evidence) as never;
  let v: HardwareAttestationVerifier;
  switch (vendor) {
    case 'amd-sev-snp': {
      const pinOverride = config['trustAnchorArkSpkiSha384'] as string | undefined;
      const table = AMD_ARK_SPKI_SHA384 as Record<string, string>;
      const fam = config['family'] as string;
      const saved = table[fam];
      try {
        if (pinOverride !== undefined && fam in table) table[fam] = pinOverride; // the pin is read once, at construction
        v = createAmdSnpVerifier({ family: config['family'], binding: config['binding'], policy: amdPolicy(config['policy'] ?? {}), ...(config['clockSkewMs'] !== undefined ? { clockSkewMs: config['clockSkewMs'] } : {}), resolveEvidence } as never);
      } finally {
        if (pinOverride !== undefined && saved !== undefined) table[fam] = saved;
      }
      break;
    }
    case 'intel-tdx-dcap':
      v = createIntelDcapVerifier({
        binding: config['binding'],
        policy: config['policy'],
        ...(config['trustAnchorRootCaSpkiSha256'] !== undefined ? { trustAnchorRootCaSpkiSha256: config['trustAnchorRootCaSpkiSha256'] } : {}),
        ...(config['allowMissingCollateral'] !== undefined ? { allowMissingCollateral: config['allowMissingCollateral'] } : {}),
        resolveEvidence,
      } as never);
      break;
    case 'azure-maa':
      v = createAzureMaaVerifier({ trustedIssuers: config['trustedIssuers'], trustAnchors: config['trustAnchors'], policy: config['policy'], ...(config['clockSkewMs'] !== undefined ? { clockSkewMs: config['clockSkewMs'] } : {}), resolveEvidence } as never);
      break;
    case 'gcp-confidential-space':
      v = createGcpConfidentialSpaceVerifier({ trustedIssuers: config['trustedIssuers'], trustAnchors: config['trustAnchors'], policy: config['policy'], ...(config['clockSkewMs'] !== undefined ? { clockSkewMs: config['clockSkewMs'] } : {}), resolveEvidence } as never);
      break;
    case 'nvidia-gpu-spdm': {
      const col = config['collateral'] as Obj | undefined;
      const c = (evidence as Obj | null | undefined)?.['collateral'] as Obj | undefined;
      const bundle = c ? { driverRimXml: c['driverRimXml'], vbiosRimXml: c['vbiosRimXml'], ...(c['crls'] ? { crls: (c['crls'] as string[]).map(unb64) } : {}), ...(c['ocsp'] ? { ocsp: (c['ocsp'] as string[]).map(unb64) } : {}) } : undefined;
      v = createNvidiaSpdmVerifier({
        rootSpkiSha256: config['rootSpkiSha256'],
        policy: { measurements: config['policy']?.['measurements'] ?? {}, ...(config['policy']?.['leafSubjectIncludes'] !== undefined ? { leafSubjectIncludes: config['policy']['leafSubjectIncludes'] } : {}) },
        resolveEvidence,
        ...(col ? { postVerify: nvidiaCollateralHook({ rimRootSpkiSha256: col['rimRootSpkiSha256'], resolve: () => bundle as never, ...(col['revocation'] !== undefined ? { revocation: col['revocation'] } : {}), ...(col['requireCrls'] !== undefined ? { requireCrls: col['requireCrls'] } : {}), ...(col['requireCrlIssuers'] !== undefined ? { requireCrlIssuers: col['requireCrlIssuers'] } : {}), ...(col['firmware'] !== undefined ? { firmware: col['firmware'] } : {}) }) } : {}),
      } as never);
      break;
    }
  }
  const ov = config['identity_overrides'] as Obj | undefined;
  if (!ov) return v;
  return { verify: async (i) => { const r = await v.verify(i); return r.ok && r.measured ? { ...r, measured: { ...r.measured, ...ov } } : r; } } as HardwareAttestationVerifier;
}

const DOC = {} as unknown as AttestationDocument;
const CTX = {} as never;

/** Run one vector's `(vendor, config, evidence, now, expected_binding)` through the TypeScript reference. */
export async function runAttestationVector(v: { vendor: Vendor; config: Obj; evidence: Obj | null; now: number; expected_binding: WireBinding | null }): Promise<WireResult> {
  let verifier: HardwareAttestationVerifier;
  try {
    verifier = verifierFromConfig(v.vendor, v.config, v.evidence);
  } catch (e) {
    return { construct_error: e instanceof Error ? e.message : String(e) };
  }
  const r: HardwareAttestationResult = await verifier.verify({ document: DOC, ctx: CTX, nowMs: v.now, expected: v.expected_binding as ExpectedAttestationBinding });
  return JSON.parse(JSON.stringify(r)) as WireResult;
}

// ───────────────────────────────────────────────────────────── x509 unit rows
export type X509Fn = 'read_cert_role_info' | 'parse_cert_extensions' | 'parse_tbs_extensions' | 'unrecognised_critical_extension' | 'check_chain_roles' | 'der_validity_ms' | 'parse_der_time' | 'tbs_of_certificate';
export type X509Result = { ok: true; value: Json } | { ok: false; error: string };

const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
/** Run one x509 unit row. `input` members are base64 bytes (`cert`, `tbs`, `chain[]`) or plain values. */
export function runX509Vector(fn: X509Fn, input: Obj): X509Result {
  try {
    switch (fn) {
      case 'read_cert_role_info':
        return { ok: true, value: JSON.parse(JSON.stringify(readCertRoleInfo(unb64(input['cert'])))) };
      case 'parse_cert_extensions':
      case 'parse_tbs_extensions': {
        const m = fn === 'parse_cert_extensions' ? parseCertExtensions(unb64(input['cert'])) : parseTbsExtensions(unb64(input['tbs']));
        return { ok: true, value: [...m.entries()].map(([oid, e]) => ({ oid, critical: e.critical, value: hex(e.value) })) };
      }
      case 'tbs_of_certificate':
        return { ok: true, value: b64(tbsOfCertificate(unb64(input['cert']))) };
      case 'unrecognised_critical_extension':
        return { ok: true, value: unrecognisedCriticalExtension(unb64(input['cert']), input['recognised'] ? new Set<string>(input['recognised']) : undefined) ?? null };
      case 'check_chain_roles':
        return { ok: true, value: checkChainRoles((input['chain'] as string[]).map(unb64)) ?? null };
      case 'der_validity_ms': {
        const r = derValidityMs(unb64(input['cert']));
        return { ok: true, value: { from: Number.isFinite(r.from) ? r.from : null, to: Number.isFinite(r.to) ? r.to : null } };
      }
      case 'parse_der_time': {
        const t = parseDerTime(input['tag'], input['text']);
        return { ok: true, value: Number.isFinite(t) ? t : null };
      }
    }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
