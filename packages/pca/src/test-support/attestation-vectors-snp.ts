// AMD SEV-SNP rows of the attestation-evidence conformance vectors (TEST/TOOLING ONLY).
import { createHash } from 'node:crypto';
import { X509Certificate } from 'node:crypto';
import { AMD_ARK_SPKI_SHA384, pemToDer } from '../attest-amd-snp';
import { parseSevSnpReport, toHex } from '../hardware-sevsnp';
import { b64, type JsonObject, type WireBinding } from './attestation-wire';
import { Collector, SYN_BINDING, append, badBindings, bindingBytes, cut, flip, fxBytes, fxText, hexOf, relays, setByte, textBytes } from './attestation-vectors-common';
import { AMD_OID, FORGE_CHIP, FORGE_NA, FORGE_NB, amdVcekExtensions, type VcekSpl } from './forge-amd';
import { bitString, boolean, cat, ctx, derTime, dn, ecdsaSign, ext, extension, forgeKey, integer, nul, octets, oid, pemOf, seq, tlv, fill, type ForgeKey } from './forge-x509';
import { forgeRsaKey, rsaSignPss } from './forge-rsa';
import { serializeSevSnpReport, type SevSnpReportFields } from './sevsnp-report';

// ───────────────────────────────────────────────────────────── deterministic AMD-format chain (RSA-2048 RSASSA-PSS ARK/ASK, P-384 VCEK)
const sha384Alg = (): Uint8Array => seq(oid('2.16.840.1.101.3.4.2.2'), nul());
const pssAlgId = (trailer: boolean): Uint8Array =>
  seq(oid('1.2.840.113549.1.1.10'), seq(ctx(0, sha384Alg()), ctx(1, seq(oid('1.2.840.113549.1.1.8'), sha384Alg())), ctx(2, integer(48)), ...(trailer ? [ctx(3, integer(1))] : [])));

interface CertSpec {
  subject: string;
  issuer: string;
  spki: Uint8Array;
  signerLabel: string;
  serial: number;
  notBefore: Date;
  notAfter: Date;
  extensions: readonly Uint8Array[];
  trailer: boolean;
  rawExtensionsBlock?: Uint8Array;
}
function buildCert(c: CertSpec): Uint8Array {
  const alg = pssAlgId(c.trailer);
  const block = c.rawExtensionsBlock ?? (c.extensions.length > 0 ? ctx(3, seq(...c.extensions)) : new Uint8Array(0));
  const tbs = seq(ctx(0, integer(2)), integer(c.serial), alg, dn([['CN', c.issuer]]), seq(derTime(c.notBefore), derTime(c.notAfter)), dn([['CN', c.subject]]), c.spki, block);
  const sig = rsaSignPss(forgeRsaKey(c.signerLabel), 'sha384', tbs, 48, `${c.signerLabel}/${c.serial}/${c.subject}`);
  return seq(tbs, alg, bitString(sig));
}

export interface CertKnobs {
  notBefore?: Date;
  notAfter?: Date;
  extensions?: readonly Uint8Array[];
  rawExtensionsBlock?: Uint8Array;
}
export interface AmdChainSpec {
  label?: string;
  family?: string;
  ark?: CertKnobs;
  ask?: CertKnobs;
  vcek?: CertKnobs & { spl?: Partial<VcekSpl> };
  askSignedBy?: string;
  vcekSignedBy?: string;
  askIssuerName?: string;
  arkIssuerName?: string;
  arkSignedBy?: string;
}
export interface AmdChain {
  arkDer: Uint8Array;
  askDer: Uint8Array;
  vcekDer: Uint8Array;
  vcekKey: ForgeKey;
  askArkPem: string;
  arkPin: string;
}
export function amdChain(o: AmdChainSpec = {}): AmdChain {
  const label = o.label ?? 'amd-a';
  const fam = o.family ?? 'Genoa';
  const arkK = forgeRsaKey(`${label}/ark`);
  const askK = forgeRsaKey(`${label}/ask`);
  const vcekKey = forgeKey(`${label}/vcek`, 'P-384');
  const spl: VcekSpl = { chip: FORGE_CHIP, bl: 7, tee: 0, snp: 3, ucode: 0, ...o.vcek?.spl };
  const arkDer = buildCert({
    subject: `ARK-${fam}`, issuer: o.arkIssuerName ?? `ARK-${fam}`, spki: arkK.spkiPss, signerLabel: o.arkSignedBy ? `${o.arkSignedBy}/ark` : `${label}/ark`, serial: 1,
    notBefore: o.ark?.notBefore ?? FORGE_NB, notAfter: o.ark?.notAfter ?? FORGE_NA, extensions: o.ark?.extensions ?? [ext.basicConstraints(true, 2), ext.keyUsage(['keyCertSign', 'cRLSign'])], trailer: true,
    ...(o.ark?.rawExtensionsBlock ? { rawExtensionsBlock: o.ark.rawExtensionsBlock } : {}),
  });
  const askDer = buildCert({
    subject: `SEV-${fam}`, issuer: o.askIssuerName ?? `ARK-${fam}`, spki: askK.spkiPss, signerLabel: o.askSignedBy ? `${o.askSignedBy}/ark` : `${label}/ark`, serial: 2,
    notBefore: o.ask?.notBefore ?? FORGE_NB, notAfter: o.ask?.notAfter ?? FORGE_NA, extensions: o.ask?.extensions ?? [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])], trailer: true,
    ...(o.ask?.rawExtensionsBlock ? { rawExtensionsBlock: o.ask.rawExtensionsBlock } : {}),
  });
  const vcekDer = buildCert({
    subject: 'SEV-VCEK', issuer: `SEV-${fam}`, spki: vcekKey.spki, signerLabel: o.vcekSignedBy ? `${o.vcekSignedBy}/ask` : `${label}/ask`, serial: 3,
    notBefore: o.vcek?.notBefore ?? FORGE_NB, notAfter: o.vcek?.notAfter ?? FORGE_NA, extensions: o.vcek?.extensions ?? amdVcekExtensions(spl), trailer: false,
    ...(o.vcek?.rawExtensionsBlock ? { rawExtensionsBlock: o.vcek.rawExtensionsBlock } : {}),
  });
  return { arkDer, askDer, vcekDer, vcekKey, askArkPem: pemOf(askDer) + pemOf(arkDer), arkPin: createHash('sha384').update(arkK.spkiPss).digest('hex') };
}

// ───────────────────────────────────────────────────────────── report forging
const le72 = (be: Uint8Array): Uint8Array => {
  const o = new Uint8Array(72);
  o.set(Uint8Array.from(be).reverse(), 0);
  return o;
};
export const SNP_TCB = 0x0003_0000_0000_0007n;
export const SNP_MEASUREMENT = new Uint8Array(48).fill(0xab);
export const SNP_HOST_DATA = new Uint8Array(32).map((_, i) => i + 1);
export const SNP_NOW = 1_790_000_000_000;

export interface SnpSynOpts {
  chain?: AmdChainSpec;
  fields?: Partial<SevSnpReportFields>;
  binding?: WireBinding;
  mode?: 'report-data' | 'azure-runtime-data';
  /** Replace the runtime-data JSON text (the report_data hash follows it). */
  runtimeText?: string;
  /** Keep this report_data instead of deriving it. */
  reportData?: Uint8Array;
  /** Sign with the VCEK of another chain label. */
  signerLabel?: string;
}
export interface SnpSyn {
  chain: AmdChain;
  report: Uint8Array;
  runtime?: Uint8Array;
  evidence: JsonObject;
  /** Config common to every row built on this chain: the harness-only ARK pin. */
  pin: string;
}
export function snpSyn(o: SnpSynOpts = {}): SnpSyn {
  const chain = amdChain(o.chain);
  const binding = o.binding ?? SYN_BINDING;
  const mode = o.mode ?? 'report-data';
  let runtime: Uint8Array | undefined;
  let reportData = o.reportData;
  if (mode === 'azure-runtime-data') {
    runtime = textBytes(o.runtimeText ?? JSON.stringify({ 'user-data': hexOf(bindingBytes(binding)), keys: [], 'vm-configuration': { 'console-enabled': false, 'secure-boot': true } }));
    reportData ??= cat(createHash('sha256').update(runtime).digest(), new Uint8Array(32));
  } else reportData ??= bindingBytes(binding);
  const fields: Partial<SevSnpReportFields> = {
    version: 2, guest_svn: 5, policy: 0x30000n, vmpl: 0, signature_algo: 1, current_tcb: SNP_TCB, reported_tcb: SNP_TCB, committed_tcb: SNP_TCB, launch_tcb: SNP_TCB,
    report_data: reportData, measurement: SNP_MEASUREMENT, host_data: SNP_HOST_DATA, chip_id: FORGE_CHIP, ...o.fields,
  };
  const unsigned = serializeSevSnpReport(fields);
  const key = o.signerLabel ? forgeKey(`${o.signerLabel}/vcek`, 'P-384') : chain.vcekKey;
  const sig = ecdsaSign(key, 'sha384', unsigned.subarray(0, 0x2a0)).raw;
  const report = serializeSevSnpReport({ ...fields, signature: { r: le72(sig.subarray(0, 48)), s: le72(sig.subarray(48, 96)) } });
  const evidence: JsonObject = { report: b64(report), vcekDer: b64(chain.vcekDer), askArkPem: chain.askArkPem, ...(runtime ? { runtimeData: b64(runtime) } : {}) };
  return { chain, report, ...(runtime ? { runtime } : {}), evidence, pin: chain.arkPin };
}

export const snpSynConfig = (s: SnpSyn, over: JsonObject = {}, policy: JsonObject = {}, mode: 'report-data' | 'azure-runtime-data' = 'report-data'): JsonObject => ({
  family: 'genoa', binding: mode, policy: { measurements: [hexOf(SNP_MEASUREMENT)], ...policy }, trustAnchorArkSpkiSha384: s.pin, ...over,
});

// ───────────────────────────────────────────────────────────── the rows
const REAL_BINDING: WireBinding = { holderPub: 'pca-realsilicon-azure-tdx-holder', grantRef: 'grant_pca_azure_maa_realsilicon', epoch: 1, nonce: 'srv-nonce-maa-5d3b8e1f9a27c604' };
export const SNP_REAL_NOW = 1791505800000;

export function snpRealBase() {
  const hcl = fxBytes('real-azure-maa', 'sevsnp-hcl-report.bin');
  const report = hcl.slice(32, 32 + 1184);
  const certs = JSON.parse(fxText('real-azure-maa', 'sevsnp-amd-certs.json')) as { vcekCert: string; certificateChain: string };
  const runtime = fxBytes('real-azure-maa', 'sevsnp-runtime-data.json');
  const parsed = parseSevSnpReport(report);
  return { hcl, report, certs, runtime, parsed, vcekDer: pemToDer(certs.vcekCert), meas: toHex(parsed.measurement), binding: REAL_BINDING };
}

export async function buildSnpVectors(c: Collector): Promise<void> {
  const R = snpRealBase();
  const realEv = (over: Partial<{ report: Uint8Array; vcekDer: Uint8Array; askArkPem: string; runtimeData: Uint8Array | null }> = {}): JsonObject => {
    const rt = over.runtimeData === undefined ? R.runtime : over.runtimeData;
    return { report: b64(over.report ?? R.report), vcekDer: b64(over.vcekDer ?? R.vcekDer), askArkPem: over.askArkPem ?? R.certs.certificateChain, ...(rt ? { runtimeData: b64(rt) } : {}) };
  };
  const realCfg = (over: JsonObject = {}, policy: JsonObject = {}): JsonObject => ({ family: 'genoa', binding: 'azure-runtime-data', policy: { measurements: [R.meas], ...policy }, ...over });
  const real = async (id: string, intent: 'accept' | 'reject', description: string, o: { cfg?: JsonObject; policy?: JsonObject; ev?: JsonObject | null; now?: number; binding?: WireBinding; tags?: string[] } = {}) =>
    c.add({ id: `snp-real-${id}`, vendor: 'amd-sev-snp', tags: ['real', 'azure-genoa', ...(o.tags ?? [])], intent, description, config: realCfg(o.cfg, o.policy), now: o.now ?? SNP_REAL_NOW, binding: o.binding ?? R.binding, evidence: o.ev === undefined ? realEv() : o.ev });

  // ── real Azure Genoa evidence ──────────────────────────────────────────────
  await real('positive', 'accept', 'Genuine Azure Genoa report, VCEK and chain, runtime-data binding.');
  const vcek = new X509Certificate(Buffer.from(R.vcekDer));
  const from = vcek.validFromDate.getTime();
  const to = vcek.validToDate.getTime();
  await real('clock-at-vcek-not-before', 'accept', 'Clock exactly at the VCEK notBefore instant is inside the window.', { now: from });
  await real('clock-at-vcek-not-after', 'accept', 'Clock exactly at the VCEK notAfter instant is inside the window.', { now: to });
  await real('clock-before-vcek-not-before', 'reject', 'One millisecond before the VCEK notBefore.', { now: from - 1 });
  await real('clock-after-vcek-not-after', 'reject', 'One millisecond after the VCEK notAfter.', { now: to + 1 });
  await real('clock-skew-widens-not-before', 'accept', 'A 1000 ms skew admits a clock 1000 ms early.', { now: from - 1000, cfg: { clockSkewMs: 1000 } });
  await real('clock-skew-too-small', 'reject', 'A 1000 ms skew does not admit a clock 1001 ms early.', { now: from - 1001, cfg: { clockSkewMs: 1000 } });
  await real('clock-skew-negative', 'reject', 'A negative skew is refused.', { cfg: { clockSkewMs: -1 } });
  await real('far-future-clock', 'reject', 'Clock far beyond every certificate.', { now: 4_102_444_800_000 });
  for (const fam of ['milan', 'turin'] as const) await real(`wrong-family-${fam}`, 'reject', `The Genoa ARK is not the ${fam} root.`, { cfg: { family: fam } });
  await real('binding-report-data-mode', 'reject', 'On Azure report_data is a runtime-data hash, so the direct mode cannot bind.', { cfg: { binding: 'report-data' } });
  for (const [n, b] of relays(R.binding)) await real(`relayed-${n}`, 'reject', `A binding with another ${n} is refused.`, { binding: b });
  for (const [n, b] of badBindings(R.binding)) await real(`bad-binding-${n}`, 'reject', `Binding ${n}: not constructible.`, { binding: b });
  await real('runtime-data-missing', 'reject', 'azure-runtime-data without the JSON bytes.', { ev: realEv({ runtimeData: null }) });
  const rtm = R.runtime;
  await real('runtime-data-tampered-last', 'reject', 'Last-but-two runtime byte flipped: hash no longer matches.', { ev: realEv({ runtimeData: flip(rtm, rtm.length - 3) }) });
  await real('runtime-data-tampered-first', 'reject', 'First runtime byte flipped.', { ev: realEv({ runtimeData: flip(rtm, 0) }) });
  await real('runtime-data-appended', 'reject', 'A trailing newline on the runtime data changes its hash.', { ev: realEv({ runtimeData: append(rtm, 0x0a) }) });
  await real('runtime-data-empty', 'reject', 'Empty runtime data.', { ev: realEv({ runtimeData: new Uint8Array(0) }) });
  // report structure
  await real('report-short-1183', 'reject', 'One byte short of the canonical 1184.', { ev: realEv({ report: cut(R.report, 1183) }) });
  await real('report-short-815', 'reject', 'Shorter than the minimum parse length.', { ev: realEv({ report: cut(R.report, 815) }) });
  await real('report-short-816', 'reject', 'Parses (>= 816) but is not canonical length.', { ev: realEv({ report: cut(R.report, 816) }) });
  await real('report-empty', 'reject', 'Empty report.', { ev: realEv({ report: new Uint8Array(0) }) });
  await real('report-appended-zero', 'reject', 'One appended zero byte: a second encoding of the same signed report.', { ev: realEv({ report: append(R.report, 0) }) });
  await real('report-appended-one', 'reject', 'One appended non-zero byte.', { ev: realEv({ report: append(R.report, 1) }) });
  await real('report-hcl-blob', 'reject', 'The whole 2600-byte HCL blob instead of the extracted report.', { ev: realEv({ report: R.hcl }) });
  await real('report-reserved-r-tail', 'reject', 'Non-zero byte in the reserved tail of the r field (offset 0x2D0).', { ev: realEv({ report: flip(R.report, 0x2a0 + 48) }) });
  await real('report-reserved-r-end', 'reject', 'Non-zero last byte of the r field.', { ev: realEv({ report: flip(R.report, 0x2a0 + 71) }) });
  await real('report-reserved-s-tail', 'reject', 'Non-zero byte in the reserved tail of the s field.', { ev: realEv({ report: flip(R.report, 0x2e8 + 48) }) });
  await real('report-reserved-after-s', 'reject', 'Non-zero byte in the reserved block after s (offset 0x330).', { ev: realEv({ report: flip(R.report, 0x330) }) });
  await real('report-reserved-last', 'reject', 'Non-zero final byte of the report.', { ev: realEv({ report: flip(R.report, 1183) }) });
  for (const [n, at] of [['version', 0], ['guest-svn', 4], ['policy', 8], ['vmpl', 0x30], ['sig-algo', 0x34], ['report-data', 0x50], ['measurement', 0x90 + 4], ['host-data', 0xc0], ['chip-id', 0x1a0], ['reported-tcb', 0x180], ['last-signed', 0x29f]] as const) {
    await real(`flip-signed-${n}`, 'reject', `A bit flipped in the signed region (${n}): the report signature fails.`, { ev: realEv({ report: flip(R.report, at) }) });
  }
  await real('flip-signature-r', 'reject', 'A bit flipped in r.', { ev: realEv({ report: flip(R.report, 0x2a0) }) });
  await real('flip-signature-s', 'reject', 'A bit flipped in s.', { ev: realEv({ report: flip(R.report, 0x2e8 + 10) }) });
  const zeroR = R.report.slice();
  zeroR.fill(0, 0x2a0, 0x2a0 + 48);
  await real('signature-r-zero', 'reject', 'r = 0 is structurally invalid.', { ev: realEv({ report: zeroR }) });
  const bigR = R.report.slice();
  bigR.fill(0xff, 0x2a0, 0x2a0 + 48);
  await real('signature-r-above-order', 'reject', 'r above the curve order.', { ev: realEv({ report: bigR }) });
  const zeroS = R.report.slice();
  zeroS.fill(0, 0x2e8, 0x2e8 + 48);
  await real('signature-s-zero', 'reject', 's = 0.', { ev: realEv({ report: zeroS }) });
  // certificates
  const vc = R.vcekDer;
  for (const [n, at] of [['early', 40], ['middle', Math.floor(vc.length / 2)], ['late', vc.length - 100], ['signature', vc.length - 10], ['last', vc.length - 1]] as const) {
    await real(`vcek-flip-${n}`, 'reject', `A bit flipped in the VCEK (${n}).`, { ev: realEv({ vcekDer: flip(vc, at) }) });
  }
  await real('vcek-trailing-zero', 'reject', 'One zero byte appended after the VCEK certificate.', { ev: realEv({ vcekDer: append(vc, 0) }) });
  await real('vcek-truncated', 'reject', 'VCEK truncated by one byte.', { ev: realEv({ vcekDer: cut(vc, vc.length - 1) }) });
  await real('vcek-empty', 'reject', 'Empty VCEK.', { ev: realEv({ vcekDer: new Uint8Array(0) }) });
  await real('vcek-garbage', 'reject', 'Not a certificate.', { ev: realEv({ vcekDer: textBytes('not a certificate') }) });
  const chainPem = R.certs.certificateChain;
  const pems = chainPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\n?/g)!.map((p) => (p.endsWith('\n') ? p : `${p}\n`));
  await real('chain-empty', 'reject', 'No ASK/ARK bundle.', { ev: realEv({ askArkPem: '' }) });
  await real('chain-ask-only', 'reject', 'Only the ASK.', { ev: realEv({ askArkPem: pems[0]! }) });
  await real('chain-ark-only', 'reject', 'Only the ARK.', { ev: realEv({ askArkPem: pems[1]! }) });
  await real('chain-swapped', 'reject', 'ARK first, ASK second.', { ev: realEv({ askArkPem: pems[1]! + pems[0]! }) });
  await real('chain-three', 'reject', 'ASK, ARK and a duplicate ARK.', { ev: realEv({ askArkPem: pems[0]! + pems[1]! + pems[1]! }) });
  await real('chain-ark-twice', 'reject', 'ARK twice.', { ev: realEv({ askArkPem: pems[1]! + pems[1]! }) });
  await real('chain-ask-twice', 'reject', 'ASK twice.', { ev: realEv({ askArkPem: pems[0]! + pems[0]! }) });
  await real('chain-garbage-pem', 'reject', 'Text that holds no certificate.', { ev: realEv({ askArkPem: 'not pem at all' }) });
  await real('chain-vcek-in-ask-slot', 'reject', 'The VCEK supplied in the ASK position.', { ev: realEv({ askArkPem: pemOf(vc) + pems[1]! }) });
  await real('chain-extra-text-between', 'accept', 'PEM bundles may carry text around the blocks.', { ev: realEv({ askArkPem: `# ASK\n${pems[0]!}\n# ARK\n${pems[1]!}` }) });
  // policy
  const P = R.parsed;
  await real('policy-measurement-other', 'reject', 'Measurement not in the allowlist.', { policy: { measurements: ['00'.repeat(48)] } });
  await real('policy-measurement-uppercase-accepts', 'accept', 'Allowlist entries compare case-insensitively.', { policy: { measurements: [R.meas.toUpperCase()] } });
  await real('policy-measurement-second-entry', 'accept', 'Any entry of the allowlist matches.', { policy: { measurements: ['00'.repeat(48), R.meas] } });
  await real('policy-measurements-empty', 'reject', 'An empty allowlist is refused at construction.', { policy: { measurements: [] } });
  await real('policy-measurements-missing', 'reject', 'A missing allowlist is refused at construction.', { cfg: { policy: {} } });
  await real('policy-missing', 'reject', 'A missing policy is refused at construction.', { cfg: { policy: null as never } });
  await real('config-family-unknown', 'reject', 'Unknown family.', { cfg: { family: 'zen9' } });
  await real('config-family-missing', 'reject', 'Missing family.', { cfg: { family: null as never } });
  await real('config-binding-unknown', 'reject', 'Unknown binding mode.', { cfg: { binding: 'nope' } });
  await real('policy-host-data-other', 'reject', 'HOST_DATA not in the allowlist.', { policy: { hostData: ['ff'.repeat(32)] } });
  await real('policy-host-data-match', 'accept', 'HOST_DATA allowlist containing the report value.', { policy: { hostData: [toHex(P.host_data)] } });
  await real('policy-chip-other', 'reject', 'CHIP_ID not in the allowlist.', { policy: { chipIds: ['00'.repeat(64)] } });
  await real('policy-chip-match', 'accept', 'CHIP_ID allowlist containing the report value.', { policy: { chipIds: [toHex(P.chip_id)] } });
  await real('policy-min-guest-svn-equal', 'accept', 'GUEST_SVN equal to the minimum passes.', { policy: { minGuestSvn: P.guest_svn } });
  await real('policy-min-guest-svn-above', 'reject', 'GUEST_SVN below the minimum.', { policy: { minGuestSvn: P.guest_svn + 1 } });
  await real('policy-min-reported-tcb-equal', 'accept', 'REPORTED_TCB equal to the minimum passes.', { policy: { minReportedTcb: P.reported_tcb.toString() } });
  await real('policy-min-reported-tcb-above', 'reject', 'REPORTED_TCB below the minimum.', { policy: { minReportedTcb: (P.reported_tcb + 1n).toString() } });
  await real('policy-min-committed-tcb-above', 'reject', 'COMMITTED_TCB below the minimum.', { policy: { minCommittedTcb: (P.committed_tcb + 1n).toString() } });
  await real('policy-min-launch-tcb-above', 'reject', 'LAUNCH_TCB below the minimum.', { policy: { minLaunchTcb: (P.launch_tcb + 1n).toString() } });
  await real('policy-vmpl-any', 'accept', "requireVmpl 'any' accepts the report's VMPL.", { policy: { requireVmpl: 'any' } });
  await real('policy-vmpl-mismatch', 'reject', 'A required VMPL that differs from the report.', { policy: { requireVmpl: P.vmpl + 1 } });
  await real('identity-overrides', 'accept', 'identity_overrides replace the measured identity fields.', { cfg: { identity_overrides: { model_id: 'm1', operator: 'acme' } } });

  // ── synthetic chain + signed reports ───────────────────────────────────────
  const syn = async (id: string, intent: 'accept' | 'reject', description: string, s: SnpSyn, o: { cfg?: JsonObject; policy?: JsonObject; now?: number; binding?: WireBinding; ev?: JsonObject | null; mode?: 'report-data' | 'azure-runtime-data'; tags?: string[] } = {}) =>
    c.add({ id: `snp-syn-${id}`, vendor: 'amd-sev-snp', tags: ['synthetic', ...(o.tags ?? [])], intent, description, config: snpSynConfig(s, o.cfg, o.policy, o.mode), now: o.now ?? SNP_NOW, binding: o.binding ?? SYN_BINDING, evidence: o.ev === undefined ? s.evidence : o.ev });
  const base = snpSyn();
  const rt = snpSyn({ mode: 'azure-runtime-data' });
  await syn('positive-report-data', 'accept', 'Forged AMD-format chain, report signed by the VCEK, direct report_data binding.', base);
  await syn('positive-azure-runtime-data', 'accept', 'Same under the azure-runtime-data binding.', rt, { mode: 'azure-runtime-data' });
  await syn('no-pin-override-wrong-root', 'reject', 'Without the harness pin the forged ARK is not the pinned genoa root.', base, { cfg: { trustAnchorArkSpkiSha384: undefined as never } });
  await syn('pin-override-malformed', 'reject', 'A malformed pin matches nothing.', base, { cfg: { trustAnchorArkSpkiSha384: 'zz' } });
  for (const fam of ['milan', 'genoa', 'turin'] as const) await syn(`pin-other-family-${fam}`, 'reject', `The real ${fam} pin does not match the forged ARK.`, base, { cfg: { trustAnchorArkSpkiSha384: AMD_ARK_SPKI_SHA384[fam] } });
  for (const [n, b] of relays(SYN_BINDING)) await syn(`relayed-${n}`, 'reject', `Direct binding: another ${n}.`, base, { binding: b });
  for (const [n, b] of badBindings(SYN_BINDING)) await syn(`bad-binding-${n}`, 'reject', `Direct binding ${n}: not constructible.`, base, { binding: b });
  for (const [n, b] of relays(SYN_BINDING)) await syn(`rt-relayed-${n}`, 'reject', `Runtime-data binding: another ${n}.`, rt, { binding: b, mode: 'azure-runtime-data' });
  await syn('rt-bad-binding-empty-nonce', 'reject', 'Runtime-data binding with an empty nonce.', rt, { binding: { ...SYN_BINDING, nonce: '' }, mode: 'azure-runtime-data' });

  // runtime-data shapes (the report_data hash always follows the text, so only the JSON rule differs)
  const rtText = (text: string) => snpSyn({ mode: 'azure-runtime-data', runtimeText: text });
  const ud = hexOf(bindingBytes(SYN_BINDING));
  for (const [n, text, why] of [
    ['not-json', 'not json', 'runtime data that is not JSON'],
    ['json-array', '[1,2]', 'a JSON array'],
    ['json-string', '"x"', 'a JSON string'],
    ['json-null', 'null', 'JSON null'],
    ['no-user-data', '{"a":1}', 'no user-data member'],
    ['user-data-number', '{"user-data":5}', 'a numeric user-data'],
    ['user-data-short', `{"user-data":"${ud.slice(0, 126)}"}`, 'a user-data of 126 hex characters'],
    ['user-data-long', `{"user-data":"${ud}00"}`, 'a user-data of 130 hex characters'],
    ['user-data-nonhex', `{"user-data":"${'zz'.repeat(64)}"}`, 'a non-hex user-data'],
    ['user-data-other', `{"user-data":"${'00'.repeat(64)}"}`, 'a user-data that is not the binding'],
    ['user-data-uppercase', `{"user-data":"${ud.toUpperCase()}"}`, 'the binding in uppercase hex (hex compare is case-insensitive in the decoder)'],
  ] as const) {
    const s = rtText(text);
    await syn(`rt-${n}`, n === 'user-data-uppercase' ? 'accept' : 'reject', `Runtime data with ${why}.`, s, { mode: 'azure-runtime-data' });
  }
  const bad32 = snpSyn({ mode: 'azure-runtime-data', reportData: cat(createHash('sha256').update(rt.runtime!).digest(), new Uint8Array(31), Uint8Array.of(1)) });
  await syn('rt-report-data-upper-half-nonzero', 'reject', 'report_data[32:64] is not zero.', bad32, { mode: 'azure-runtime-data' });
  await syn('rt-report-data-hash-mismatch', 'reject', 'report_data[0:32] is not sha256(runtime data).', snpSyn({ mode: 'azure-runtime-data', reportData: new Uint8Array(64).fill(7) }), { mode: 'azure-runtime-data' });
  await syn('rt-missing-runtime-data', 'reject', 'azure-runtime-data mode without runtime bytes.', rt, { mode: 'azure-runtime-data', ev: { ...rt.evidence, runtimeData: undefined as never } });

  // report structure on a validly signed report
  const ev = (s: SnpSyn, report: Uint8Array): JsonObject => ({ ...s.evidence, report: b64(report) });
  await syn('report-appended-zero', 'reject', 'Appended zero byte on a validly signed report.', base, { ev: ev(base, append(base.report, 0)) });
  await syn('report-appended-one', 'reject', 'Appended non-zero byte.', base, { ev: ev(base, append(base.report, 1)) });
  await syn('report-short-1183', 'reject', 'One byte short.', base, { ev: ev(base, cut(base.report, 1183)) });
  await syn('report-short-815', 'reject', 'Below the minimum parse length.', base, { ev: ev(base, cut(base.report, 815)) });
  await syn('report-long-2048', 'reject', 'Padded to 2048 bytes.', base, { ev: ev(base, cat(base.report, new Uint8Array(864))) });
  for (const [n, at] of [['r-tail-first', 0x2a0 + 48], ['r-tail-last', 0x2a0 + 71], ['s-tail-first', 0x2e8 + 48], ['s-tail-last', 0x2e8 + 71], ['after-s-first', 0x2e8 + 72], ['after-s-mid', 0x400], ['last', 1183]] as const) {
    await syn(`report-reserved-${n}`, 'reject', `Non-zero reserved signature-block byte (${n}); the signature itself still verifies.`, base, { ev: ev(base, setByte(base.report, at, 0x5a)) });
  }
  await syn('report-signature-r-zero', 'reject', 'r = 0.', base, { ev: ev(base, (() => { const r = base.report.slice(); r.fill(0, 0x2a0, 0x2a0 + 48); return r; })()) });
  await syn('report-signature-from-other-vcek', 'reject', 'Signed by another VCEK key.', snpSyn({ signerLabel: 'amd-b' }));
  await syn('report-flip-signed-byte', 'reject', 'One flipped bit in the signed region.', base, { ev: ev(base, flip(base.report, 0x90)) });

  // policy gates on validly signed reports
  const f = (fields: Partial<SevSnpReportFields>, chain?: AmdChainSpec) => snpSyn({ fields, ...(chain ? { chain } : {}) });
  await syn('sig-algo-2', 'reject', 'SIGNATURE_ALGO is not ECDSA-P384.', f({ signature_algo: 2 }));
  await syn('sig-algo-2-allowed', 'accept', 'requireEcdsaP384 false waives the algorithm check.', f({ signature_algo: 2 }), { policy: { requireEcdsaP384: false } });
  await syn('debug-bit', 'reject', 'Guest policy has the DEBUG bit.', f({ policy: 0x30000n | (1n << 19n) }));
  await syn('debug-bit-allowed', 'accept', 'allowDebug accepts the DEBUG bit.', f({ policy: 0x30000n | (1n << 19n) }), { policy: { allowDebug: true } });
  await syn('debug-bit-allow-false', 'reject', 'allowDebug false keeps refusing.', f({ policy: 0x30000n | (1n << 19n) }), { policy: { allowDebug: false } });
  await syn('vmpl-1-default', 'reject', 'VMPL 1 against the default requirement of 0.', f({ vmpl: 1 }));
  await syn('vmpl-1-required', 'accept', 'requireVmpl 1 accepts VMPL 1.', f({ vmpl: 1 }), { policy: { requireVmpl: 1 } });
  await syn('vmpl-3-any', 'accept', "requireVmpl 'any' accepts VMPL 3.", f({ vmpl: 3 }), { policy: { requireVmpl: 'any' } });
  await syn('guest-svn-below', 'reject', 'GUEST_SVN 5 below a minimum of 6.', base, { policy: { minGuestSvn: 6 } });
  await syn('guest-svn-equal', 'accept', 'GUEST_SVN 5 meets a minimum of 5.', base, { policy: { minGuestSvn: 5 } });
  await syn('reported-tcb-below', 'reject', 'REPORTED_TCB below the minimum.', base, { policy: { minReportedTcb: (SNP_TCB + 1n).toString() } });
  await syn('reported-tcb-equal', 'accept', 'REPORTED_TCB equal to the minimum.', base, { policy: { minReportedTcb: SNP_TCB.toString() } });
  await syn('reported-tcb-above-2e53', 'reject', 'A TCB floor above 2^53 is compared as a whole u64.', base, { policy: { minReportedTcb: '18446744073709551615' } });
  await syn('committed-tcb-below', 'reject', 'COMMITTED_TCB below the minimum.', base, { policy: { minCommittedTcb: (SNP_TCB + 1n).toString() } });
  await syn('launch-tcb-below', 'reject', 'LAUNCH_TCB below the minimum.', base, { policy: { minLaunchTcb: (SNP_TCB + 1n).toString() } });
  await syn('launch-tcb-equal', 'accept', 'LAUNCH_TCB equal to the minimum.', base, { policy: { minLaunchTcb: SNP_TCB.toString() } });
  await syn('measurement-not-allowed', 'reject', 'Launch measurement not allowlisted.', base, { policy: { measurements: ['cd'.repeat(48)] } });
  await syn('host-data-mismatch', 'reject', 'HOST_DATA not allowlisted.', base, { policy: { hostData: ['00'.repeat(32)] } });
  await syn('host-data-match', 'accept', 'HOST_DATA allowlisted.', base, { policy: { hostData: [hexOf(SNP_HOST_DATA)] } });
  await syn('chip-id-mismatch', 'reject', 'CHIP_ID not allowlisted.', base, { policy: { chipIds: ['00'.repeat(64)] } });
  await syn('chip-id-match', 'accept', 'CHIP_ID allowlisted.', base, { policy: { chipIds: [hexOf(FORGE_CHIP)] } });
  await syn('identity-default', 'accept', 'Default measured identity: measurement and chip id, nothing else.', base);
  await syn('identity-overrides', 'accept', 'identity_overrides merge over the measured identity.', base, { cfg: { identity_overrides: { model_id: 'model-x', operator: 'op-y', weights_digest: 'wd', weights_measured: true } } });
  await syn('policy-empty-measurements', 'reject', 'Empty measurement allowlist refused at construction.', base, { policy: { measurements: [] } });

  // chain-level
  const withChain = (spec: AmdChainSpec) => snpSyn({ chain: spec });
  const SPL: VcekSpl = { chip: FORGE_CHIP, bl: 7, tee: 0, snp: 3, ucode: 0 };
  const goodExts = amdVcekExtensions(SPL);
  const bad = extension('1.2.3.4.5', true, octets(Uint8Array.of(1)));
  const chainRows: Array<[string, string, AmdChainSpec]> = [
    ['ask-not-ca', 'ASK BasicConstraints CA:FALSE', { ask: { extensions: [ext.basicConstraints(false), ext.keyUsage(['keyCertSign'])] } }],
    ['ask-no-basic-constraints', 'ASK without BasicConstraints', { ask: { extensions: [ext.keyUsage(['keyCertSign'])] } }],
    ['ask-key-usage-no-cert-sign', 'ASK keyUsage lacks keyCertSign', { ask: { extensions: [ext.basicConstraints(true, 0), ext.keyUsage(['digitalSignature'])] } }],
    ['ark-not-ca', 'ARK CA:FALSE', { ark: { extensions: [ext.basicConstraints(false), ext.keyUsage(['keyCertSign'])] } }],
    ['ark-path-len-0', 'ARK pathLenConstraint 0 cannot admit the ASK', { ark: { extensions: [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])] } }],
    ['vcek-ca-true', 'VCEK asserting CA:TRUE', { vcek: { extensions: [ext.basicConstraints(true), ...goodExts] } }],
    ['ask-basic-constraints-noncritical', 'ASK BasicConstraints not critical', { ask: { extensions: [extension('2.5.29.19', false, seq(boolean(true), integer(0))), ext.keyUsage(['keyCertSign'])] } }],
    ['vcek-unrecognised-critical', 'VCEK unknown critical extension', { vcek: { extensions: [bad, ...goodExts] } }],
    ['ask-unrecognised-critical', 'ASK unknown critical extension', { ask: { extensions: [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign']), bad] } }],
    ['ark-unrecognised-critical', 'ARK unknown critical extension', { ark: { extensions: [ext.basicConstraints(true, 2), ext.keyUsage(['keyCertSign', 'cRLSign']), bad] } }],
    ['ask-key-usage-unused-bits-8', 'ASK keyUsage BIT STRING with 8 unused bits', { ask: { extensions: [ext.basicConstraints(true, 0), extension('2.5.29.15', true, bitString(Uint8Array.of(0x04), 8))] } }],
    ['ask-basic-constraints-nonminimal-length', 'ASK BasicConstraints value with a non-minimal DER length', { ask: { extensions: [extension('2.5.29.19', true, Uint8Array.of(0x30, 0x81, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00)), ext.keyUsage(['keyCertSign'])] } }],
    ['ask-duplicate-basic-constraints', 'ASK with two BasicConstraints', { ask: { extensions: [ext.basicConstraints(true, 0), ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])] } }],
    ['vcek-duplicate-hwid', 'VCEK with a second hwID extension', { vcek: { extensions: [...goodExts, extension(AMD_OID.hwid, false, new Uint8Array(64).fill(1))] } }],
    ['vcek-duplicate-spl', 'VCEK with a second SNP SPL extension', { vcek: { extensions: [...goodExts, extension(AMD_OID.snp, false, integer(3))] } }],
    ['vcek-hwid-63', 'hwID of 63 bytes', { vcek: { extensions: [...goodExts.slice(0, 4), extension(AMD_OID.hwid, false, new Uint8Array(63))] } }],
    ['vcek-hwid-65', 'hwID of 65 bytes', { vcek: { extensions: [...goodExts.slice(0, 4), extension(AMD_OID.hwid, false, new Uint8Array(65))] } }],
    ['vcek-hwid-wrapped-66', 'hwID wrapped in an inner OCTET STRING', { vcek: { extensions: [...goodExts.slice(0, 4), extension(AMD_OID.hwid, false, cat(Uint8Array.of(0x04, 0x40), FORGE_CHIP))] } }],
    ['vcek-hwid-critical', 'critical hwID', { vcek: { extensions: [...goodExts.slice(0, 4), extension(AMD_OID.hwid, true, FORGE_CHIP)] } }],
    ['vcek-hwid-other-chip', 'hwID differs from the report chip id', { vcek: { extensions: [...goodExts.slice(0, 4), extension(AMD_OID.hwid, false, new Uint8Array(64).fill(1))] } }],
    ['vcek-spl-bl-critical', 'critical bootloader SPL', { vcek: { extensions: [extension(AMD_OID.bl, true, integer(7)), ...goodExts.slice(1)] } }],
    ['vcek-spl-bl-mismatch', 'bootloader SPL differs from reported_tcb', { vcek: { spl: { bl: 2 } } }],
    ['vcek-spl-tee-mismatch', 'TEE SPL differs from reported_tcb', { vcek: { spl: { tee: 1 } } }],
    ['vcek-spl-snp-mismatch', 'SNP SPL differs from reported_tcb', { vcek: { spl: { snp: 4 } } }],
    ['vcek-spl-ucode-mismatch', 'microcode SPL differs from reported_tcb', { vcek: { spl: { ucode: 9 } } }],
    ['vcek-no-extensions', 'VCEK without any extension block', { vcek: { extensions: [] } }],
    ['vcek-empty-extensions-block', 'VCEK with an empty Extensions SEQUENCE', { vcek: { rawExtensionsBlock: ctx(3, seq()) } }],
    ['vcek-noncanonical-critical-flag', 'extension critical flag encoded as 0x01', { vcek: { extensions: [seq(oid('1.2.3'), tlv(0x01, Uint8Array.of(0x01)), octets(Uint8Array.of(1))), ...goodExts] } }],
    ['vcek-extension-trailing-bytes', 'an Extension with a second OCTET STRING', { vcek: { extensions: [seq(oid('1.2.3'), octets(Uint8Array.of(1)), octets(Uint8Array.of(2))), ...goodExts] } }],
    ['vcek-extensions-block-twice', 'two [3] extension blocks', { vcek: { rawExtensionsBlock: cat(ctx(3, seq(...goodExts)), ctx(3, seq(...goodExts))) } }],
    ['ask-issuer-name-mismatch', 'ASK issuer name is not the ARK subject', { askIssuerName: 'Someone Else' }],
    ['ark-issuer-name-mismatch', 'ARK not self-named', { arkIssuerName: 'Someone Else' }],
    ['ark-bad-self-signature', 'ARK signed by another key', { arkSignedBy: 'amd-b' }],
    ['ask-signed-by-foreign-ark', 'ASK not issued by the ARK', { askSignedBy: 'amd-b' }],
    ['vcek-signed-by-foreign-ask', 'VCEK not issued by the ASK', { vcekSignedBy: 'amd-b' }],
  ];
  for (const [n, why, spec] of chainRows) await syn(`chain-${n}`, 'reject', `Chain defect: ${why}.`, withChain(spec), { tags: ['strictness'] });
  // validity windows
  for (const [who, name] of [['vcek', 'VCEK'], ['ask', 'ASK'], ['ark', 'ARK']] as const) {
    await syn(`validity-${who}-not-yet`, 'reject', `${name} not yet valid.`, withChain({ [who]: { notBefore: new Date(SNP_NOW + 86_400_000), notAfter: FORGE_NA } }));
    await syn(`validity-${who}-expired`, 'reject', `${name} expired.`, withChain({ [who]: { notBefore: FORGE_NB, notAfter: new Date(SNP_NOW - 86_400_000) } }));
  }
  const edge = (nb: number, na: number) => withChain({ vcek: { notBefore: new Date(nb), notAfter: new Date(na) } });
  await syn('validity-vcek-at-not-before', 'accept', 'Clock exactly at the VCEK notBefore.', edge(SNP_NOW, SNP_NOW + 1e6));
  await syn('validity-vcek-1s-before-not-before', 'reject', 'Clock one second before the VCEK notBefore.', edge(SNP_NOW + 1000, SNP_NOW + 1e6));
  await syn('validity-vcek-at-not-after', 'accept', 'Clock exactly at the VCEK notAfter.', edge(SNP_NOW - 1e6, SNP_NOW));
  await syn('validity-vcek-1s-after-not-after', 'reject', 'Clock one second after the VCEK notAfter.', edge(SNP_NOW - 1e6, SNP_NOW - 1000));
  await syn('validity-skew-admits-early-vcek', 'accept', 'A 1000 ms skew admits a VCEK that starts one second ahead.', edge(SNP_NOW + 1000, SNP_NOW + 1e6), { cfg: { clockSkewMs: 1000 } });
  await syn('validity-skew-too-small', 'reject', 'A 999 ms skew does not.', edge(SNP_NOW + 1000, SNP_NOW + 1e6), { cfg: { clockSkewMs: 999 } });
  // order / count / encoding of the bundle and VCEK
  const ch = base.chain;
  const evb = (over: Partial<{ vcekDer: Uint8Array; askArkPem: string }>): JsonObject => ({ ...base.evidence, ...(over.vcekDer ? { vcekDer: b64(over.vcekDer) } : {}), ...(over.askArkPem !== undefined ? { askArkPem: over.askArkPem } : {}) });
  await syn('bundle-swapped', 'reject', '[ARK, ASK] order.', base, { ev: evb({ askArkPem: pemOf(ch.arkDer) + pemOf(ch.askDer) }) });
  await syn('bundle-ark-twice', 'reject', '[ARK, ARK].', base, { ev: evb({ askArkPem: pemOf(ch.arkDer) + pemOf(ch.arkDer) }) });
  await syn('bundle-ask-only', 'reject', 'One certificate.', base, { ev: evb({ askArkPem: pemOf(ch.askDer) }) });
  await syn('bundle-three', 'reject', 'Three certificates.', base, { ev: evb({ askArkPem: pemOf(ch.askDer) + pemOf(ch.arkDer) + pemOf(ch.arkDer) }) });
  await syn('bundle-vcek-in-ask-slot', 'reject', 'ASK supplied as the VCEK.', base, { ev: evb({ vcekDer: ch.askDer }) });
  await syn('vcek-trailing-zero', 'reject', 'A zero byte after the VCEK certificate.', base, { ev: evb({ vcekDer: append(ch.vcekDer, 0) }), tags: ['strictness'] });
  await syn('vcek-trailing-ff', 'reject', 'A 0xFF byte after the VCEK certificate.', base, { ev: evb({ vcekDer: append(ch.vcekDer, 0xff) }), tags: ['strictness'] });
  await syn('vcek-truncated', 'reject', 'VCEK truncated.', base, { ev: evb({ vcekDer: cut(ch.vcekDer, ch.vcekDer.length - 3) }) });
  await syn('evidence-missing-vcek', 'reject', 'No VCEK in the evidence.', base, { ev: { report: base.evidence['report']!, askArkPem: base.evidence['askArkPem']! } });
  await syn('evidence-missing-report', 'reject', 'No report in the evidence.', base, { ev: { vcekDer: base.evidence['vcekDer']!, askArkPem: base.evidence['askArkPem']! } });
  await syn('evidence-null', 'reject', 'The resolver has no evidence.', base, { ev: null });
  // pass-through of the DER-strict rules by the AMD verifier (non-minimal length / long-form below 128 inside the VCEK)
  const vcekBytes = ch.vcekDer;
  // re-encode the outer SEQUENCE length of the VCEK in a non-minimal long form (0x82 0x00 NN instead of the short/minimal form): the signature is untouched
  const outerHdr = vcekBytes[1]! & 0x80 ? 2 + (vcekBytes[1]! & 0x7f) : 2;
  const outerLen = vcekBytes.length - outerHdr;
  const nonMinimal = cat(Uint8Array.of(0x30, 0x83, 0x00, (outerLen >> 8) & 0xff, outerLen & 0xff), vcekBytes.subarray(outerHdr));
  await syn('vcek-outer-length-nonminimal', 'reject', 'VCEK whose outer SEQUENCE length has a leading zero length byte.', base, { ev: evb({ vcekDer: nonMinimal }), tags: ['strictness'] });
}
