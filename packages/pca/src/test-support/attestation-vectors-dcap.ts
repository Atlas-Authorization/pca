// Intel TDX / DCAP rows of the attestation-evidence conformance vectors (TEST/TOOLING ONLY).
import { createHash } from 'node:crypto';
import { parseDcapQuote, parseDcapTdReport, toHex } from '../attest-intel-tdx';
import type { IntelTdxCollateral } from '../attest-intel-collateral';
import { b64, type JsonObject, type WireBinding } from './attestation-wire';
import { Collector, SYN_BINDING, append, badBindings, bindingBytes, cut, flip, fxBytes, fxText, hexOf, relays, setByte, textBytes } from './attestation-vectors-common';
import {
  DCAP_OFFSETS, TD10_FIELDS, forgeIntelPki, forgeTdxCollateral, forgeTdxQuote, defaultTcbInfoSpec,
  type ForgeCollateralOptions, type ForgeTdxOptions, type ForgedTdxQuote, type TdxTcbInfoSpec,
} from './forge-dcap';
import { cat, ext, extension, forgeCert, forgeKey, oid, octets, pemOf, seq, tlv, u16, u32, bytesToHex } from './forge-x509';
import { forgeRsaKey } from './forge-rsa';

export const DCAP_NOW = Date.parse('2026-10-20T00:00:00Z');

const colWire = (c: IntelTdxCollateral): JsonObject => ({
  tcbInfoJson: String(c.tcbInfoJson),
  tcbInfoIssuerChainPem: c.tcbInfoIssuerChainPem,
  qeIdentityJson: String(c.qeIdentityJson),
  qeIdentityIssuerChainPem: c.qeIdentityIssuerChainPem,
  pckCrlDer: b64(c.pckCrlDer),
  rootCrlDer: b64(c.rootCrlDer),
});

export interface DcapSynOpts {
  quote?: ForgeTdxOptions;
  col?: ForgeCollateralOptions;
  binding?: WireBinding;
  mode?: 'report-data' | 'azure-runtime-data';
  runtimeText?: string;
  reportData?: Uint8Array;
  /** Skip the collateral entirely. */
  noCollateral?: boolean;
}
export interface DcapSyn {
  f: ForgedTdxQuote;
  col: IntelTdxCollateral;
  runtime?: Uint8Array;
  evidence: JsonObject;
  pin: string;
  mrtd: string;
}
/** The collateral windows are anchored on `now` so a forged bundle is fresh at any verifier clock. */
export const windows = (now: number): ForgeCollateralOptions => {
  const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
  return {
    tcbInfo: { issueDate: iso(now - 86_400_000), nextUpdate: iso(now + 30 * 86_400_000) },
    qeIdentity: { issueDate: iso(now - 86_400_000), nextUpdate: iso(now + 30 * 86_400_000) },
    crlThisUpdate: new Date(now - 86_400_000),
    crlNextUpdate: new Date(now + 30 * 86_400_000),
  };
};
export function dcapSyn(o: DcapSynOpts = {}, now = DCAP_NOW): DcapSyn {
  const binding = o.binding ?? SYN_BINDING;
  const mode = o.mode ?? 'report-data';
  let runtime: Uint8Array | undefined;
  let reportData = o.reportData;
  if (mode === 'azure-runtime-data') {
    runtime = textBytes(o.runtimeText ?? JSON.stringify({ 'user-data': hexOf(bindingBytes(binding)), keys: [], 'vm-configuration': { 'console-enabled': false } }));
    reportData ??= cat(createHash('sha256').update(runtime).digest(), new Uint8Array(32));
  } else reportData ??= bindingBytes(binding);
  const qo: ForgeTdxOptions = { ...(o.quote ?? {}), td: { reportData, ...(o.quote?.td ?? {}) } };
  const f = forgeTdxQuote(qo);
  const w = windows(now);
  const col = forgeTdxCollateral(f, { ...w, ...(o.col ?? {}), tcbInfo: { ...w.tcbInfo, ...(o.col?.tcbInfo ?? {}) }, qeIdentity: { ...w.qeIdentity, ...(o.col?.qeIdentity ?? {}) } });
  const evidence: JsonObject = { quote: b64(f.quote), ...(runtime ? { runtimeData: b64(runtime) } : {}), ...(o.noCollateral ? {} : { collateral: colWire(col) }) };
  const mrtd = hexOf(f.tdBody.subarray(TD10_FIELDS.MRTD, TD10_FIELDS.MRTD + 48));
  return { f, col, ...(runtime ? { runtime } : {}), evidence, pin: f.rootSpkiSha256, mrtd };
}
export const dcapSynConfig = (s: DcapSyn, mode: 'report-data' | 'azure-runtime-data' = 'report-data', policy: JsonObject = {}, over: JsonObject = {}): JsonObject => ({
  binding: mode, policy: { mrtds: [s.mrtd], ...policy }, trustAnchorRootCaSpkiSha256: s.pin, ...over,
});

const REAL_BINDING: WireBinding = { holderPub: 'pca-realsilicon-azure-tdx-holder', grantRef: 'grant_pca_azure_maa_realsilicon', epoch: 1, nonce: 'srv-nonce-maa-5d3b8e1f9a27c604' };
export const DCAP_REAL_NOW = 1791506476000;

export function dcapRealBase() {
  const quote = fxBytes('real-azure-maa', 'pcabound-tdx-dcap-quote.bin');
  const runtime = fxBytes('real-azure-maa', 'pcabound-runtime-data.json');
  const col = (f: string) => fxText('real-tdx-collateral', f);
  const colBytes = (f: string) => fxBytes('real-tdx-collateral', f);
  const collateral: IntelTdxCollateral = {
    tcbInfoJson: col('tdx-tcbinfo.json'), tcbInfoIssuerChainPem: col('tdx-tcbinfo-issuer-chain.pem'), qeIdentityJson: col('tdx-qeidentity.json'), qeIdentityIssuerChainPem: col('tdx-qeidentity-issuer-chain.pem'),
    pckCrlDer: colBytes('pckcrl-platform.der'), rootCrlDer: colBytes('IntelSGXRootCA.crl.der'),
  };
  const parsed = parseDcapQuote(quote);
  const td = parseDcapTdReport(parsed.tdReportBody);
  return { quote, runtime, collateral, parsed, td, mrtd: toHex(td.mrTd), binding: REAL_BINDING, otherQuote: fxBytes('real-tdx', 'azure-intel-tdx-dcap-quote.bin') };
}

export async function buildDcapVectors(c: Collector): Promise<void> {
  const R = dcapRealBase();
  const realEv = (o: { quote?: Uint8Array; runtime?: Uint8Array | null; col?: Partial<IntelTdxCollateral> | null } = {}): JsonObject => ({
    quote: b64(o.quote ?? R.quote),
    ...(o.runtime === null ? {} : { runtimeData: b64(o.runtime ?? R.runtime) }),
    ...(o.col === null ? {} : { collateral: colWire({ ...R.collateral, ...(o.col ?? {}) } as IntelTdxCollateral) }),
  });
  const rcfg = (over: JsonObject = {}, policy: JsonObject = {}): JsonObject => ({ binding: 'azure-runtime-data', policy: { mrtds: [R.mrtd], ...policy }, ...over });
  const real = (id: string, intent: 'accept' | 'reject', description: string, o: { cfg?: JsonObject; policy?: JsonObject; ev?: JsonObject | null; now?: number; binding?: WireBinding; tags?: string[] } = {}) =>
    c.add({ id: `tdx-real-${id}`, vendor: 'intel-tdx-dcap', tags: ['real', 'azure-tdx', ...(o.tags ?? [])], intent, description, config: rcfg(o.cfg, o.policy), now: o.now ?? DCAP_REAL_NOW, binding: o.binding ?? R.binding, evidence: o.ev === undefined ? realEv() : o.ev });

  const q = R.quote;
  await real('positive', 'accept', 'Genuine Azure TDX quote with real Intel PCS collateral, runtime-data binding.');
  await real('positive-uppercase-pin', 'accept', 'The explicit default pin in upper case.', { cfg: { trustAnchorRootCaSpkiSha256: 'A0AF031289F5D5D4132F9186068A7FC13628633BA235777472E29B6B6C67A49E' } });
  await real('wrong-root-pin', 'reject', 'A different Intel root pin.', { cfg: { trustAnchorRootCaSpkiSha256: '00'.repeat(32) } });
  await real('collateral-missing', 'reject', 'Collateral is required by default.', { ev: realEv({ col: null }) });
  await real('collateral-missing-allowed', 'accept', 'allowMissingCollateral labels the status unevaluated.', { ev: realEv({ col: null }), cfg: { allowMissingCollateral: true } });
  await real('report-data-mode', 'reject', 'On Azure report_data is a runtime-data hash.', { cfg: { binding: 'report-data' } });
  for (const [n, b] of relays(R.binding)) await real(`relayed-${n}`, 'reject', `Another ${n} in the binding.`, { binding: b });
  for (const [n, b] of badBindings(R.binding)) await real(`bad-binding-${n}`, 'reject', `Binding ${n}: not constructible.`, { binding: b });
  await real('runtime-data-missing', 'reject', 'No runtime-data bytes.', { ev: realEv({ runtime: null }) });
  await real('runtime-data-tampered', 'reject', 'Runtime data edited.', { ev: realEv({ runtime: flip(R.runtime, R.runtime.length - 3) }) });
  await real('runtime-data-empty', 'reject', 'Empty runtime data.', { ev: realEv({ runtime: new Uint8Array(0) }) });
  // policy
  await real('mrtd-other', 'reject', 'MRTD not allowlisted.', { policy: { mrtds: ['00'.repeat(48)] } });
  await real('mrtd-uppercase', 'accept', 'MRTD allowlist compares case-insensitively.', { policy: { mrtds: [R.mrtd.toUpperCase()] } });
  await real('mrtd-second-entry', 'accept', 'Any entry matches.', { policy: { mrtds: ['00'.repeat(48), R.mrtd] } });
  await real('mrtds-empty', 'reject', 'Empty MRTD list refused at construction.', { policy: { mrtds: [] } });
  await real('mrtds-short-entry', 'reject', 'An MRTD that is not 96 hex characters.', { policy: { mrtds: ['abc'] } });
  await real('mrtds-nonhex-entry', 'reject', 'An MRTD with non-hex characters.', { policy: { mrtds: ['zz'.repeat(48)] } });
  await real('config-binding-unknown', 'reject', 'Unknown binding mode.', { cfg: { binding: 'nope' } });
  await real('fmspc-match', 'accept', 'FMSPC allowlist with the quote platform.', { policy: { fmspcs: ['90c06f000000'] } });
  await real('fmspc-other', 'reject', 'FMSPC not allowlisted.', { policy: { fmspcs: ['ffffffffffff'] } });
  await real('rtmr0-match', 'accept', 'RTMR0 allowlist with the quote value.', { policy: { rtmrs: [toHex(R.td.rtmr0)] } });
  await real('rtmr0-other', 'reject', 'RTMR0 not allowlisted.', { policy: { rtmrs: ['ee'.repeat(48)] } });
  await real('mr-seam-match', 'accept', 'MRSEAM allowlist with the quote value.', { policy: { mrSeams: [toHex(R.td.mrSeam)] } });
  await real('mr-seam-other', 'reject', 'MRSEAM not allowlisted.', { policy: { mrSeams: ['11'.repeat(48)] } });
  await real('mr-signer-seam-match', 'accept', 'MRSIGNERSEAM allowlist with the quote value.', { policy: { mrSignerSeams: [toHex(R.td.mrSignerSeam)] } });
  await real('mr-signer-seam-other', 'reject', 'MRSIGNERSEAM not allowlisted.', { policy: { mrSignerSeams: ['22'.repeat(48)] } });
  await real('mr-seams-empty-list', 'reject', 'An empty mrSeams list is refused at construction.', { policy: { mrSeams: [] } });
  await real('mr-signer-seams-bad-entry', 'reject', 'A malformed mrSignerSeams entry.', { policy: { mrSignerSeams: ['zz'] } });
  await real('allow-debug-true', 'accept', 'allowDebug true on a non-debug TD changes nothing.', { policy: { allowDebug: true } });
  await real('identity-overrides', 'accept', 'identity_overrides replace the measured identity fields.', { cfg: { identity_overrides: { model_id: 'm1', operator: 'acme' } } });
  // collateral policy
  await real('collateral-accept-status-sw-only', 'reject', 'Only SWHardeningNeeded accepted: the real UpToDate platform is refused.', { policy: { collateral: { acceptStatuses: ['SWHardeningNeeded'] } } });
  await real('collateral-accept-status-uptodate', 'accept', 'Only UpToDate accepted.', { policy: { collateral: { acceptStatuses: ['UpToDate'] } } });
  await real('collateral-accept-status-empty', 'reject', 'An empty acceptStatuses list accepts nothing.', { policy: { collateral: { acceptStatuses: [] } } });
  await real('collateral-min-eval-number-equal', 'accept', 'tcbEvaluationDataNumber 20 meets a floor of 20.', { policy: { collateral: { minTcbEvaluationDataNumber: 20 } } });
  await real('collateral-min-eval-number-above', 'reject', 'Floor of 21 refuses collateral 20.', { policy: { collateral: { minTcbEvaluationDataNumber: 21 } } });
  // collateral tampering
  const info = String(R.collateral.tcbInfoJson);
  await real('collateral-tcbinfo-number-edited', 'reject', 'tcbEvaluationDataNumber edited after signing.', { ev: realEv({ col: { tcbInfoJson: info.replace('"tcbEvaluationDataNumber":20', '"tcbEvaluationDataNumber":21') } }) });
  await real('collateral-tcbinfo-signature-flipped', 'reject', 'One signature nibble of the TCB info changed.', { ev: realEv({ col: { tcbInfoJson: info.replace(/"signature":"([0-9a-f])/, (_m, d: string) => `"signature":"${d === '0' ? '1' : '0'}`) } }) });
  await real('collateral-tcbinfo-signature-removed', 'reject', 'TCB info without a signature member.', { ev: realEv({ col: { tcbInfoJson: info.replace(/,"signature":"[0-9a-f]+"/, '') } }) });
  await real('collateral-tcbinfo-not-json', 'reject', 'TCB info that is not JSON.', { ev: realEv({ col: { tcbInfoJson: 'not json' } }) });
  await real('collateral-tcbinfo-empty', 'reject', 'Empty TCB info is incomplete collateral.', { ev: realEv({ col: { tcbInfoJson: '' } }) });
  await real('collateral-qe-identity-as-tcbinfo', 'reject', 'The QE identity document in the TCB info slot.', { ev: realEv({ col: { tcbInfoJson: String(R.collateral.qeIdentityJson) } }) });
  await real('collateral-tcbinfo-as-qe-identity', 'reject', 'The TCB info in the QE identity slot.', { ev: realEv({ col: { qeIdentityJson: info } }) });
  await real('collateral-qe-identity-edited', 'reject', 'QE identity edited after signing.', { ev: realEv({ col: { qeIdentityJson: String(R.collateral.qeIdentityJson).replace('"isvprodid":2', '"isvprodid":3') } }) });
  await real('collateral-chain-wrong-root', 'reject', 'TCB info issuer chain without the Intel root.', { ev: realEv({ col: { tcbInfoIssuerChainPem: R.collateral.tcbInfoIssuerChainPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\n?/)![0] } }) });
  await real('collateral-chain-empty', 'reject', 'Empty issuer chain is incomplete collateral.', { ev: realEv({ col: { tcbInfoIssuerChainPem: '' } }) });
  await real('collateral-pck-crl-empty', 'reject', 'Empty PCK CRL is incomplete collateral.', { ev: realEv({ col: { pckCrlDer: new Uint8Array(0) } }) });
  await real('collateral-pck-crl-processor', 'reject', "The processor-CA PCK CRL does not belong to this quote's PCK CA.", { ev: realEv({ col: { pckCrlDer: fxBytes('real-tdx-collateral', 'pckcrl-processor.der') } }) });
  await real('collateral-pck-crl-flipped', 'reject', 'A flipped byte of the PCK CRL.', { ev: realEv({ col: { pckCrlDer: flip(R.collateral.pckCrlDer, 100) } }) });
  await real('collateral-root-crl-flipped', 'reject', 'A flipped byte of the root CRL.', { ev: realEv({ col: { rootCrlDer: flip(R.collateral.rootCrlDer, 60) } }) });
  await real('collateral-root-crl-trailing', 'reject', 'A trailing byte after the root CRL.', { ev: realEv({ col: { rootCrlDer: append(R.collateral.rootCrlDer, 0) } }) });
  await real('collateral-root-crl-garbage', 'reject', 'Garbage root CRL.', { ev: realEv({ col: { rootCrlDer: textBytes('garbage') } }) });
  await real('collateral-root-crl-swapped', 'reject', 'Root CRL and PCK CRL swapped.', { ev: realEv({ col: { rootCrlDer: R.collateral.pckCrlDer, pckCrlDer: R.collateral.rootCrlDer } }) });
  // clocks
  const tcb = JSON.parse(info) as { tcbInfo: { issueDate: string; nextUpdate: string } };
  await real('clock-after-2031', 'reject', 'Clock years after every collateral window.', { now: Date.parse('2031-01-01T00:00:00Z') });
  await real('clock-before-issue', 'reject', 'Clock before the collateral was issued.', { now: Date.parse(tcb.tcbInfo.issueDate) - 3_600_000 });
  await real('clock-after-quote-chain', 'reject', 'Clock far in the future: every window is over.', { now: Date.parse('2100-01-01T00:00:00Z') });
  await real('clock-before-pck-valid', 'reject', 'Clock before the PCK certificate validity.', { now: Date.parse('2020-01-01T00:00:00Z') });
  await real('clock-nonfinite-skipped', 'accept', 'A later clock still inside every window (one day on).', { now: DCAP_REAL_NOW + 86_400_000 });
  // quote byte edits
  await real('quote-appended-zero', 'accept', 'One more zero byte after the declared signature data (Azure already pads 70).', { ev: realEv({ quote: append(q, 0) }), tags: ['strictness'] });
  await real('quote-appended-nonzero', 'reject', 'A non-zero byte after the signature data.', { ev: realEv({ quote: append(q, 1) }), tags: ['strictness'] });
  await real('quote-nonzero-in-padding', 'reject', 'A non-zero byte inside the existing zero padding.', { ev: realEv({ quote: setByte(q, q.length - 5, 0x01) }), tags: ['strictness'] });
  await real('quote-truncated-padding', 'accept', 'The zero padding removed entirely is still the same signed quote.', { ev: realEv({ quote: cut(q, q.length - 70) }) });
  await real('quote-empty', 'reject', 'Empty quote.', { ev: realEv({ quote: new Uint8Array(0) }) });
  await real('quote-too-short', 'reject', 'Shorter than header + TD report + length.', { ev: realEv({ quote: cut(q, 600) }) });
  await real('quote-version-3', 'reject', 'Quote version 3.', { ev: realEv({ quote: setByte(q, 0, 3) }) });
  await real('quote-att-key-type-3', 'reject', 'Attestation key type 3.', { ev: realEv({ quote: setByte(q, 2, 3) }) });
  await real('quote-tee-type-0', 'reject', 'TEE type 0 (SGX).', { ev: realEv({ quote: setByte(q, 4, 0) }) });
  await real('quote-flip-header-user-data', 'reject', 'A bit flipped in the header user data.', { ev: realEv({ quote: flip(q, 30) }) });
  await real('quote-flip-mrtd', 'reject', 'A bit flipped in the MRTD.', { ev: realEv({ quote: flip(q, 48 + TD10_FIELDS.MRTD) }) });
  await real('quote-flip-report-data', 'reject', 'A bit flipped in report_data.', { ev: realEv({ quote: flip(q, 48 + TD10_FIELDS.REPORT_DATA) }) });
  await real('quote-flip-td-attributes', 'reject', 'A bit flipped in TD_ATTRIBUTES (the debug bit).', { ev: realEv({ quote: flip(q, 48 + TD10_FIELDS.TD_ATTRIBUTES) }) });
  await real('quote-flip-last-body', 'reject', 'Last byte of the TD report body flipped.', { ev: realEv({ quote: flip(q, 48 + 583) }) });
  await real('quote-flip-quote-signature', 'reject', 'A bit flipped in the quote signature.', { ev: realEv({ quote: flip(q, DCAP_OFFSETS.QUOTE_SIG + 5) }) });
  await real('quote-flip-ak', 'reject', 'A bit flipped in the attestation key.', { ev: realEv({ quote: flip(q, DCAP_OFFSETS.AK + 5) }) });
  const sigLen = Buffer.from(q).readUInt32LE(DCAP_OFFSETS.SIG_DATA_LEN);
  const withSigLen = (n: number) => { const b = new Uint8Array(q); Buffer.from(b.buffer).writeUInt32LE(n, DCAP_OFFSETS.SIG_DATA_LEN); return b; };
  await real('quote-sigdata-len-covers-padding', 'accept', 'The declared signature-data length grown by 16 over the zero padding.', { ev: realEv({ quote: withSigLen(sigLen + 16) }), tags: ['strictness'] });
  await real('quote-sigdata-len-over-padding', 'reject', 'The declared length grown past the end of the quote.', { ev: realEv({ quote: withSigLen(sigLen + 71) }), tags: ['strictness'] });
  await real('quote-sigdata-len-short', 'reject', 'The declared length shortened by 16: the PEM tail becomes unaccounted bytes.', { ev: realEv({ quote: withSigLen(sigLen - 16) }), tags: ['strictness'] });
  await real('quote-flip-outer-type', 'reject', 'Outer certification data type edited.', { ev: realEv({ quote: setByte(q, DCAP_OFFSETS.OUTER_TYPE, 5) }) });
  await real('quote-flip-qe-report', 'reject', 'A bit flipped in the QE report.', { ev: realEv({ quote: flip(q, DCAP_OFFSETS.QE_REPORT + 3) }) });
  await real('quote-flip-qe-report-signature', 'reject', 'A bit flipped in the QE report signature.', { ev: realEv({ quote: flip(q, DCAP_OFFSETS.QE_SIG + 9) }) });
  await real('quote-flip-qe-auth', 'reject', 'A bit flipped in the QE authentication data.', { ev: realEv({ quote: flip(q, DCAP_OFFSETS.QE_AUTH + 2) }) });
  const pemAt = Buffer.from(q).indexOf('-----BEGIN CERTIFICATE-----');
  await real('quote-flip-pck-pem', 'reject', 'A character of the embedded PCK PEM changed.', { ev: realEv({ quote: setByte(q, pemAt + 60, q[pemAt + 60] === 0x41 ? 0x42 : 0x41) }) });
  await real('quote-other-boot-report-data', 'reject', 'A genuine quote of another boot: report_data is not a PCA binding.', { ev: realEv({ quote: R.otherQuote }), cfg: { binding: 'report-data', policy: { mrtds: [toHex(parseDcapTdReport(parseDcapQuote(R.otherQuote).tdReportBody).mrTd)] } } });
  await real('evidence-null', 'reject', 'No evidence for the action.', { ev: null });
  await real('evidence-no-quote', 'reject', 'Evidence without a quote.', { ev: { runtimeData: b64(R.runtime) } });

  // ── synthetic quotes under a test Intel PKI ────────────────────────────────
  const syn = (id: string, intent: 'accept' | 'reject', description: string, s: DcapSyn, o: { mode?: 'report-data' | 'azure-runtime-data'; policy?: JsonObject; cfg?: JsonObject; now?: number; binding?: WireBinding; ev?: JsonObject | null; tags?: string[] } = {}) =>
    c.add({ id: `tdx-syn-${id}`, vendor: 'intel-tdx-dcap', tags: ['synthetic', ...(o.tags ?? [])], intent, description, config: dcapSynConfig(s, o.mode, o.policy, o.cfg), now: o.now ?? DCAP_NOW, binding: o.binding ?? SYN_BINDING, evidence: o.ev === undefined ? s.evidence : o.ev });
  const base = dcapSyn();
  const rtb = dcapSyn({ mode: 'azure-runtime-data' });
  const withQ = (quote: ForgeTdxOptions, col?: ForgeCollateralOptions) => dcapSyn({ quote, ...(col ? { col } : {}) });
  const withBytes = (s: DcapSyn, quote: Uint8Array): JsonObject => ({ ...s.evidence, quote: b64(quote) });
  await syn('positive-report-data', 'accept', 'Forged quote and PCS collateral under a test root, direct binding.', base);
  await syn('positive-azure-runtime-data', 'accept', 'Runtime-data binding.', rtb, { mode: 'azure-runtime-data' });
  await syn('no-pin-wrong-root', 'reject', "Without the test pin the forged root is not Intel's.", base, { cfg: { trustAnchorRootCaSpkiSha256: undefined as never } });
  await syn('pin-uppercase', 'accept', 'An upper-case pin compares case-insensitively.', base, { cfg: { trustAnchorRootCaSpkiSha256: base.pin.toUpperCase() } });
  await syn('pin-other', 'reject', 'Another pin.', base, { cfg: { trustAnchorRootCaSpkiSha256: 'ab'.repeat(32) } });
  await syn('collateral-missing', 'reject', 'No collateral by default.', dcapSyn({ noCollateral: true }));
  await syn('collateral-missing-allowed', 'accept', 'allowMissingCollateral: tcb_status unevaluated.', dcapSyn({ noCollateral: true }), { cfg: { allowMissingCollateral: true } });
  for (const [n, b] of relays(SYN_BINDING)) await syn(`relayed-${n}`, 'reject', `Direct binding: another ${n}.`, base, { binding: b });
  for (const [n, b] of badBindings(SYN_BINDING)) await syn(`bad-binding-${n}`, 'reject', `Direct binding ${n}: not constructible.`, base, { binding: b });
  for (const [n, b] of relays(SYN_BINDING)) await syn(`rt-relayed-${n}`, 'reject', `Runtime binding: another ${n}.`, rtb, { binding: b, mode: 'azure-runtime-data' });
  await syn('unbound-zero-report-data', 'reject', 'report_data all zero.', dcapSyn({ reportData: new Uint8Array(64) }));
  const rtText = (text: string) => dcapSyn({ mode: 'azure-runtime-data', runtimeText: text });
  const ud = hexOf(bindingBytes(SYN_BINDING));
  for (const [n, text] of [['not-json', 'not json'], ['array', '[1]'], ['no-user-data', '{"a":1}'], ['user-data-number', '{"user-data":1}'], ['user-data-short', `{"user-data":"${ud.slice(2)}"}`], ['user-data-nonhex', `{"user-data":"${'g'.repeat(128)}"}`], ['user-data-other', `{"user-data":"${'11'.repeat(64)}"}`]] as const) {
    await syn(`rt-${n}`, 'reject', `Runtime data: ${n}.`, rtText(text), { mode: 'azure-runtime-data' });
  }
  await syn('rt-user-data-uppercase', 'accept', 'Upper-case hex user-data.', rtText(`{"user-data":"${ud.toUpperCase()}"}`), { mode: 'azure-runtime-data' });
  await syn('rt-report-data-tail-nonzero', 'reject', 'report_data[32:64] not zero.', dcapSyn({ mode: 'azure-runtime-data', reportData: cat(createHash('sha256').update(rtb.runtime!).digest(), new Uint8Array(31), Uint8Array.of(1)) }), { mode: 'azure-runtime-data' });
  await syn('rt-report-data-hash-mismatch', 'reject', 'report_data[0:32] not the hash of the runtime data.', dcapSyn({ mode: 'azure-runtime-data', reportData: new Uint8Array(64).fill(3) }), { mode: 'azure-runtime-data' });
  await syn('rt-missing-bytes', 'reject', 'Runtime binding without runtime bytes.', rtb, { mode: 'azure-runtime-data', ev: { quote: rtb.evidence['quote']!, collateral: rtb.evidence['collateral']! } });

  // framing
  const Q = base.f.quote;
  const patchAt = (off: number, v: Uint8Array) => {
    const o = new Uint8Array(Q);
    o.set(v, off);
    return o;
  };
  const framing: Array<[string, Uint8Array]> = [
    ['too-short', cut(Q, 600)], ['empty', new Uint8Array(0)], ['version-3', patchAt(0, u16(3))], ['att-key-type-3', patchAt(2, u16(3))], ['tee-type-0', patchAt(4, u32(0))],
    ['sig-data-overruns', patchAt(DCAP_OFFSETS.SIG_DATA_LEN, u32(Q.length))], ['sig-data-zero', patchAt(DCAP_OFFSETS.SIG_DATA_LEN, u32(0))], ['sig-data-64', patchAt(DCAP_OFFSETS.SIG_DATA_LEN, u32(64))],
    ['sig-data-131', patchAt(DCAP_OFFSETS.SIG_DATA_LEN, u32(131))], ['outer-type-5', patchAt(DCAP_OFFSETS.OUTER_TYPE, u16(5))], ['outer-size-overruns', patchAt(DCAP_OFFSETS.OUTER_SIZE, u32(1_000_000))],
    ['qe-auth-size-ffff', patchAt(DCAP_OFFSETS.QE_AUTH_SIZE, u16(0xffff))], ['inner-type-6', patchAt(base.f.offsets.innerType, u16(6))], ['inner-size-overruns', patchAt(base.f.offsets.innerSize, u32(base.f.offsets.pemLen + 500))],
  ];
  for (const [n, b] of framing) await syn(`framing-${n}`, 'reject', `Quote framing: ${n}.`, base, { ev: withBytes(base, b), tags: ['strictness'] });
  await syn('framing-understated-sig-data', 'reject', 'Understated signature-data length.', withQ({ sigDataLenDelta: -(base.f.offsets.pemLen + 6 + 32 + 2 + 64 + 100) }));
  await syn('pad-70-zero', 'accept', 'Azure pads 70 zero bytes after the signature data.', withQ({ trailingPad: 70 }), { tags: ['strictness'] });
  await syn('pad-1-zero', 'accept', 'One zero byte of padding.', withQ({ trailingPad: 1 }), { tags: ['strictness'] });
  await syn('pad-nonzero-last', 'reject', 'Non-zero final padding byte.', withQ({ trailingPad: 70 }), { ev: withBytes(withQ({ trailingPad: 70 }), setByte(withQ({ trailingPad: 70 }).f.quote, withQ({ trailingPad: 70 }).f.quote.length - 1, 1)), tags: ['strictness'] });
  await syn('pad-nonzero-first', 'reject', 'Non-zero first byte after the signature data.', base, { ev: withBytes(base, append(Q, 0x80)), tags: ['strictness'] });
  await syn('pad-nonzero-after-zeros', 'reject', 'Non-zero byte after zeros of padding.', base, { ev: withBytes(base, append(Q, 0, 0, 0, 7)), tags: ['strictness'] });

  // chain
  const pki = base.f.pki;
  // the collateral is re-minted for the quote and for the row's own clock, so only the quote/chain varies
  const evq = (f: ForgedTdxQuote, now: number) => ({ quote: b64(f.quote), collateral: colWire(forgeTdxCollateral(f, windows(now))) });
  const std = (id: string, intent: 'accept' | 'reject', desc: string, f: ForgedTdxQuote, o: { cfg?: JsonObject; policy?: JsonObject; now?: number; tags?: string[] } = {}) =>
    syn(id, intent, desc, base, { ...o, ev: evq(f, o.now ?? DCAP_NOW) });
  await std('chain-root-first', 'accept', 'Chain order root, CA, leaf.', forgeTdxQuote({ td: { reportData: bindingBytes(SYN_BINDING) }, chain: { order: [pki.root, pki.platformCa, base.f.pck] } }));
  await std('chain-shuffled', 'accept', 'Chain order CA, leaf, root.', forgeTdxQuote({ td: { reportData: bindingBytes(SYN_BINDING) }, chain: { order: [pki.platformCa, base.f.pck, pki.root] } }));
  await std('chain-no-trailing-nul', 'accept', 'PEM without the trailing NUL.', forgeTdxQuote({ td: { reportData: bindingBytes(SYN_BINDING) }, chain: { noNul: true } }));
  const qOpt = (more: ForgeTdxOptions): ForgeTdxOptions => ({ ...more, td: { reportData: bindingBytes(SYN_BINDING), ...(more.td ?? {}) } });
  await std('chain-empty-pem', 'reject', 'Empty PEM.', forgeTdxQuote(qOpt({ chain: { pemOverride: '' } })));
  await std('chain-missing-platform-ca', 'reject', 'Platform CA missing.', forgeTdxQuote(qOpt({ chain: { order: [base.f.pck, pki.root] } })));
  await std('chain-leaf-only', 'reject', 'Leaf only.', forgeTdxQuote(qOpt({ chain: { order: [base.f.pck] } })));
  const k = forgeKey('stranger', 'P-256');
  const stranger = forgeCert({ subject: [['CN', 'Stranger CA']], issuer: [['CN', 'Stranger CA']], subjectKey: k, signer: k, serial: 5n, notBefore: new Date('2020-01-01Z'), notAfter: new Date('2040-01-01Z') });
  await std('chain-orphan-appended', 'reject', 'An orphan certificate appended.', forgeTdxQuote(qOpt({ chain: { appendPem: stranger.pem } })));
  await std('chain-leaf-signed-by-other', 'reject', 'PCK leaf not signed by the Platform CA.', forgeTdxQuote(qOpt({ pck: { issuerKey: forgeKey('evil-ca', 'P-256') } })));
  await std('chain-ca-signed-by-other', 'reject', 'Platform CA not signed by the root.', forgeTdxQuote(qOpt({ pki: forgeIntelPki('p1', { caSignedBy: forgeKey('evil-root', 'P-256') }) })), { cfg: { trustAnchorRootCaSpkiSha256: forgeIntelPki('p1', { caSignedBy: forgeKey('evil-root', 'P-256') }).rootSpkiSha256 } });
  const rootBad = forgeIntelPki('p2', { rootSelfSigned: false });
  await std('chain-root-not-self-signed', 'reject', 'Root whose self-signature fails.', forgeTdxQuote(qOpt({ pki: rootBad })), { cfg: { trustAnchorRootCaSpkiSha256: rootBad.rootSpkiSha256 } });
  const rsa = forgeRsaKey('dcap-pck-rsa').spki;
  await std('chain-leaf-rsa-key', 'reject', 'PCK leaf with an RSA key.', forgeTdxQuote(qOpt({ pck: { spkiOverride: rsa } })));
  const offCurve = seq(seq(oid('1.2.840.10045.2.1'), oid('1.2.840.10045.3.1.7')), tlv(0x03, Uint8Array.of(0), Uint8Array.of(4), new Uint8Array(64).fill(7)));
  await std('chain-leaf-off-curve', 'reject', 'PCK leaf point not on the curve.', forgeTdxQuote(qOpt({ pck: { spkiOverride: offCurve } })));
  await std('chain-leaf-p384', 'reject', 'PCK leaf on P-384.', forgeTdxQuote(qOpt({ pck: { spkiOverride: forgeKey('wrong-curve', 'P-384').spki } })));
  await std('chain-leaf-spki-trailing', 'reject', 'PCK SPKI with bytes after the point.', forgeTdxQuote(qOpt({ pck: { spkiOverride: cat(forgeKey('trail', 'P-256').spki, Uint8Array.of(0, 0, 0)) } })));
  await std('chain-leaf-short-point', 'reject', 'PCK point with a 31-byte coordinate.', forgeTdxQuote(qOpt({ pck: { spkiOverride: seq(seq(oid('1.2.840.10045.2.1'), oid('1.2.840.10045.3.1.7')), tlv(0x03, Uint8Array.of(0), forgeKey('forge-tdx/pck/leaf', 'P-256').pub.slice(0, 64))) } })));
  await std('chain-garbage-pem', 'reject', 'Garbage inside a PEM block.', forgeTdxQuote(qOpt({ chain: { pemOverride: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n' } })));
  await std('chain-leaf-expired', 'reject', 'Expired PCK leaf.', forgeTdxQuote(qOpt({ pck: { notBefore: new Date('2019-01-01Z'), notAfter: new Date('2020-01-01Z') } })));
  await std('chain-leaf-not-yet-valid', 'reject', 'PCK leaf not yet valid.', forgeTdxQuote(qOpt({ pck: { notBefore: new Date('2040-01-01Z'), notAfter: new Date('2041-01-01Z') } })));
  const caOld = forgeIntelPki('clk1', { caValidity: [new Date('2018-01-01Z'), new Date('2026-06-01Z')] });
  await std('chain-ca-expired', 'reject', 'Expired Platform CA.', forgeTdxQuote(qOpt({ pki: caOld })), { cfg: { trustAnchorRootCaSpkiSha256: caOld.rootSpkiSha256 } });
  const rootOld = forgeIntelPki('clk2', { rootValidity: [new Date('2018-01-01Z'), new Date('2026-06-01Z')] });
  await std('chain-root-expired', 'reject', 'Expired root.', forgeTdxQuote(qOpt({ pki: rootOld })), { cfg: { trustAnchorRootCaSpkiSha256: rootOld.rootSpkiSha256 } });
  const edge = forgeTdxQuote(qOpt({ pck: { notBefore: new Date('2026-10-20T00:00:00Z'), notAfter: new Date('2027-01-01T00:00:00Z') } }));
  await std('chain-leaf-at-not-before', 'accept', 'Clock exactly at the PCK notBefore.', edge);
  await std('chain-leaf-1s-before-not-before', 'reject', 'One second before the PCK notBefore.', edge, { now: DCAP_NOW - 1000 });
  await std('chain-leaf-at-not-after', 'accept', 'Clock exactly at the PCK notAfter.', edge, { now: Date.parse('2027-01-01T00:00:00Z') });
  await std('chain-leaf-1s-after-not-after', 'reject', 'One second after the PCK notAfter.', edge, { now: Date.parse('2027-01-01T00:00:01Z') });
  const caAbsent = forgeIntelPki('p3a', { caBasicConstraints: 'absent' });
  await std('chain-ca-no-basic-constraints', 'reject', 'Platform CA without BasicConstraints.', forgeTdxQuote(qOpt({ pki: caAbsent })), { cfg: { trustAnchorRootCaSpkiSha256: caAbsent.rootSpkiSha256 } });
  const caFalse = forgeIntelPki('p3b', { caBasicConstraints: 'ca-false' });
  await std('chain-ca-ca-false', 'reject', 'Platform CA with CA:FALSE.', forgeTdxQuote(qOpt({ pki: caFalse })), { cfg: { trustAnchorRootCaSpkiSha256: caFalse.rootSpkiSha256 } });
  await std('chain-leaf-ca-true', 'reject', 'PCK leaf asserting CA:TRUE.', forgeTdxQuote(qOpt({ pck: { ca: true } })));
  await std('chain-leaf-no-basic-constraints', 'accept', 'A PCK leaf without BasicConstraints is fine.', forgeTdxQuote(qOpt({ pck: { ca: 'absent' } })));
  const crit = extension('1.2.3.4.5', true, octets(Uint8Array.of(1)));
  await std('chain-leaf-unknown-critical', 'reject', 'PCK leaf with an unrecognised critical extension.', forgeTdxQuote(qOpt({ pck: { extraExtensions: [crit] } })), { tags: ['strictness'] });
  const caCrit = forgeIntelPki('p4a', { caExtra: [crit] });
  await std('chain-ca-unknown-critical', 'reject', 'Platform CA with an unrecognised critical extension.', forgeTdxQuote(qOpt({ pki: caCrit })), { cfg: { trustAnchorRootCaSpkiSha256: caCrit.rootSpkiSha256 }, tags: ['strictness'] });
  const rootCrit = forgeIntelPki('p4b', { rootExtra: [crit] });
  await std('chain-root-unknown-critical', 'reject', 'Root with an unrecognised critical extension.', forgeTdxQuote(qOpt({ pki: rootCrit })), { cfg: { trustAnchorRootCaSpkiSha256: rootCrit.rootSpkiSha256 }, tags: ['strictness'] });
  await std('chain-leaf-unknown-noncritical', 'accept', 'An unknown NON-critical extension is ignored.', forgeTdxQuote(qOpt({ pck: { extraExtensions: [extension('1.2.3.4.6', false, octets(Uint8Array.of(1)))] } })));
  await std('chain-leaf-duplicate-extension', 'reject', 'PCK leaf with a duplicated BasicConstraints.', forgeTdxQuote(qOpt({ pck: { extraExtensions: [ext.basicConstraints(false)] } })), { tags: ['strictness'] });
  // trailing bytes after a certificate inside the PEM chain (the DER carries a zero byte)
  const trailingCertPem = (() => {
    const o = forgeTdxQuote(qOpt({}));
    const der = new Uint8Array(Buffer.from(o.pck.pem.replace(/-----[A-Z ]+-----|\s/g, ''), 'base64'));
    return pemOf(append(der, 0)) + o.platformCa.pem + o.pki.root.pem;
  })();
  await std('chain-leaf-trailing-der-byte', 'reject', 'A zero byte after the PCK leaf DER inside its PEM block.', forgeTdxQuote(qOpt({ chain: { pemOverride: trailingCertPem } })), { tags: ['strictness'] });
  await std('debug-qe', 'reject', 'Debug quoting enclave.', forgeTdxQuote(qOpt({ qe: { attributes: '1700000000000000e700000000000000' } })));
  // QE / AK / TD signature
  await std('qe-signed-by-other', 'reject', 'QE report signed by a key other than the PCK leaf.', forgeTdxQuote(qOpt({ qe: { signer: forgeKey('evil-qe', 'P-256') } })));
  await std('qe-report-data-wrong', 'reject', 'QE report_data is not hash(AK || auth).', forgeTdxQuote(qOpt({ qe: { reportData: new Uint8Array(64).fill(1) } })));
  await std('qe-report-data-tail-nonzero', 'reject', 'QE report_data tail non-zero.', forgeTdxQuote(qOpt({ qe: { reportData: cat(createHash('sha256').update(cat(forgeKey('forge-tdx/ak', 'P-256').pub.subarray(1), forgeTdxQuote({}).qeAuth)).digest(), new Uint8Array(31), Uint8Array.of(1)) } })));
  await syn('qe-swapped-attestation-key', 'reject', 'A valid AK the QE never endorsed.', base, { ev: withBytes(base, patchAt(DCAP_OFFSETS.AK, forgeKey('other-ak', 'P-256').pub.subarray(1))) });
  await syn('qe-attestation-key-off-curve', 'reject', 'An endorsed-looking AK that is not a curve point.', base, { ev: withBytes(base, patchAt(DCAP_OFFSETS.AK, new Uint8Array(64).fill(7))) });
  await std('td-signed-by-other-key', 'reject', 'TD region signed by a key other than the endorsed AK.', forgeTdxQuote(qOpt({ tdSigner: forgeKey('evil-ak', 'P-256') })));
  await std('qe-auth-data-tampered', 'reject', 'QE auth data edited after the QE endorsed the AK.', (() => { const o = forgeTdxQuote(qOpt({})); const b = new Uint8Array(o.quote); b[DCAP_OFFSETS.QE_AUTH] = b[DCAP_OFFSETS.QE_AUTH]! ^ 1; return { ...o, quote: b }; })());
  for (const [n, at] of [['header', 10], ['td-body', 48 + 100], ['mrtd', 48 + TD10_FIELDS.MRTD], ['report-data', 48 + TD10_FIELDS.REPORT_DATA], ['quote-signature', DCAP_OFFSETS.QUOTE_SIG + 3], ['ak', DCAP_OFFSETS.AK + 3], ['qe-report', DCAP_OFFSETS.QE_REPORT + 100], ['qe-signature', DCAP_OFFSETS.QE_SIG + 3]] as const) {
    await syn(`flip-${n}`, 'reject', `A bit flipped after signing (${n}).`, base, { ev: withBytes(base, flip(Q, at)) });
  }
  // debug TD, policy gates
  await std('td-debug', 'reject', 'TD_ATTRIBUTES.DEBUG set.', forgeTdxQuote(qOpt({ td: { debug: true } })));
  await std('td-debug-allowed', 'accept', 'allowDebug true accepts the debug TD.', forgeTdxQuote(qOpt({ td: { debug: true } })), { policy: { allowDebug: true } });
  await std('td-debug-allow-false', 'reject', 'allowDebug false keeps refusing.', forgeTdxQuote(qOpt({ td: { debug: true } })), { policy: { allowDebug: false } });
  await std('td-other-attribute-bits-ok', 'accept', 'Only bit 0 matters: SEPT_VE_DISABLE, PKS, KL and PERFMON do not trigger the debug gate.', forgeTdxQuote(qOpt({ td: { tdAttributes: '000000f00000001e' } })));
  await syn('mrtd-other', 'reject', 'MRTD not allowlisted.', base, { policy: { mrtds: ['00'.repeat(48)] } });
  await syn('mrtd-uppercase', 'accept', 'Case-insensitive MRTD.', base, { policy: { mrtds: [base.mrtd.toUpperCase()] } });
  await syn('mrtds-empty', 'reject', 'Empty MRTD list.', base, { policy: { mrtds: [] } });
  await syn('mrtds-bad-length', 'reject', 'MRTD of the wrong length.', base, { policy: { mrtds: ['abcd'] } });
  await syn('fmspc-match', 'accept', 'FMSPC allowlisted.', base, { policy: { fmspcs: ['90c06f000000'] } });
  await syn('fmspc-other', 'reject', 'FMSPC not allowlisted.', base, { policy: { fmspcs: ['aabbccddeeff'] } });
  await syn('fmspc-empty-list-not-gated', 'accept', 'An empty FMSPC list does not gate.', base, { policy: { fmspcs: [] } });
  const rt0 = hexOf(parseDcapTdReport(parseDcapQuote(Q).tdReportBody).rtmr0);
  await syn('rtmr0-match', 'accept', 'RTMR0 allowlisted.', base, { policy: { rtmrs: [rt0] } });
  await syn('rtmr0-other', 'reject', 'RTMR0 not allowlisted.', base, { policy: { rtmrs: ['00'.repeat(48)] } });
  const tdp = parseDcapTdReport(parseDcapQuote(Q).tdReportBody);
  await syn('mr-seam-match', 'accept', 'MRSEAM allowlisted (upper case).', base, { policy: { mrSeams: [toHex(tdp.mrSeam).toUpperCase()] } });
  await syn('mr-seam-off-by-one', 'reject', 'MRSEAM differing in one nibble.', base, { policy: { mrSeams: [toHex(tdp.mrSeam).replace(/.$/, (ch) => (ch === '0' ? '1' : '0'))] } });
  await syn('mr-signer-seam-match', 'accept', 'MRSIGNERSEAM allowlisted.', base, { policy: { mrSignerSeams: [toHex(tdp.mrSignerSeam)] } });
  await syn('mr-signer-seam-other', 'reject', 'MRSIGNERSEAM not allowlisted.', base, { policy: { mrSignerSeams: ['44'.repeat(48)] } });
  await syn('mr-seams-empty', 'reject', 'Empty mrSeams refused at construction.', base, { policy: { mrSeams: [] } });
  await syn('mr-signer-seams-bad-entry', 'reject', 'Malformed mrSignerSeams entry.', base, { policy: { mrSignerSeams: ['zz'] } });
  await syn('identity-default', 'accept', 'Default identity: runtime_measurement = MRTD.', base);
  await syn('identity-overrides', 'accept', 'identity_overrides merge.', base, { cfg: { identity_overrides: { model_id: 'model-x', operator: 'op-y', weights_digest: 'wd', weights_measured: true } } });

  // SGX extension branches
  await std('sgx-extension-absent', 'reject', 'PCK without the SGX extension.', forgeTdxQuote(qOpt({ pck: { noSgxExtension: true } })));
  await std('sgx-fmspc-absent', 'reject', 'FMSPC sub-extension absent.', forgeTdxQuote(qOpt({ pck: { ext: { omit: ['fmspc'] } } })));
  await std('sgx-tcb-absent', 'reject', 'TCB sub-extension absent.', forgeTdxQuote(qOpt({ pck: { ext: { omit: ['tcb'] } } })));
  await std('sgx-pcesvn-absent', 'reject', 'PCESVN absent from the TCB sequence.', forgeTdxQuote(qOpt({ pck: { ext: { omit: ['pcesvn'] } } })));
  await std('sgx-fmspc-5-bytes', 'reject', 'A 5-byte FMSPC.', forgeTdxQuote(qOpt({ pck: { ext: { fmspcLen: 5 } } })));

  // collateral
  const colRow = (id: string, intent: 'accept' | 'reject', desc: string, quote: ForgeTdxOptions | undefined, col: ForgeCollateralOptions, o: { policy?: JsonObject; now?: number; cfg?: JsonObject } = {}) => {
    const s = dcapSyn({ ...(quote ? { quote: qOpt(quote) } : {}), col });
    return syn(`col-${id}`, intent, desc, s, { ...o, tags: ['collateral'] });
  };
  const sampleForge = forgeTdxQuote({ td: { reportData: bindingBytes(SYN_BINDING) } });
  const spec0 = defaultTcbInfoSpec(sampleForge);
  await colRow('uptodate', 'accept', 'Default collateral: everything UpToDate.', undefined, {});
  for (const [status, intent] of [['SWHardeningNeeded', 'accept'], ['ConfigurationNeeded', 'reject'], ['ConfigurationAndSWHardeningNeeded', 'reject'], ['OutOfDateConfigurationNeeded', 'reject'], ['OutOfDate', 'reject'], ['Revoked', 'reject']] as const) {
    await colRow(`platform-${status}`, intent, `Platform level status ${status} against the default accepted set.`, undefined, { tcbInfo: { levels: [{ ...spec0.levels[0]!, status }] } });
  }
  await colRow('out-of-date-accepted-by-policy', 'accept', 'OutOfDate listed in acceptStatuses, with advisories surfaced sorted.', undefined, { tcbInfo: { levels: [{ ...spec0.levels[0]!, status: 'OutOfDate', advisories: ['INTEL-SA-00002', 'INTEL-SA-00001'] }] } }, { policy: { collateral: { acceptStatuses: ['OutOfDate'] } } });
  await colRow('advisories-on-failure', 'reject', 'Advisories do not hide a refused status.', undefined, { tcbInfo: { levels: [{ ...spec0.levels[0]!, status: 'OutOfDate', advisories: ['INTEL-SA-00009'] }] } });
  await colRow('qe-out-of-date', 'reject', 'QE identity level OutOfDate.', undefined, { qeIdentity: { levels: [{ isvsvn: 4, status: 'OutOfDate' }] } });
  await colRow('qe-sw-hardening', 'accept', 'QE level SWHardeningNeeded with an advisory.', undefined, { qeIdentity: { levels: [{ isvsvn: 4, status: 'SWHardeningNeeded', advisories: ['INTEL-SA-00500'] }] } });
  await colRow('qe-merge-worst', 'reject', 'The merged status is the worst of platform, module and QE.', undefined, { tcbInfo: { levels: [{ ...spec0.levels[0]!, status: 'SWHardeningNeeded', advisories: ['INTEL-SA-00001'] }] }, qeIdentity: { levels: [{ isvsvn: 4, status: 'ConfigurationNeeded', advisories: ['INTEL-SA-00001', 'INTEL-SA-00002'] }] } });
  await colRow('merge-worst-accepted-when-listed', 'accept', 'Worst-of merge accepted when the policy lists it.', undefined, { tcbInfo: { levels: [{ ...spec0.levels[0]!, status: 'SWHardeningNeeded', advisories: ['INTEL-SA-00001'] }] }, qeIdentity: { levels: [{ isvsvn: 4, status: 'ConfigurationNeeded', advisories: ['INTEL-SA-00001', 'INTEL-SA-00002'] }] } }, { policy: { collateral: { acceptStatuses: ['ConfigurationNeeded', 'SWHardeningNeeded', 'UpToDate'] } } });
  await colRow('min-eval-number-equal', 'accept', 'tcbEvaluationDataNumber 20 meets a floor of 20.', undefined, {}, { policy: { collateral: { minTcbEvaluationDataNumber: 20 } } });
  await colRow('min-eval-number-above', 'reject', 'Floor 21.', undefined, {}, { policy: { collateral: { minTcbEvaluationDataNumber: 21 } } });
  await colRow('eval-number-missing-tcbinfo', 'reject', 'TCB info without tcbEvaluationDataNumber.', undefined, { tcbInfo: { tcbEvaluationDataNumber: null } });
  await colRow('eval-number-missing-qe', 'reject', 'QE identity without tcbEvaluationDataNumber.', undefined, { qeIdentity: { tcbEvaluationDataNumber: null } });
  await colRow('eval-number-min-of-two', 'reject', 'The floor applies to the lower of the two numbers.', undefined, { tcbInfo: { tcbEvaluationDataNumber: 25 }, qeIdentity: { tcbEvaluationDataNumber: 19 } }, { policy: { collateral: { minTcbEvaluationDataNumber: 20 } } });
  await colRow('empty-accept-statuses', 'reject', 'Empty acceptStatuses accepts nothing.', undefined, {}, { policy: { collateral: { acceptStatuses: [] } } });
  const w = windows(DCAP_NOW);
  await colRow('tcbinfo-stale', 'reject', 'TCB info past its nextUpdate.', undefined, { tcbInfo: { ...w.tcbInfo, nextUpdate: new Date(DCAP_NOW - 1000).toISOString().replace('.000Z', 'Z') } });
  await colRow('tcbinfo-issue-future', 'reject', 'TCB info issued in the future.', undefined, { tcbInfo: { ...w.tcbInfo, issueDate: new Date(DCAP_NOW + 86_400_000).toISOString().replace('.000Z', 'Z') } });
  await colRow('tcbinfo-next-update-at-now', 'accept', 'nextUpdate exactly at the clock still counts as fresh.', undefined, { tcbInfo: { ...w.tcbInfo, nextUpdate: new Date(DCAP_NOW).toISOString().replace('.000Z', 'Z') } });
  await colRow('qe-stale', 'reject', 'QE identity past its nextUpdate.', undefined, { qeIdentity: { ...w.qeIdentity, nextUpdate: new Date(DCAP_NOW - 1000).toISOString().replace('.000Z', 'Z') } });
  await colRow('qe-issue-future', 'reject', 'QE identity issued in the future.', undefined, { qeIdentity: { ...w.qeIdentity, issueDate: new Date(DCAP_NOW + 86_400_000).toISOString().replace('.000Z', 'Z') } });
  await colRow('crl-stale', 'reject', 'CRLs past their nextUpdate.', undefined, { crlNextUpdate: new Date(DCAP_NOW - 1000) });
  await colRow('crl-future', 'reject', 'CRLs issued in the future.', undefined, { crlThisUpdate: new Date(DCAP_NOW + 86_400_000) });
  await colRow('pck-leaf-revoked', 'reject', 'The PCK leaf serial on the PCK CRL.', undefined, { pckCrlRevoked: [base.f.pck.serialHex] });
  await colRow('pck-ca-revoked', 'reject', 'The Platform CA serial on the root CRL.', undefined, { rootCrlRevoked: [base.f.platformCa.serialHex] });
  await colRow('unrelated-serials-ignored', 'accept', 'Unrelated serials on both CRLs do not matter.', undefined, { pckCrlRevoked: ['0102030405'], rootCrlRevoked: ['0a0b0c'] });
  await colRow('root-crl-signed-by-stranger', 'reject', 'Root CRL signed by another key.', undefined, { rootCrlSigner: forgeKey('stranger-crl', 'P-256') });
  await colRow('pck-crl-signed-by-stranger', 'reject', 'PCK CRL signed by another key.', undefined, { pckCrlSigner: forgeKey('stranger-crl', 'P-256') });
  await colRow('tcbinfo-signed-by-stranger', 'reject', 'TCB info signed by a key that is not the TCB-signing leaf.', undefined, { signerKey: forgeKey('stranger-tcb', 'P-256') });
  await colRow('tcbinfo-tampered-after-signing', 'reject', 'TCB info altered after signing.', undefined, { tamperTcbInfo: (raw) => raw.replace('"tcbType":0', '"tcbType":1') });
  await colRow('qe-tampered-after-signing', 'reject', 'QE identity altered after signing.', undefined, { tamperQeIdentity: (raw) => raw.replace('"isvprodid":2', '"isvprodid":9') });
  await colRow('tcbinfo-chain-without-root', 'reject', 'TCB info issuer chain without the root.', undefined, { tcbInfoChainPem: base.f.pki.tcbSigning.pem });
  const fmspcOther = defaultTcbInfoSpec(sampleForge);
  await colRow('tcbinfo-other-fmspc', 'reject', 'TCB info for another FMSPC.', undefined, { tcbInfo: { ...fmspcOther, fmspc: 'aabbccddeeff' } });
  await colRow('tcbinfo-not-tdx', 'reject', 'TCB info id is not TDX.', undefined, { tcbInfo: { id: 'SGX' } });
  await colRow('tcbinfo-version-2', 'reject', 'TCB info version 2.', undefined, { tcbInfo: { version: 2 } });
  await colRow('tcbinfo-no-levels', 'reject', 'TCB info without tcbLevels.', undefined, { tcbInfo: { rawLevels: [] } });
  await colRow('tcbinfo-malformed-level', 'reject', 'A tcb level that is not an object.', undefined, { tcbInfo: { rawLevels: [5] } });
  await colRow('tcbinfo-unknown-status', 'reject', 'Unknown tcbStatus.', undefined, { tcbInfo: { levels: [{ ...spec0.levels[0]!, status: 'Fine' as never }] } });
  await colRow('platform-below-lowest-level', 'reject', 'PCK SGX component below the lowest level.', undefined, { tcbInfo: { levels: [{ ...spec0.levels[0]!, sgx: spec0.levels[0]!.sgx.map((v, i) => (i === 0 ? v + 1 : v)) }] } });
  await colRow('pcesvn-below-lowest-level', 'reject', 'PCESVN below the lowest level.', undefined, { tcbInfo: { levels: [{ ...spec0.levels[0]!, pcesvn: spec0.levels[0]!.pcesvn + 1 }] } });
  await colRow('td-tcb-below-lowest-level', 'reject', 'TD TEE_TCB_SVN below the lowest level.', undefined, { tcbInfo: { levels: [{ ...spec0.levels[0]!, tdx: spec0.levels[0]!.tdx.map((v, i) => (i === 5 ? v + 1 : v)) }] } });
  await colRow('first-matching-level-wins', 'accept', 'The first matching level (descending order) supplies status and advisories.', undefined, { tcbInfo: { levels: [{ ...spec0.levels[0]!, status: 'SWHardeningNeeded', advisories: ['INTEL-SA-00777'] }, { ...spec0.levels[0]!, sgx: spec0.levels[0]!.sgx.map(() => 0), pcesvn: 0, status: 'OutOfDate' }] } });
  await colRow('module-identity-missing', 'reject', 'TEE_TCB_SVN minor > 0 and no matching module identity.', undefined, { tcbInfo: { tdxModuleIdentities: [] } });
  await colRow('module-svn-below-all', 'reject', 'Module SVN below every known level.', undefined, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 200, status: 'UpToDate' }] }] } });
  await colRow('module-unknown-status', 'reject', 'Module level with an unknown status.', undefined, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 5, status: 'Fine' as never }] }] } });
  await colRow('module-out-of-date', 'reject', 'Module level OutOfDate folds into the status.', undefined, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', levels: [{ isvsvn: 5, status: 'OutOfDate', advisories: ['INTEL-SA-00123'] }] }] } });
  await colRow('module-mrsigner-mismatch', 'reject', 'TD MRSIGNERSEAM differs from the module identity.', undefined, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', mrsigner: '11'.repeat(48), levels: [{ isvsvn: 5, status: 'UpToDate' }] }] } });
  await colRow('module-attributes-mismatch', 'reject', 'SEAM attributes differ under the mask.', undefined, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', attributes: '0100000000000000', levels: [{ isvsvn: 5, status: 'UpToDate' }] }] } });
  await colRow('module-malformed-mask', 'reject', 'Malformed module attributesMask.', undefined, { tcbInfo: { tdxModuleIdentities: [{ id: 'TDX_01', attributesMask: 'zz', levels: [{ isvsvn: 5, status: 'UpToDate' }] }] } });
  await colRow('minor-zero-base-module', 'accept', 'Minor 0 uses the base tdxModule.', { td: { teeTcbSvn: '05000000000000000000000000000000' }, pck: { sgxTcb: [5, 5, 2, 2, 6, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0] } }, { tcbInfo: { levels: [{ sgx: [5, 5, 2, 2, 6, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0], pcesvn: 13, tdx: [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], status: 'UpToDate' }] } });
  await colRow('minor-zero-no-base-module', 'reject', 'Minor 0 and no tdxModule in the TCB info.', { td: { teeTcbSvn: '05000000000000000000000000000000' } }, { tcbInfo: { tdxModule: null, levels: [{ sgx: [5, 5, 2, 2, 6, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0], pcesvn: 13, tdx: [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], status: 'UpToDate' }] } });
  await colRow('qe-wrong-id', 'reject', 'QE identity id is not TD_QE.', undefined, { qeIdentity: { id: 'QE' } });
  await colRow('qe-wrong-version', 'reject', 'QE identity version 1.', undefined, { qeIdentity: { version: 1 } });
  await colRow('qe-miscselect-mismatch', 'reject', 'MISCSELECT differs.', undefined, { qeIdentity: { miscselect: '01000000' } });
  await colRow('qe-attributes-mismatch', 'reject', 'ATTRIBUTES differ under the mask.', undefined, { qeIdentity: { attributes: '10000000000000000000000000000000' } });
  await colRow('qe-attributes-unmasked-bit-ignored', 'accept', 'A bit outside the mask is ignored.', undefined, { qeIdentity: { attributes: '15000000000000000000000000000000' , attributesMask: 'FBFFFFFFFFFFFFFF0000000000000000' } });
  await colRow('qe-mrsigner-mismatch', 'reject', 'MRSIGNER differs.', undefined, { qeIdentity: { mrsigner: '11'.repeat(32) } });
  await colRow('qe-isvprodid-mismatch', 'reject', 'ISVPRODID differs.', undefined, { qeIdentity: { isvprodid: 3 } });
  await colRow('qe-isvsvn-below-all', 'reject', 'QE ISVSVN below every level.', undefined, { qeIdentity: { levels: [{ isvsvn: 200, status: 'UpToDate' }] } });
  await colRow('qe-unknown-status', 'reject', 'QE level with an unknown status.', undefined, { qeIdentity: { levels: [{ isvsvn: 4, status: 'Fine' as never }] } });
  await colRow('qe-malformed-field', 'reject', 'Malformed QE identity field.', undefined, { qeIdentity: { miscselectMask: 'zz' } });
  await colRow('qe-picks-highest-reached-level', 'accept', 'The highest QE level the ISVSVN reaches decides.', undefined, { qeIdentity: { levels: [{ isvsvn: 9, status: 'OutOfDate' }, { isvsvn: 7, status: 'UpToDate' }, { isvsvn: 4, status: 'OutOfDate' }] } });
  // incomplete collateral, each field
  for (const field of ['tcbInfoJson', 'tcbInfoIssuerChainPem', 'qeIdentityJson', 'qeIdentityIssuerChainPem', 'pckCrlDer', 'rootCrlDer'] as const) {
    const cw = { ...(base.evidence['collateral'] as JsonObject) };
    cw[field] = '';
    await syn(`col-incomplete-${field}`, 'reject', `Collateral without ${field}.`, base, { ev: { quote: base.evidence['quote']!, collateral: cw }, tags: ['collateral'] });
  }
  // signing-chain faults
  const badLeaf = forgeCert({ subject: base.f.pki.tcbDn, issuer: base.f.pki.rootDn, subjectKey: base.f.pki.tcbSigningKey, signer: base.f.pki.rootKey, serial: 77n, notBefore: new Date('2018-05-21Z'), notAfter: new Date('2034-05-21Z'), extensions: [ext.basicConstraints(true)] });
  await colRow('tcbinfo-signer-is-ca', 'reject', 'TCB-signing leaf claiming CA:TRUE.', undefined, { tcbInfoChainPem: badLeaf.pem + base.f.pki.root.pem });
  await colRow('tcbinfo-signer-revoked-on-root-crl', 'reject', 'TCB-signing certificate revoked on the root CRL.', undefined, { rootCrlRevoked: [base.f.pki.tcbSigning.serialHex] });
}
