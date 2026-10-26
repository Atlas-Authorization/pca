// Azure MAA rows of the attestation-evidence conformance vectors (TEST/TOOLING ONLY).
import { createHash } from 'node:crypto';
import { type JsonObject, type WireBinding } from './attestation-wire';
import { Collector, SYN_BINDING, badBindings, bindingBytes, fxText, hexOf, relays } from './attestation-vectors-common';
import { ecdsaSign, forgeCert, forgeKey, ext, type ForgeKey, type ForgedCert } from './forge-x509';
import { forgeRsaKey, rsaSignPkcs1, type ForgeRsaKey } from './forge-rsa';
import { sha512 } from '@noble/hashes/sha512';

const REAL_BINDING: WireBinding = { holderPub: 'pca-realsilicon-azure-tdx-holder', grantRef: 'grant_pca_azure_maa_realsilicon', epoch: 1, nonce: 'srv-nonce-maa-5d3b8e1f9a27c604' };
export const MAA_NOW = 1_790_000_000_000;
const NB = new Date('2025-01-01T00:00:00Z');
const NA = new Date('2035-01-01T00:00:00Z');

const b64u = (s: string | Uint8Array): string => Buffer.from(s).toString('base64url');
const jsonSeg = (o: unknown): string => b64u(JSON.stringify(o));
const split = (t: string): [string, string, string] => t.split('.') as [string, string, string];
const parseSeg = (s: string): Record<string, unknown> => JSON.parse(Buffer.from(s, 'base64url').toString('utf8')) as Record<string, unknown>;

/** Replace the header / payload JSON of a real token (the signature then no longer matches). */
export const editToken = (t: string, o: { header?: (h: Record<string, unknown>) => Record<string, unknown>; payload?: (p: Record<string, unknown>) => Record<string, unknown>; sig?: (s: string) => string }): string => {
  const [h, p, s] = split(t);
  return `${o.header ? jsonSeg(o.header(parseSeg(h))) : h}.${o.payload ? jsonSeg(o.payload(parseSeg(p))) : p}.${o.sig ? o.sig(s) : s}`;
};

export type Signer = { kind: 'ec'; key: ForgeKey } | { kind: 'rsa'; key: ForgeRsaKey };
/** Mint a compact JWS under `signer` (deterministic). */
export function mint(header: Record<string, unknown>, payload: unknown, signer: Signer, over: { signingInput?: string } = {}): string {
  const input = over.signingInput ?? `${jsonSeg(header)}.${jsonSeg(payload)}`;
  const data = new TextEncoder().encode(input);
  const sig = signer.kind === 'ec' ? ecdsaSign(signer.key, 'sha256', data).raw : rsaSignPkcs1(signer.key, 'sha256', data);
  return `${input}.${b64u(sig)}`;
}

export interface MaaWorld {
  ec: { root: ForgedCert; int: ForgedCert; leaf: ForgedCert; leafKey: ForgeKey; rootKey: ForgeKey };
  rsaLeaf: ForgedCert;
  rsaKey: ForgeRsaKey;
  rogue: ForgedCert;
  rogueKey: ForgeKey;
  x5c: (...c: ForgedCert[]) => string[];
}
const dnOf = (cn: string) => [['CN', cn]] as const;
export function maaWorld(label = 'maa'): MaaWorld {
  const rootKey = forgeKey(`${label}/root`, 'P-256');
  const intKey = forgeKey(`${label}/int`, 'P-256');
  const leafKey = forgeKey(`${label}/leaf`, 'P-256');
  const root = forgeCert({ subject: dnOf('maa-root'), issuer: dnOf('maa-root'), subjectKey: rootKey, signer: rootKey, serial: 1n, notBefore: NB, notAfter: NA, extensions: [ext.basicConstraints(true, 2)] });
  const int = forgeCert({ subject: dnOf('maa-int'), issuer: dnOf('maa-root'), subjectKey: intKey, signer: rootKey, serial: 2n, notBefore: NB, notAfter: NA, extensions: [ext.basicConstraints(true, 1)] });
  const leaf = forgeCert({ subject: dnOf('maa-leaf'), issuer: dnOf('maa-int'), subjectKey: leafKey, signer: intKey, serial: 3n, notBefore: NB, notAfter: NA });
  const rsaKey = forgeRsaKey(`${label}/rsa-leaf`);
  const rsaSubject = { ...leafKey, spki: rsaKey.spki } as ForgeKey;
  const rsaLeaf = forgeCert({ subject: dnOf('maa-rsa-leaf'), issuer: dnOf('maa-int'), subjectKey: rsaSubject, signer: intKey, serial: 4n, notBefore: NB, notAfter: NA });
  const rogueKey = forgeKey(`${label}/rogue`, 'P-256');
  const rogue = forgeCert({ subject: dnOf('rogue'), issuer: dnOf('rogue'), subjectKey: rogueKey, signer: rogueKey, serial: 9n, notBefore: NB, notAfter: NA });
  return { ec: { root, int, leaf, leafKey, rootKey }, rsaLeaf, rsaKey, rogue, rogueKey, x5c: (...c) => c.map((x) => Buffer.from(x.der).toString('base64')) };
}

export const MAA_ISS = 'https://conf-maa.attest.example.net';
export const MAA_MRTD = 'ab'.repeat(48);
export const MAA_MEAS = 'cd'.repeat(48);
export const MAA_HOSTDATA = 'ee'.repeat(32);
export const MAA_RTMR0 = '12'.repeat(48);

/** The standard claim sets (what a real MAA emits, keyed as the verifier reads them). */
export function maaTdxClaims(binding: WireBinding, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    'x-ms-attestation-type': 'tdxvm', tdx_mrtd: MAA_MRTD, tdx_rtmr0: MAA_RTMR0, attester_tcb_status: 'UpToDate', dbgstat: 'disabled', tdx_td_attributes_debug: false,
    tdx_report_data: hexOf(bindingBytes(binding)), 'x-ms-runtime': { 'user-data': hexOf(bindingBytes(binding)), keys: [] }, ...over,
  };
}
export function maaSnpClaims(binding: WireBinding, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    'x-ms-attestation-type': 'sevsnpvm', 'x-ms-sevsnpvm-launchmeasurement': MAA_MEAS, 'x-ms-sevsnpvm-hostdata': MAA_HOSTDATA, 'x-ms-sevsnpvm-is-debuggable': false,
    'x-ms-sevsnpvm-bootloader-svn': 10, 'x-ms-sevsnpvm-snpfw-svn': 27, 'x-ms-sevsnpvm-microcode-svn': 88, 'x-ms-sevsnpvm-tee-svn': 0,
    'x-ms-sevsnpvm-reportdata': hexOf(bindingBytes(binding)), 'x-ms-runtime': { 'user-data': hexOf(bindingBytes(binding)), keys: [] }, ...over,
  };
}
export const maaPayload = (now: number, claims: Record<string, unknown>, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  iss: MAA_ISS, iat: Math.floor(now / 1000) - 60, nbf: Math.floor(now / 1000) - 60, exp: Math.floor(now / 1000) + 3600, ...claims, ...over,
});

export async function buildMaaVectors(c: Collector): Promise<void> {
  // ── real Azure MAA evidence ────────────────────────────────────────────────
  const tdxTok = fxText('real-azure-maa', 'pcabound-tdxvm-token.jwt').trim();
  const unboundTok = fxText('real-azure-maa', 'tdxvm-token.jwt').trim();
  const snpTok = fxText('real-azure-maa', 'sevsnp-token.jwt').trim();
  const wusAll = JSON.parse(fxText('real-azure-maa', 'maa-signing-certs.json')) as { keys: Array<{ kid: string }> };
  const eusAll = JSON.parse(fxText('real-azure-maa', 'maa-signing-certs-eus.json')) as { keys: Array<{ kid: string }> };
  const kidOf = (t: string) => parseSeg(split(t)[0]).kid as string;
  const only = (all: { keys: Array<{ kid: string }> }, kid: string): JsonObject => ({ keys: all.keys.filter((k) => k.kid === kid) as unknown as JsonObject[] });
  const wus = only(wusAll, kidOf(tdxTok));
  const eus = only(eusAll, kidOf(snpTok));
  const tdxP = parseSeg(split(tdxTok)[1]);
  const snpP = parseSeg(split(snpTok)[1]);
  const TDX_NOW = ((tdxP['iat'] as number) + 3600) * 1000;
  const SNP_NOW = ((snpP['iat'] as number) + 3600) * 1000;
  const WUS = 'https://sharedwus.wus.attest.azure.net';
  const EUS = 'https://sharedeus.eus.attest.azure.net';
  const WUS_PIN = 'fe4fa28d5b2e89f088d484f260363a12bcab53d9a9e0d6725507336fc8b6a71e';
  const EUS_PIN = '97cda3af47e762fb8673d1664066082ad7a9e82120eb9523da1a39f6a84de3cc';
  const tdxMrtd = String(tdxP['tdx_mrtd']);
  const snpMeas = String(snpP['x-ms-sevsnpvm-launchmeasurement']);
  const tdxCfg = (over: JsonObject = {}, policy: JsonObject = {}): JsonObject => ({ trustedIssuers: [WUS], trustAnchors: { rootSpkiSha256: [WUS_PIN] }, policy: { tdxMrtds: [tdxMrtd], runtimeUserDataBinding: true, ...policy }, ...over });
  const snpCfg = (over: JsonObject = {}, policy: JsonObject = {}): JsonObject => ({ trustedIssuers: [EUS], trustAnchors: { rootSpkiSha256: [EUS_PIN] }, policy: { sevSnpMeasurements: [snpMeas], runtimeUserDataBinding: true, ...policy }, ...over });
  const rt = (id: string, intent: 'accept' | 'reject', description: string, o: { snp?: boolean; token?: string; jwks?: JsonObject | null; cfg?: JsonObject; policy?: JsonObject; now?: number; binding?: WireBinding; tags?: string[] } = {}) => {
    const snp = o.snp === true;
    const token = o.token ?? (snp ? snpTok : tdxTok);
    const jwks = o.jwks === undefined ? (snp ? eus : wus) : o.jwks;
    return c.add({
      id: `maa-real-${id}`, vendor: 'azure-maa', tags: ['real', snp ? 'sevsnpvm' : 'tdxvm', ...(o.tags ?? [])], intent, description,
      config: snp ? snpCfg(o.cfg, o.policy) : tdxCfg(o.cfg, o.policy), now: o.now ?? (snp ? SNP_NOW : TDX_NOW), binding: o.binding ?? REAL_BINDING, evidence: { token, ...(jwks ? { jwks } : {}) },
    });
  };
  await rt('tdx-positive', 'accept', 'Genuine MAA RS256 token over a genuine TDX quote, PCA binding through x-ms-runtime.user-data.');
  await rt('sevsnp-positive', 'accept', 'Genuine MAA token over a genuine SEV-SNP report (another instance, another signing key).', { snp: true });
  await rt('tdx-unbound-token', 'reject', "A token over a boot whose runtime data carries no PCA binding.", { token: unboundTok, cfg: {} , policy: { tdxMrtds: [String(parseSeg(split(unboundTok)[1])['tdx_mrtd'])] } });
  await rt('tdx-report-data-mode', 'reject', 'Direct report-data comparison cannot hold on Azure (report_data is a hash).', { policy: { runtimeUserDataBinding: false } });
  for (const [n, b] of relays(REAL_BINDING)) await rt(`tdx-relayed-${n}`, 'reject', `Another ${n} in the binding.`, { binding: b });
  for (const [n, b] of badBindings(REAL_BINDING)) await rt(`tdx-bad-binding-${n}`, 'reject', `Binding ${n}: not constructible.`, { binding: b });
  await rt('tdx-wrong-issuer', 'reject', 'Issuer not configured.', { cfg: { trustedIssuers: ['https://evil.example'] } });
  await rt('tdx-issuer-second-entry', 'accept', 'Any configured issuer may match.', { cfg: { trustedIssuers: ['https://evil.example', WUS] } });
  await rt('tdx-issuer-trailing-slash', 'reject', 'The issuer compares exactly.', { cfg: { trustedIssuers: [`${WUS}/`] } });
  await rt('tdx-wrong-pin', 'reject', 'Pin that matches no certificate of the chain.', { cfg: { trustAnchors: { rootSpkiSha256: ['00'.repeat(32)] } } });
  await rt('tdx-pin-uppercase', 'accept', 'SPKI pins compare case-insensitively.', { cfg: { trustAnchors: { rootSpkiSha256: [WUS_PIN.toUpperCase()] } } });
  await rt('tdx-pin-second-entry', 'accept', 'Any pin may match.', { cfg: { trustAnchors: { rootSpkiSha256: ['00'.repeat(32), WUS_PIN] } } });
  await rt('config-no-issuers', 'reject', 'Empty trustedIssuers refused at construction.', { cfg: { trustedIssuers: [] } });
  await rt('config-empty-issuer-string', 'reject', 'An empty issuer string refused at construction.', { cfg: { trustedIssuers: [''] } });
  await rt('config-no-anchors', 'reject', 'No trust anchor refused at construction.', { cfg: { trustAnchors: {} } });
  await rt('config-empty-anchor-lists', 'reject', 'Empty anchor lists refused at construction.', { cfg: { trustAnchors: { rootSpkiSha256: [], rootCertsPem: [] } } });
  await rt('config-no-measurement-lists', 'reject', 'No allowlist at all refused at construction.', { policy: { tdxMrtds: [] } });
  await rt('config-min-tcb-negative', 'reject', 'A negative SVN floor refused.', { snp: true, policy: { sevSnpMinTcb: { bootloader: -1 } } });
  await rt('config-min-tcb-unknown-field', 'reject', 'An unknown SVN floor field refused.', { snp: true, policy: { sevSnpMinTcb: { firmware: 1 } } });
  await rt('config-min-tcb-fractional', 'reject', 'A fractional SVN floor refused.', { snp: true, policy: { sevSnpMinTcb: { snp: 1.5 } } });
  await rt('tdx-mrtd-other', 'reject', 'MRTD not allowlisted.', { policy: { tdxMrtds: ['00'.repeat(48)] } });
  await rt('tdx-mrtd-uppercase', 'accept', 'MRTD allowlist is case-insensitive.', { policy: { tdxMrtds: [tdxMrtd.toUpperCase()] } });
  await rt('tdx-no-tdx-list', 'reject', 'A tdxvm token while the policy only lists SEV-SNP measurements.', { policy: { tdxMrtds: undefined as never, sevSnpMeasurements: ['aa'.repeat(48)] } });
  await rt('tdx-rtmr0-match', 'accept', 'RTMR0 allowlist with the claim.', { policy: { tdxRtmrs: [String(tdxP['tdx_rtmr0'])] } });
  await rt('tdx-rtmr0-other', 'reject', 'RTMR0 not allowlisted.', { policy: { tdxRtmrs: ['ee'.repeat(48)] } });
  await rt('tdx-tcb-status-only-out-of-date', 'reject', 'Only OutOfDate accepted: UpToDate refused.', { policy: { tdxAllowedTcbStatuses: ['OutOfDate'] } });
  await rt('tdx-tcb-status-uptodate', 'accept', 'Only UpToDate accepted.', { policy: { tdxAllowedTcbStatuses: ['UpToDate'] } });
  await rt('tdx-tcb-status-empty', 'reject', 'An empty accepted-status list accepts nothing.', { policy: { tdxAllowedTcbStatuses: [] } });
  await rt('tdx-identity-overrides', 'accept', 'identity_overrides replace measured fields.', { cfg: { identity_overrides: { model_id: 'm1', operator: 'acme' } } });
  // time
  const exp = tdxP['exp'] as number;
  const iat = tdxP['iat'] as number;
  await rt('tdx-clock-at-iat', 'accept', 'Clock exactly at nbf/iat.', { now: iat * 1000 });
  await rt('tdx-clock-before-nbf', 'reject', 'One second before nbf.', { now: (iat - 1) * 1000 });
  await rt('tdx-clock-at-exp-plus-999ms', 'accept', 'Whole-second comparison: 999 ms after exp is still second exp.', { now: exp * 1000 + 999 });
  await rt('tdx-clock-after-exp', 'reject', 'One second after exp.', { now: (exp + 1) * 1000 });
  await rt('tdx-skew-admits-expired', 'accept', 'A skew of 1000 ms admits a clock one second past exp.', { now: (exp + 1) * 1000, cfg: { clockSkewMs: 1000 } });
  await rt('tdx-skew-rounds-up-to-seconds', 'accept', 'A 1 ms skew counts as one whole second.', { now: (exp + 1) * 1000, cfg: { clockSkewMs: 1 } });
  await rt('tdx-skew-negative-is-zero', 'reject', 'A negative skew is treated as zero.', { now: (exp + 1) * 1000, cfg: { clockSkewMs: -5000 } });
  await rt('tdx-clock-cert-expired', 'reject', 'Clock past every signing-certificate window.', { now: Date.parse('2100-01-01T00:00:00Z') });
  await rt('tdx-clock-cert-not-yet-valid', 'reject', 'Clock before the signing certificate is valid.', { now: Date.parse('2015-01-01T00:00:00Z') });
  // token mutations
  const [h0, p0, s0] = split(tdxTok);
  const flipLast = (s: string) => `${s.slice(0, -2)}${s.at(-2) === 'A' ? 'B' : 'A'}${s.at(-1)}`;
  await rt('tdx-sig-flipped-first', 'reject', 'First signature character changed.', { token: `${h0}.${p0}.${s0[0] === 'A' ? 'B' : 'A'}${s0.slice(1)}` });
  await rt('tdx-sig-flipped-middle', 'reject', 'A middle signature character changed.', { token: `${h0}.${p0}.${flipLast(s0.slice(0, 200))}${s0.slice(200)}` });
  await rt('tdx-payload-tampered', 'reject', 'Payload claim edited after signing.', { token: editToken(tdxTok, { payload: (p) => ({ ...p, tdx_mrtd: '00'.repeat(48) }) }) });
  await rt('tdx-payload-status-edited', 'reject', 'attester_tcb_status edited.', { token: editToken(tdxTok, { payload: (p) => ({ ...p, attester_tcb_status: 'OutOfDate' }) }) });
  await rt('tdx-header-alg-none', 'reject', 'Header alg none.', { token: editToken(tdxTok, { header: (h) => ({ ...h, alg: 'none' }) }) });
  await rt('tdx-header-alg-hs256', 'reject', 'Header alg HS256.', { token: editToken(tdxTok, { header: (h) => ({ ...h, alg: 'HS256' }) }) });
  await rt('tdx-header-alg-es256-on-rsa-key', 'reject', 'ES256 header over an RSA signing key.', { token: editToken(tdxTok, { header: (h) => ({ ...h, alg: 'ES256' }) }) });
  await rt('tdx-header-kid-edited', 'reject', 'A kid that matches no JWKS key.', { token: editToken(tdxTok, { header: (h) => ({ ...h, kid: 'other' }) }) });
  await rt('tdx-header-no-kid-edited', 'reject', 'Header edited to drop the kid: the signature no longer matches.', { token: editToken(tdxTok, { header: (h) => { const { kid: _k, ...r } = h; return r; } }) });
  await rt('tdx-two-segments', 'reject', 'Only two segments.', { token: `${h0}.${p0}` });
  await rt('tdx-four-segments', 'reject', 'Four segments.', { token: `${tdxTok}.x` });
  await rt('tdx-empty-signature-segment', 'reject', 'Empty signature segment.', { token: `${h0}.${p0}.` });
  await rt('tdx-empty-payload-segment', 'reject', 'Empty payload segment.', { token: `${h0}..${s0}` });
  await rt('tdx-empty-header-segment', 'reject', 'Empty header segment.', { token: `.${p0}.${s0}` });
  await rt('tdx-token-empty', 'reject', 'Empty token string.', { token: '' });
  await rt('tdx-sig-stray-character', 'reject', 'A stray character in the signature segment.', { token: `${h0}.${p0}.${s0}!`, tags: ['strictness'] });
  await rt('tdx-sig-stray-character-middle', 'reject', 'A stray character inside the signature segment.', { token: `${h0}.${p0}.${s0.slice(0, 50)}*${s0.slice(50)}`, tags: ['strictness'] });
  await rt('tdx-sig-padding', 'reject', 'Base64 padding on the signature segment.', { token: `${h0}.${p0}.${s0}==`, tags: ['strictness'] });
  const lastIdx = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(s0.at(-1)!);
  const alias = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'[lastIdx ^ 1]!;
  await rt('tdx-sig-trailing-bits', 'reject', 'Non-zero trailing bits in the last signature character: another spelling of the same bytes.', { token: `${h0}.${p0}.${s0.slice(0, -1)}${alias}`, tags: ['strictness'] });
  await rt('tdx-sig-whitespace', 'reject', 'A newline inside the signature segment.', { token: `${h0}.${p0}.${s0.slice(0, 40)}\n${s0.slice(40)}`, tags: ['strictness'] });
  await rt('tdx-sig-standard-alphabet', 'reject', 'Standard-alphabet characters in the signature.', { token: `${h0}.${p0}.${s0.slice(0, 40)}+/${s0.slice(42)}`, tags: ['strictness'] });
  await rt('tdx-sig-impossible-length', 'reject', 'A signature segment whose length is 1 mod 4.', { token: `${h0}.${p0}.${s0.slice(0, -1)}`, tags: ['strictness'] });
  await rt('tdx-payload-stray-character', 'reject', 'A stray character in the payload segment.', { token: `${h0}.${p0}!.${s0}`, tags: ['strictness'] });
  await rt('tdx-payload-padding', 'reject', 'Padding on the payload segment.', { token: `${h0}.${p0}=.${s0}`, tags: ['strictness'] });
  await rt('tdx-header-stray-character', 'reject', 'A stray character in the header segment.', { token: `${h0}!.${p0}.${s0}`, tags: ['strictness'] });
  await rt('tdx-header-not-json', 'reject', 'Header segment that is not JSON.', { token: `${b64u('not json')}.${p0}.${s0}` });
  await rt('tdx-header-array', 'reject', 'Header JSON array.', { token: `${jsonSeg([1])}.${p0}.${s0}` });
  await rt('tdx-payload-array', 'reject', 'Payload JSON array.', { token: `${h0}.${jsonSeg([1])}.${s0}` });
  await rt('tdx-header-no-alg', 'reject', 'Header without alg.', { token: `${jsonSeg({ kid: 'x' })}.${p0}.${s0}` });
  // JWKS faults
  await rt('tdx-jwks-missing', 'reject', 'No JWKS and no header x5c.', { jwks: null });
  await rt('tdx-jwks-empty-keys', 'reject', 'A JWKS with no keys.', { jwks: { keys: [] } });
  await rt('tdx-jwks-other-kid', 'reject', 'JWKS keys that do not include the token kid.', { jwks: { keys: [{ ...(wus['keys'] as JsonObject[])[0]!, kid: 'other' }] } });
  await rt('tdx-jwks-key-without-x5c', 'reject', 'The matching JWKS key carries no x5c.', { jwks: { keys: [{ kid: kidOf(tdxTok), kty: 'RSA' }] } });
  await rt('tdx-jwks-empty-x5c', 'reject', 'The matching JWKS key has an empty x5c.', { jwks: { keys: [{ kid: kidOf(tdxTok), kty: 'RSA', x5c: [] }] } });
  await rt('tdx-jwks-x5c-empty-entry', 'reject', 'An empty x5c entry.', { jwks: { keys: [{ kid: kidOf(tdxTok), kty: 'RSA', x5c: [''] }] } });
  await rt('tdx-jwks-x5c-garbage', 'reject', 'An x5c entry that is not a certificate.', { jwks: { keys: [{ kid: kidOf(tdxTok), kty: 'RSA', x5c: [Buffer.from('not a certificate').toString('base64')] }] } });
  await rt('tdx-jwks-all-wus-keys', 'accept', 'The full published JWKS (several keys); the kid selects.', { jwks: wusAll as unknown as JsonObject });
  await rt('tdx-jwks-other-instance-keys', 'reject', "Another instance's JWKS: the kid is not there.", { jwks: eus });
  await rt('tdx-sevsnp-token-with-wus-pin', 'reject', "The EUS token against the WUS pin.", { snp: true, cfg: { trustAnchors: { rootSpkiSha256: [WUS_PIN] } } });
  // sevsnp policy
  await rt('sevsnp-measurement-other', 'reject', 'Launch measurement not allowlisted.', { snp: true, policy: { sevSnpMeasurements: ['00'.repeat(48)] } });
  await rt('sevsnp-measurement-uppercase', 'accept', 'Case-insensitive allowlist.', { snp: true, policy: { sevSnpMeasurements: [snpMeas.toUpperCase()] } });
  await rt('sevsnp-no-snp-list', 'reject', 'A sevsnpvm token while only TDX MRTDs are listed.', { snp: true, policy: { sevSnpMeasurements: undefined as never, tdxMrtds: [tdxMrtd] } });
  await rt('sevsnp-host-data-match', 'accept', 'Host-data allowlist with the claim.', { snp: true, policy: { sevSnpHostData: [String(snpP['x-ms-sevsnpvm-hostdata'])] } });
  await rt('sevsnp-host-data-other', 'reject', 'Host-data not allowlisted.', { snp: true, policy: { sevSnpHostData: ['ff'.repeat(32)] } });
  for (const [name, claim] of [['bootloader', 'x-ms-sevsnpvm-bootloader-svn'], ['snp', 'x-ms-sevsnpvm-snpfw-svn'], ['microcode', 'x-ms-sevsnpvm-microcode-svn'], ['tee', 'x-ms-sevsnpvm-tee-svn']] as const) {
    const v = snpP[claim] as number;
    await rt(`sevsnp-min-tcb-${name}-equal`, 'accept', `${name} SVN equal to its floor.`, { snp: true, policy: { sevSnpMinTcb: { [name]: v } } });
    await rt(`sevsnp-min-tcb-${name}-above`, 'reject', `${name} SVN below its floor.`, { snp: true, policy: { sevSnpMinTcb: { [name]: v + 1 } } });
  }
  await rt('sevsnp-min-tcb-all-equal', 'accept', 'All four floors at the claimed values; the SVNs surface in hostAsserted.', { snp: true, policy: { sevSnpMinTcb: { bootloader: 10, snp: 27, microcode: 88, tee: 0 } } });
  await rt('sevsnp-identity-overrides', 'accept', 'identity_overrides.', { snp: true, cfg: { identity_overrides: { model_id: 'm1' } } });
  await rt('sevsnp-relayed-nonce', 'reject', 'Another nonce.', { snp: true, binding: { ...REAL_BINDING, nonce: 'x' } });

  // ── synthetic tokens under a test MAA PKI ──────────────────────────────────
  const W = maaWorld();
  const ecPin = W.ec.leaf.key.spkiSha256;
  const rsaPin = W.rsaKey.spkiSha256;
  const rootPin = W.ec.root.key.spkiSha256;
  const intPin = W.ec.int.key.spkiSha256;
  const ecSigner: Signer = { kind: 'ec', key: W.ec.leafKey };
  const rsaSigner: Signer = { kind: 'rsa', key: W.rsaKey };
  const jwksEc = (...x5c: ForgedCert[]): JsonObject => ({ keys: [{ kid: 'kid-ec', kty: 'EC', x5c: W.x5c(...x5c) }] });
  const jwksRsa: JsonObject = { keys: [{ kid: 'kid-rsa', kty: 'RSA', x5c: W.x5c(W.rsaLeaf, W.ec.int, W.ec.root) }] };
  const baseCfg = (over: JsonObject = {}, policy: JsonObject = {}): JsonObject => ({
    trustedIssuers: [MAA_ISS], trustAnchors: { rootSpkiSha256: [rootPin] }, policy: { tdxMrtds: [MAA_MRTD], sevSnpMeasurements: [MAA_MEAS], runtimeUserDataBinding: true, ...policy }, ...over,
  });
  const hdr = (alg: string, kid: string | undefined, extra: Record<string, unknown> = {}) => ({ alg, typ: 'JWT', ...(kid ? { kid } : {}), ...extra });
  const syn = (id: string, intent: 'accept' | 'reject', description: string, token: string, jwks: JsonObject | null, o: { cfg?: JsonObject; policy?: JsonObject; now?: number; binding?: WireBinding; tags?: string[] } = {}) =>
    c.add({ id: `maa-syn-${id}`, vendor: 'azure-maa', tags: ['synthetic', ...(o.tags ?? [])], intent, description, config: baseCfg(o.cfg, o.policy), now: o.now ?? MAA_NOW, binding: o.binding ?? SYN_BINDING, evidence: { token, ...(jwks ? { jwks } : {}) } });
  const tdxTokEc = (claims: Record<string, unknown> = {}, over: Record<string, unknown> = {}, signer: Signer = ecSigner, kid = 'kid-ec', alg = 'ES256') => mint(hdr(alg, kid), maaPayload(MAA_NOW, maaTdxClaims(SYN_BINDING, claims), over), signer);
  const snpTokEc = (claims: Record<string, unknown> = {}, over: Record<string, unknown> = {}) => mint(hdr('ES256', 'kid-ec'), maaPayload(MAA_NOW, maaSnpClaims(SYN_BINDING, claims), over), ecSigner);
  const J = jwksEc(W.ec.leaf, W.ec.int, W.ec.root);
  const T = tdxTokEc();

  await syn('es256-chain-root-pin', 'accept', 'ES256 token, leaf/intermediate/root x5c, anchored by the root SPKI pin.', T, J);
  await syn('es256-chain-intermediate-pin', 'accept', 'Anchored by an intermediate pin: links below it must verify.', T, J, { cfg: { trustAnchors: { rootSpkiSha256: [intPin] } } });
  await syn('es256-leaf-only-pin', 'accept', 'Anchored by the leaf pin alone (a self-contained signing cert).', T, jwksEc(W.ec.leaf), { cfg: { trustAnchors: { rootSpkiSha256: [ecPin] } } });
  await syn('es256-external-root-cert', 'accept', 'x5c [leaf, intermediate] whose top is signed by a configured root certificate.', T, jwksEc(W.ec.leaf, W.ec.int), { cfg: { trustAnchors: { rootCertsPem: [W.ec.root.pem] } } });
  await syn('es256-external-root-cert-wrong', 'reject', 'The configured root certificate did not sign the chain top.', T, jwksEc(W.ec.leaf, W.ec.int), { cfg: { trustAnchors: { rootCertsPem: [W.rogue.pem] } } });
  await syn('es256-root-cert-also-pins', 'accept', 'A root certificate anchors by its own SPKI as well.', T, J, { cfg: { trustAnchors: { rootCertsPem: [W.ec.root.pem] } } });
  await syn('es256-chain-broken-link', 'reject', 'A link not signed by the certificate above it.', T, jwksEc(W.ec.leaf, W.rogue, W.ec.root), { cfg: { trustAnchors: { rootSpkiSha256: [rootPin] } } });
  await syn('es256-no-anchor-in-chain', 'reject', 'Chain whose certificates match no pin.', T, jwksEc(W.ec.leaf, W.ec.int, W.ec.root), { cfg: { trustAnchors: { rootSpkiSha256: [W.rogue.key.spkiSha256] } } });
  await syn('es256-rogue-signer', 'reject', 'Token signed by a key outside the anchor.', tdxTokEc({}, {}, { kind: 'ec', key: W.rogueKey }, 'kid-ec'), J);
  await syn('es256-header-x5c-no-jwks', 'accept', 'No JWKS: the header x5c is used.', mint(hdr('ES256', undefined, { x5c: W.x5c(W.ec.leaf, W.ec.int, W.ec.root) }), maaPayload(MAA_NOW, maaTdxClaims(SYN_BINDING)), ecSigner), null);
  await syn('es256-no-jwks-no-header-x5c', 'reject', 'No JWKS, no header x5c.', T, null);
  await syn('es256-no-kid-single-key', 'accept', 'No kid and exactly one JWKS key.', mint(hdr('ES256', undefined), maaPayload(MAA_NOW, maaTdxClaims(SYN_BINDING)), ecSigner), J);
  await syn('es256-no-kid-ambiguous', 'reject', 'No kid and two JWKS keys.', mint(hdr('ES256', undefined), maaPayload(MAA_NOW, maaTdxClaims(SYN_BINDING)), ecSigner), { keys: [(J['keys'] as JsonObject[])[0]!, { kid: 'k2', kty: 'EC', x5c: W.x5c(W.rogue) }] });
  await syn('es256-kid-not-found', 'reject', 'kid absent from the JWKS.', tdxTokEc({}, {}, ecSigner, 'nope'), J);
  await syn('es256-jwks-key-no-x5c', 'reject', 'JWKS key without x5c.', T, { keys: [{ kid: 'kid-ec', kty: 'EC' }] });
  await syn('es256-x5c-empty', 'reject', 'Empty x5c array.', T, { keys: [{ kid: 'kid-ec', kty: 'EC', x5c: [] }] });
  await syn('es256-x5c-empty-entry', 'reject', 'Empty x5c entry.', T, { keys: [{ kid: 'kid-ec', kty: 'EC', x5c: [''] }] });
  await syn('es256-x5c-garbage-entry', 'reject', 'x5c entry that is not a certificate.', T, { keys: [{ kid: 'kid-ec', kty: 'EC', x5c: [Buffer.from('garbage').toString('base64')] }] });
  const expiredLeaf = forgeCert({ subject: dnOf('maa-leaf'), issuer: dnOf('maa-int'), subjectKey: W.ec.leafKey, signer: forgeKey('maa/int', 'P-256'), serial: 30n, notBefore: new Date('2020-01-01Z'), notAfter: new Date('2022-01-01Z') });
  await syn('cert-expired-leaf', 'reject', 'Signing certificate expired.', T, jwksEc(expiredLeaf, W.ec.int, W.ec.root));
  const futureLeaf = forgeCert({ subject: dnOf('maa-leaf'), issuer: dnOf('maa-int'), subjectKey: W.ec.leafKey, signer: forgeKey('maa/int', 'P-256'), serial: 31n, notBefore: new Date('2040-01-01Z'), notAfter: new Date('2041-01-01Z') });
  await syn('cert-not-yet-valid-leaf', 'reject', 'Signing certificate not yet valid.', T, jwksEc(futureLeaf, W.ec.int, W.ec.root));
  const edgeLeaf = forgeCert({ subject: dnOf('maa-leaf'), issuer: dnOf('maa-int'), subjectKey: W.ec.leafKey, signer: forgeKey('maa/int', 'P-256'), serial: 32n, notBefore: new Date(MAA_NOW), notAfter: new Date(MAA_NOW + 1e6) });
  await syn('cert-at-not-before', 'accept', 'Clock exactly at the signing certificate notBefore.', T, jwksEc(edgeLeaf, W.ec.int, W.ec.root));
  await syn('cert-1s-before-not-before', 'reject', 'One second before the signing certificate notBefore.', T, jwksEc(edgeLeaf, W.ec.int, W.ec.root), { now: MAA_NOW - 1000 });
  await syn('cert-skew-admits-early', 'accept', 'A 1000 ms skew admits a certificate starting one second ahead.', T, jwksEc(edgeLeaf, W.ec.int, W.ec.root), { now: MAA_NOW - 1000, cfg: { clockSkewMs: 1000 } });
  // RS256
  const rsaTok = (claims: Record<string, unknown> = {}) => mint(hdr('RS256', 'kid-rsa'), maaPayload(MAA_NOW, maaTdxClaims(SYN_BINDING, claims)), rsaSigner);
  await syn('rs256-positive', 'accept', 'RS256 token with an RSA signing certificate.', rsaTok(), jwksRsa);
  await syn('rs256-rsa-pin', 'accept', 'Anchored by the RSA leaf pin.', rsaTok(), jwksRsa, { cfg: { trustAnchors: { rootSpkiSha256: [rsaPin] } } });
  await syn('rs256-flipped-signature', 'reject', 'One flipped signature byte.', ((): string => { const [a, b, sg] = split(rsaTok()); return `${a}.${b}.${sg.slice(0, 10)}${sg[10] === 'A' ? 'B' : 'A'}${sg.slice(11)}`; })(), jwksRsa);
  await syn('rs256-header-over-ec-key', 'reject', 'RS256 header with an EC signing key.', mint(hdr('RS256', 'kid-ec'), maaPayload(MAA_NOW, maaTdxClaims(SYN_BINDING)), ecSigner), J);
  await syn('es256-header-over-rsa-key', 'reject', 'ES256 header with an RSA signing key.', mint(hdr('ES256', 'kid-rsa'), maaPayload(MAA_NOW, maaTdxClaims(SYN_BINDING)), rsaSigner), jwksRsa);
  await syn('es256-signature-63-bytes', 'reject', 'ES256 signature of 63 bytes.', ((): string => { const [a, b, sg] = split(T); return `${a}.${b}.${b64u(Buffer.from(sg, 'base64url').subarray(0, 63))}`; })(), J);
  await syn('es256-signature-flipped', 'reject', 'ES256 signature edited.', ((): string => { const [a, b, sg] = split(T); const raw = Buffer.from(sg, 'base64url'); raw[5] ^= 1; return `${a}.${b}.${b64u(raw)}`; })(), J);
  await syn('alg-none', 'reject', 'alg none.', mint(hdr('none', 'kid-ec'), maaPayload(MAA_NOW, maaTdxClaims(SYN_BINDING)), ecSigner), J);
  await syn('alg-ps256', 'reject', 'alg PS256.', mint(hdr('PS256', 'kid-ec'), maaPayload(MAA_NOW, maaTdxClaims(SYN_BINDING)), ecSigner), J);
  await syn('alg-lowercase-es256', 'reject', 'alg is case-sensitive.', mint(hdr('es256', 'kid-ec'), maaPayload(MAA_NOW, maaTdxClaims(SYN_BINDING)), ecSigner), J);
  // standard claims
  await syn('iss-missing', 'reject', 'No iss claim.', tdxTokEc({}, { iss: undefined }), J);
  await syn('iss-other', 'reject', 'iss not configured.', tdxTokEc({}, { iss: 'https://other.example' }), J);
  await syn('iss-not-string', 'reject', 'iss that is not a string.', tdxTokEc({}, { iss: 5 }), J);
  await syn('exp-missing', 'reject', 'No exp claim.', tdxTokEc({}, { exp: undefined }), J);
  await syn('exp-string', 'reject', 'exp as a string.', tdxTokEc({}, { exp: String(Math.floor(MAA_NOW / 1000) + 3600) }), J);
  await syn('exp-passed', 'reject', 'exp one second in the past.', tdxTokEc({}, { exp: Math.floor(MAA_NOW / 1000) - 1 }), J);
  await syn('exp-equals-now', 'accept', 'exp equal to the current second is still valid.', tdxTokEc({}, { exp: Math.floor(MAA_NOW / 1000) }), J);
  await syn('exp-skew', 'accept', 'A 1000 ms skew admits exp one second past.', tdxTokEc({}, { exp: Math.floor(MAA_NOW / 1000) - 1 }), J, { cfg: { clockSkewMs: 1000 } });
  await syn('nbf-future', 'reject', 'nbf one second ahead.', tdxTokEc({}, { nbf: Math.floor(MAA_NOW / 1000) + 1 }), J);
  await syn('nbf-future-skew', 'accept', 'nbf one second ahead with a 1000 ms skew.', tdxTokEc({}, { nbf: Math.floor(MAA_NOW / 1000) + 1 }), J, { cfg: { clockSkewMs: 1000 } });
  await syn('nbf-absent', 'accept', 'nbf is optional.', tdxTokEc({}, { nbf: undefined }), J);
  await syn('iat-future', 'reject', 'iat one second ahead.', tdxTokEc({}, { iat: Math.floor(MAA_NOW / 1000) + 1, nbf: undefined }), J);
  await syn('iat-absent', 'accept', 'iat is optional.', tdxTokEc({}, { iat: undefined }), J);
  // isolation type + claim placement
  await syn('type-missing', 'reject', 'No x-ms-attestation-type.', tdxTokEc({ 'x-ms-attestation-type': undefined }), J);
  await syn('type-unknown', 'reject', 'Unknown isolation type.', tdxTokEc({ 'x-ms-attestation-type': 'vbs' }), J);
  await syn('type-in-isolation-tee-subtree', 'accept', 'Claims inside the x-ms-isolation-tee object.', mint(hdr('ES256', 'kid-ec'), maaPayload(MAA_NOW, { 'x-ms-isolation-tee': maaTdxClaims(SYN_BINDING), 'x-ms-runtime': { 'user-data': hexOf(bindingBytes(SYN_BINDING)) } }), ecSigner), J);
  await syn('type-top-level-with-empty-subtree', 'reject', 'An empty isolation-tee object hides the top-level measurement.', mint(hdr('ES256', 'kid-ec'), maaPayload(MAA_NOW, { 'x-ms-attestation-type': 'tdxvm', 'x-ms-isolation-tee': {}, tdx_mrtd: MAA_MRTD, 'x-ms-runtime': { 'user-data': hexOf(bindingBytes(SYN_BINDING)) } }), ecSigner), J);
  await syn('type-only-in-payload-with-subtree', 'reject', 'Type at the top level but the measurement inside a subtree that lacks the type is read from the subtree.', mint(hdr('ES256', 'kid-ec'), maaPayload(MAA_NOW, { 'x-ms-attestation-type': 'tdxvm', 'x-ms-isolation-tee': { tdx_mrtd: MAA_MRTD }, 'x-ms-runtime': { 'user-data': hexOf(bindingBytes(SYN_BINDING)) } }), ecSigner), J);
  // runtime user-data binding
  for (const [n, b] of relays(SYN_BINDING)) await syn(`rt-relayed-${n}`, 'reject', `Runtime user-data bound to another ${n}.`, T, J, { binding: b });
  for (const [n, b] of badBindings(SYN_BINDING)) await syn(`rt-bad-binding-${n}`, 'reject', `Binding ${n}: not constructible.`, T, J, { binding: b });
  const bytes = bindingBytes(SYN_BINDING);
  const enc: Array<[string, string, 'accept' | 'reject']> = [
    ['hex', hexOf(bytes), 'accept'], ['hex-upper', hexOf(bytes).toUpperCase(), 'accept'], ['hex-0x', `0x${hexOf(bytes)}`, 'accept'], ['hex-0X-upper', `0X${hexOf(bytes).toUpperCase()}`, 'accept'],
    ['hex-padded-spaces', `  ${hexOf(bytes)}  `, 'accept'], ['base64', Buffer.from(bytes).toString('base64'), 'accept'], ['base64url', Buffer.from(bytes).toString('base64url'), 'accept'],
    ['hex-truncated', hexOf(bytes).slice(0, 126), 'reject'], ['hex-other', '00'.repeat(64), 'reject'], ['empty', '', 'reject'],
  ];
  for (const [n, v, intent] of enc) await syn(`rt-user-data-${n}`, intent, `x-ms-runtime.user-data spelled as ${n}.`, tdxTokEc({ 'x-ms-runtime': { 'user-data': v } }), J);
  await syn('rt-user-data-number', 'reject', 'Numeric user-data.', tdxTokEc({ 'x-ms-runtime': { 'user-data': 5 } }), J);
  await syn('rt-no-runtime-claim', 'reject', 'No x-ms-runtime claim.', tdxTokEc({ 'x-ms-runtime': undefined }), J);
  await syn('rt-runtime-not-object', 'reject', 'x-ms-runtime that is not an object.', tdxTokEc({ 'x-ms-runtime': 'x' }), J);
  await syn('rt-runtime-array', 'reject', 'x-ms-runtime that is an array.', tdxTokEc({ 'x-ms-runtime': [] }), J);
  // direct report-data claim binding
  const direct = (claims: Record<string, unknown>, policy: JsonObject = {}, intent: 'accept' | 'reject' = 'accept', id = '', desc = '') =>
    syn(`rd-${id}`, intent, desc, tdxTokEc({ 'x-ms-runtime': undefined, ...claims }), J, { policy: { runtimeUserDataBinding: false, ...policy } });
  await direct({}, {}, 'accept', 'hex', 'Direct report-data claim equal to the binding (hex).');
  await direct({ tdx_report_data: hexOf(bytes).toUpperCase() }, {}, 'accept', 'hex-upper', 'Upper-case hex.');
  await direct({ tdx_report_data: Buffer.from(bytes).toString('base64') }, {}, 'accept', 'base64', 'Standard base64.');
  await direct({ tdx_report_data: undefined, 'x-ms-tdx-report-data': hexOf(bytes) }, {}, 'accept', 'alt-key-hyphen', 'Alternative claim key x-ms-tdx-report-data.');
  await direct({ tdx_report_data: undefined, 'x-ms-tdx-reportdata': hexOf(bytes) }, {}, 'accept', 'alt-key-compact', 'Alternative claim key x-ms-tdx-reportdata.');
  await direct({ tdx_report_data: undefined }, {}, 'reject', 'missing', 'No report-data claim.');
  await direct({ tdx_report_data: '' }, {}, 'reject', 'empty', 'Empty report-data claim.');
  await direct({ tdx_report_data: '00'.repeat(64) }, {}, 'reject', 'mismatch', 'Report-data claim not the binding.');
  await direct({ tdx_report_data: '!!!' }, {}, 'reject', 'undecodable', 'Report-data claim that decodes to nothing.');
  await direct({ tdx_report_data: hexOf(createHash('sha256').update(bytes).digest()) }, { reportDataHash: 'sha256' }, 'accept', 'sha256', "reportDataHash 'sha256' compares H(binding).");
  await direct({ tdx_report_data: hexOf(sha512(bytes)) }, { reportDataHash: 'sha512' }, 'accept', 'sha512', "reportDataHash 'sha512'.");
  await direct({ tdx_report_data: hexOf(bytes) }, { reportDataHash: 'sha256' }, 'reject', 'sha256-but-raw', "sha256 mode refuses the raw binding.");
  await direct({ tdx_report_data: hexOf(bytes) }, { reportDataHash: 'none' }, 'accept', 'hash-none', "reportDataHash 'none'.");
  await syn('rd-snp-claim', 'accept', 'SEV-SNP direct report-data claim.', mint(hdr('ES256', 'kid-ec'), maaPayload(MAA_NOW, maaSnpClaims(SYN_BINDING, { 'x-ms-runtime': undefined })), ecSigner), J, { policy: { runtimeUserDataBinding: false } });
  await syn('rd-snp-claim-missing', 'reject', 'SEV-SNP token without the report-data claim.', mint(hdr('ES256', 'kid-ec'), maaPayload(MAA_NOW, maaSnpClaims(SYN_BINDING, { 'x-ms-runtime': undefined, 'x-ms-sevsnpvm-reportdata': undefined })), ecSigner), J, { policy: { runtimeUserDataBinding: false } });
  // tdx policy
  await syn('tdx-mrtd-missing-claim', 'reject', 'No MRTD claim.', tdxTokEc({ tdx_mrtd: undefined }), J);
  await syn('tdx-mrtd-legacy-key', 'accept', 'Legacy x-ms-tdx-mrtd claim key.', tdxTokEc({ tdx_mrtd: undefined, 'x-ms-tdx-mrtd': MAA_MRTD }), J);
  await syn('tdx-mrtd-empty-claim', 'reject', 'Empty MRTD claim falls through to nothing.', tdxTokEc({ tdx_mrtd: '' }), J);
  await syn('tdx-mrtd-mismatch', 'reject', 'MRTD not allowlisted.', tdxTokEc({ tdx_mrtd: '11'.repeat(48) }), J);
  await syn('tdx-mrtd-uppercase-claim', 'accept', 'Upper-case MRTD claim.', tdxTokEc({ tdx_mrtd: MAA_MRTD.toUpperCase().replace(/AB/g, 'AB') }), J);
  await syn('tdx-debug-claim', 'reject', 'tdx_td_attributes_debug true.', tdxTokEc({ tdx_td_attributes_debug: true }), J);
  await syn('tdx-debug-claim-allowed', 'accept', 'allowDebug accepts it.', tdxTokEc({ tdx_td_attributes_debug: true }), J, { policy: { allowDebug: true } });
  await syn('tdx-dbgstat-enabled', 'reject', 'dbgstat enabled.', tdxTokEc({ dbgstat: 'enabled' }), J);
  await syn('tdx-dbgstat-absent', 'accept', 'dbgstat absent is not a debug signal.', tdxTokEc({ dbgstat: undefined }), J);
  await syn('tdx-debug-string-false', 'accept', 'A string "false" is not boolean true.', tdxTokEc({ tdx_td_attributes_debug: 'false' }), J);
  await syn('tdx-tcb-status-absent', 'accept', 'A token without attester_tcb_status is not gated on it.', tdxTokEc({ attester_tcb_status: undefined }), J);
  await syn('tdx-tcb-status-out-of-date', 'reject', 'OutOfDate against the default set.', tdxTokEc({ attester_tcb_status: 'OutOfDate' }), J);
  await syn('tdx-tcb-status-sw-hardening', 'accept', 'SWHardeningNeeded is in the default set.', tdxTokEc({ attester_tcb_status: 'SWHardeningNeeded' }), J);
  await syn('tdx-tcb-status-listed', 'accept', 'OutOfDate when the policy lists it.', tdxTokEc({ attester_tcb_status: 'OutOfDate' }), J, { policy: { tdxAllowedTcbStatuses: ['OutOfDate'] } });
  await syn('tdx-rtmr0-missing-claim', 'reject', 'RTMR0 allowlist but no claim.', tdxTokEc({ tdx_rtmr0: undefined }), J, { policy: { tdxRtmrs: [MAA_RTMR0] } });
  await syn('tdx-rtmr0-match', 'accept', 'RTMR0 allowlisted.', T, J, { policy: { tdxRtmrs: [MAA_RTMR0.toUpperCase()] } });
  await syn('tdx-rtmr0-legacy-key', 'accept', 'Legacy RTMR0 claim key.', tdxTokEc({ tdx_rtmr0: undefined, 'x-ms-tdx-rtmr0': MAA_RTMR0 }), J, { policy: { tdxRtmrs: [MAA_RTMR0] } });
  await syn('tdx-rtmrs-empty-not-gated', 'accept', 'An empty RTMR list does not gate.', T, J, { policy: { tdxRtmrs: [] } });
  await syn('tdx-no-allowlist-for-type', 'reject', 'A tdxvm token while only SEV-SNP is listed.', T, J, { policy: { tdxMrtds: undefined as never } });
  // snp policy
  await syn('snp-positive', 'accept', 'A synthetic sevsnpvm token.', snpTokEc(), J);
  await syn('snp-measurement-missing', 'reject', 'No launch-measurement claim.', snpTokEc({ 'x-ms-sevsnpvm-launchmeasurement': undefined }), J);
  await syn('snp-measurement-mismatch', 'reject', 'Measurement not allowlisted.', snpTokEc({ 'x-ms-sevsnpvm-launchmeasurement': '11'.repeat(48) }), J);
  await syn('snp-debuggable', 'reject', 'Debuggable guest.', snpTokEc({ 'x-ms-sevsnpvm-is-debuggable': true }), J);
  await syn('snp-debuggable-allowed', 'accept', 'allowDebug.', snpTokEc({ 'x-ms-sevsnpvm-is-debuggable': true }), J, { policy: { allowDebug: true } });
  await syn('snp-host-data-missing', 'reject', 'Host-data allowlist but no claim.', snpTokEc({ 'x-ms-sevsnpvm-hostdata': undefined }), J, { policy: { sevSnpHostData: [MAA_HOSTDATA] } });
  await syn('snp-host-data-uppercase', 'accept', 'Host-data compares case-insensitively.', snpTokEc(), J, { policy: { sevSnpHostData: [MAA_HOSTDATA.toUpperCase()] } });
  await syn('snp-min-tcb-claim-missing', 'reject', 'A floor with the claim absent.', snpTokEc({ 'x-ms-sevsnpvm-snpfw-svn': undefined }), J, { policy: { sevSnpMinTcb: { snp: 1 } } });
  await syn('snp-min-tcb-claim-string', 'reject', 'A floor with a string claim.', snpTokEc({ 'x-ms-sevsnpvm-snpfw-svn': '27' }), J, { policy: { sevSnpMinTcb: { snp: 1 } } });
  await syn('snp-min-tcb-claim-negative', 'reject', 'A floor with a negative claim.', snpTokEc({ 'x-ms-sevsnpvm-snpfw-svn': -1 }), J, { policy: { sevSnpMinTcb: { snp: 0 } } });
  await syn('snp-min-tcb-claim-float', 'reject', 'A floor with a fractional claim.', snpTokEc({ 'x-ms-sevsnpvm-snpfw-svn': 27.5 }), J, { policy: { sevSnpMinTcb: { snp: 1 } } });
  await syn('snp-min-tcb-zero-floor-ok', 'accept', 'Floor 0 against claim 0 (tee).', snpTokEc(), J, { policy: { sevSnpMinTcb: { tee: 0 } } });
  await syn('snp-svn-surface-without-floor', 'accept', 'SVNs surface in hostAsserted even with no floor.', snpTokEc(), J);
  await syn('snp-bad-svn-not-surfaced', 'accept', 'A non-integer SVN claim is not surfaced and, with no floor, not gated.', snpTokEc({ 'x-ms-sevsnpvm-bootloader-svn': 'x' }), J);
  await syn('snp-identity-overrides', 'accept', 'identity_overrides.', snpTokEc(), J, { cfg: { identity_overrides: { operator: 'op', model_id: 'm' } } });
  await syn('snp-in-subtree', 'accept', 'sevsnpvm claims inside x-ms-isolation-tee.', mint(hdr('ES256', 'kid-ec'), maaPayload(MAA_NOW, { 'x-ms-isolation-tee': maaSnpClaims(SYN_BINDING), 'x-ms-runtime': { 'user-data': hexOf(bytes) } }), ecSigner), J);
}
