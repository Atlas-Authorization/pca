// NVIDIA GPU (SPDM) rows of the attestation-evidence conformance vectors (TEST/TOOLING ONLY).
import { createHash } from 'node:crypto';
import { b64, type JsonObject, type WireBinding } from './attestation-wire';
import { Collector, SYN_BINDING, append, badBindings, bindingBytes, cut, flip, fxBytes, fxText, hexOf, relays } from './attestation-vectors-common';
import { forgeNvidiaScenario, forgeNvidiaCrl, forgeNvidiaDevicePki, goldenDigest, type ForgeScenarioOptions, type ForgedNvidiaScenario } from './forge-spdm';

export const NV_NOW = Date.parse('2026-10-20T00:00:00Z');
const challengeOf = (b: WireBinding): Uint8Array => new Uint8Array(createHash('sha256').update(bindingBytes(b)).digest());

export interface NvSyn {
  s: ForgedNvidiaScenario;
  evidence: JsonObject;
  /** Pinned SPDM blocks (index -> digest hex) for the base, collateral-free configuration. */
  measurements: Record<string, string>;
}
export const nvidiaCollateralWire = (s: ForgedNvidiaScenario, o: { crls?: Uint8Array[]; ocsp?: Uint8Array[]; driverRimXml?: string; vbiosRimXml?: string } = {}): JsonObject => ({
  driverRimXml: o.driverRimXml ?? s.driverRimXml, vbiosRimXml: o.vbiosRimXml ?? s.vbiosRimXml, crls: (o.crls ?? s.crls).map(b64), ocsp: (o.ocsp ?? s.ocsp).map(b64),
});
export function nvSyn(o: ForgeScenarioOptions = {}, binding: WireBinding = SYN_BINDING, withCollateral = true): NvSyn {
  const s = forgeNvidiaScenario({ challenge: challengeOf(binding), now: new Date(NV_NOW), ...o });
  const evidence: JsonObject = { evidence: b64(s.evidence.evidence), certChainPem: s.evidence.certChainPem, ...(withCollateral ? { collateral: nvidiaCollateralWire(s) } : {}) };
  return { s, evidence, measurements: { '1': hexOf(goldenDigest(1)), '2': hexOf(goldenDigest(2)) } };
}
export const nvConfig = (n: NvSyn, o: { collateral?: JsonObject | false; policy?: JsonObject; over?: JsonObject } = {}): JsonObject => ({
  rootSpkiSha256: [n.s.deviceRootSpkiSha256],
  policy: { measurements: o.collateral ? {} : n.measurements, ...(o.policy ?? {}) },
  ...(o.collateral ? { collateral: { rimRootSpkiSha256: [n.s.rimRootSpkiSha256], requireCrlIssuers: ['NVIDIA GH100 Identity', 'NVIDIA Device Identity CA'], ...o.collateral } } : {}),
  ...(o.over ?? {}),
});

export async function buildNvidiaVectors(c: Collector): Promise<void> {
  // ── real H100 NVL ──────────────────────────────────────────────────────────
  const dir = ['real-nvidia-cc', 'own-h100'];
  const REAL_BINDING: WireBinding = { holderPub: 'pca-realsilicon-nvidia-h100-holder', grantRef: 'grant_pca_nvidia_gpucc_realsilicon', epoch: 1, nonce: 'srv-nonce-nv-7c1e9f2a4b8d0536' };
  const rep = fxBytes(...dir, 'h100-gpu-attestation-report.bin');
  const chain = fxText(...dir, 'h100-device-cert-chain.pem');
  const drv = fxText(...dir, 'driver-rim.xml');
  const vb = fxText(...dir, 'vbios-rim.xml');
  const crls = [fxBytes('real-nvidia-cc', 'collateral', 'l2-gh100.crl'), fxBytes('real-nvidia-cc', 'collateral', 'l1-root.crl')];
  const REAL_NOW = 1791504000000;
  const rootPin = 'a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4';
  const rimPin = 'dec1dc316477aa851eebdf51327ae9f864bc8d89254657ed1e7eb9168af1e1a3';
  const realCol = (o: Partial<{ drv: string; vb: string; crls: Uint8Array[] }> = {}): JsonObject => ({ driverRimXml: o.drv ?? drv, vbiosRimXml: o.vb ?? vb, crls: (o.crls ?? crls).map(b64) });
  const realCfg = (collateral: JsonObject = {}, over: JsonObject = {}, policy: JsonObject = {}): JsonObject => ({
    rootSpkiSha256: [rootPin], policy: { measurements: {}, leafSubjectIncludes: 'GH100', ...policy }, collateral: { rimRootSpkiSha256: [rimPin], requireCrlIssuers: ['NVIDIA GH100 Identity', 'NVIDIA Device Identity CA'], ...collateral }, ...over,
  });
  const real = (id: string, intent: 'accept' | 'reject', description: string, o: { cfg?: JsonObject; ev?: JsonObject | null; now?: number; binding?: WireBinding; tags?: string[] } = {}) =>
    c.add({
      id: `nv-real-${id}`, vendor: 'nvidia-gpu-spdm', tags: ['real', 'h100', 'collateral:rim', 'collateral:crl', ...(o.tags ?? [])], intent, description, config: o.cfg ?? realCfg(), now: o.now ?? REAL_NOW, binding: o.binding ?? REAL_BINDING,
      evidence: o.ev === undefined ? { evidence: b64(rep), certChainPem: chain, collateral: realCol() } : o.ev,
    });
  const ev = (o: { rep?: Uint8Array; chain?: string; col?: JsonObject | null } = {}): JsonObject => ({ evidence: b64(o.rep ?? rep), certChainPem: o.chain ?? chain, ...(o.col === null ? {} : { collateral: o.col ?? realCol() }) });
  await real('positive', 'accept', 'Genuine H100 NVL report and device chain with real RIMs and CRLs.');
  await real('wrong-root-pin', 'reject', 'Another device root pin.', { cfg: realCfg({}, { rootSpkiSha256: ['00'.repeat(32)] }) });
  await real('wrong-rim-root-pin', 'reject', 'Another CoRIM root pin.', { cfg: realCfg({ rimRootSpkiSha256: ['00'.repeat(32)] }) });
  await real('leaf-subject-mismatch', 'reject', 'Leaf subject substring absent.', { cfg: realCfg({}, {}, { leafSubjectIncludes: 'GB100' }) });
  await real('collateral-missing', 'reject', 'Hook installed, no collateral supplied.', { ev: ev({ col: null }) });
  for (const [n, b] of relays(REAL_BINDING)) await real(`relayed-${n}`, 'reject', `Another ${n} in the binding.`, { binding: b });
  for (const [n, b] of badBindings(REAL_BINDING)) await real(`bad-binding-${n}`, 'reject', `Binding ${n}: not constructible.`, { binding: b });
  await real('report-flip-signed', 'reject', 'A bit flipped in the signed transcript.', { ev: ev({ rep: flip(rep, 100) }) });
  await real('report-flip-nonce', 'reject', 'A bit flipped in the request nonce.', { ev: ev({ rep: flip(rep, 10) }) });
  await real('report-flip-signature', 'reject', 'A bit flipped in the signature.', { ev: ev({ rep: flip(rep, rep.length - 3) }) });
  await real('report-truncated', 'reject', 'Report truncated.', { ev: ev({ rep: cut(rep, rep.length - 10) }) });
  await real('report-appended', 'reject', 'A byte appended after the signature.', { ev: ev({ rep: append(rep, 0) }) });
  await real('report-empty', 'reject', 'Empty report.', { ev: ev({ rep: new Uint8Array(0) }) });
  await real('chain-flip', 'reject', 'A character of the device chain changed.', { ev: ev({ chain: chain.replace(/(-----BEGIN CERTIFICATE-----\n.{20})(.)/, (_m, a: string, b: string) => `${a}${b === 'A' ? 'B' : 'A'}`) }) });
  await real('chain-leaf-only', 'reject', 'Only the leaf certificate.', { ev: ev({ chain: chain.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\n?/)![0] }) });
  await real('chain-empty', 'reject', 'Empty chain.', { ev: ev({ chain: '' }) });
  await real('clock-far-future', 'reject', 'Clock beyond the CRL window.', { now: Date.parse('2100-01-01T00:00:00Z') });
  await real('crl-missing', 'reject', 'Required CRLs absent.', { ev: ev({ col: { driverRimXml: drv, vbiosRimXml: vb } }) });
  await real('crl-one-only', 'reject', 'Only one of the required CRL issuers.', { ev: ev({ col: realCol({ crls: [crls[0]!] }) }) });
  await real('crl-flipped', 'reject', 'A flipped CRL byte.', { ev: ev({ col: realCol({ crls: [flip(crls[0]!, 80), crls[1]!] }) }) });
  await real('rim-driver-tampered', 'reject', 'Driver RIM edited after signing.', { ev: ev({ col: realCol({ drv: drv.replace('GH100', 'GH101') }) }) });
  await real('rim-swapped', 'reject', 'Driver and VBIOS RIMs swapped.', { ev: ev({ col: realCol({ drv: vb, vb: drv }) }) });
  await real('rim-empty', 'reject', 'Empty driver RIM.', { ev: ev({ col: realCol({ drv: '' }) }) });
  await real('firmware-min-driver-ok', 'accept', 'A driver floor at the reported version passes.', { cfg: realCfg({ firmware: { minDriverVersion: '595.71.05' } }) });
  await real('firmware-min-driver-above', 'reject', 'A driver floor above the reported version.', { cfg: realCfg({ firmware: { minDriverVersion: '595.71.06' } }) });
  await real('firmware-deny-driver', 'reject', 'The reported driver is on the deny list.', { cfg: realCfg({ firmware: { denyDriverVersions: ['595.71.05'] } }) });
  await real('firmware-malformed-version', 'reject', 'A malformed version in the policy refused at construction.', { cfg: realCfg({ firmware: { minDriverVersion: 'x' } }) });
  await real('crl-not-required', 'accept', 'requireCrls false with CRLs supplied still enforces them.', { cfg: realCfg({ requireCrls: false }) });
  await real('identity-overrides', 'accept', 'identity_overrides.', { cfg: realCfg({}, { identity_overrides: { model_id: 'm1' } }) });

  // ── synthetic scenarios ────────────────────────────────────────────────────
  const syn = (id: string, intent: 'accept' | 'reject', description: string, n: NvSyn, o: { cfg?: JsonObject; ev?: JsonObject | null; now?: number; binding?: WireBinding; tags?: string[]; collateral?: boolean } = {}) =>
    c.add({
      id: `nv-syn-${id}`, vendor: 'nvidia-gpu-spdm', tags: ['synthetic', ...(o.collateral ? ['collateral:rim', 'collateral:crl'] : []), ...(o.tags ?? [])], intent, description,
      config: o.cfg ?? nvConfig(n, o.collateral ? { collateral: {} } : {}), now: o.now ?? NV_NOW, binding: o.binding ?? SYN_BINDING, evidence: o.ev === undefined ? n.evidence : o.ev,
    });
  const base = nvSyn();
  await syn('base-positive', 'accept', 'Forged SPDM transcript and device chain, pinned measurement blocks, no collateral hook.', base);
  await syn('base-positive-leaf-subject', 'accept', 'leafSubjectIncludes matches the device leaf.', base, { cfg: nvConfig(base, { policy: { leafSubjectIncludes: 'GH100' } }) });
  await syn('base-leaf-subject-mismatch', 'reject', 'leafSubjectIncludes does not match.', base, { cfg: nvConfig(base, { policy: { leafSubjectIncludes: 'GB100' } }) });
  await syn('base-wrong-root-pin', 'reject', 'Another root pin.', base, { cfg: nvConfig(base, { over: { rootSpkiSha256: ['00'.repeat(32)] } }) });
  await syn('base-root-pin-uppercase', 'accept', 'Pins compare case-insensitively.', base, { cfg: nvConfig(base, { over: { rootSpkiSha256: [base.s.deviceRootSpkiSha256.toUpperCase()] } }) });
  await syn('base-no-pins', 'reject', 'No root pin refused at construction.', base, { cfg: nvConfig(base, { over: { rootSpkiSha256: [] } }) });
  await syn('base-no-measurements', 'reject', 'Empty measurements without a collateral hook refused at construction.', base, { cfg: nvConfig(base, { policy: { measurements: {} } }) });
  await syn('base-measurement-index-out-of-range', 'reject', 'A pinned index above 255 refused at construction.', base, { cfg: nvConfig(base, { policy: { measurements: { '256': 'aa' } } }) });
  await syn('base-measurement-mismatch', 'reject', 'A pinned block digest that differs.', base, { cfg: nvConfig(base, { policy: { measurements: { '1': '00'.repeat(48) } } }) });
  await syn('base-measurement-uppercase', 'accept', 'Digest pins compare case-insensitively.', base, { cfg: nvConfig(base, { policy: { measurements: { '1': hexOf(goldenDigest(1)).toUpperCase() } } }) });
  await syn('base-measurement-block-missing', 'reject', 'A pinned block the report does not carry.', base, { cfg: nvConfig(base, { policy: { measurements: { '200': hexOf(goldenDigest(1)) } } }) });
  await syn('base-identity-default', 'accept', 'Default identity is empty; hostAsserted carries the GPU digest, driver and VBIOS versions.', base);
  await syn('base-identity-overrides', 'accept', 'identity_overrides.', base, { cfg: nvConfig(base, { over: { identity_overrides: { model_id: 'm', operator: 'o', weights_digest: 'w', weights_measured: true } } }) });
  for (const [n, b] of relays(SYN_BINDING)) await syn(`relayed-${n}`, 'reject', `Another ${n} in the binding.`, base, { binding: b });
  for (const [n, b] of badBindings(SYN_BINDING)) await syn(`bad-binding-${n}`, 'reject', `Binding ${n}: not constructible.`, base, { binding: b });
  await syn('evidence-null', 'reject', 'No evidence.', base, { ev: null });
  await syn('chain-empty', 'reject', 'Empty chain.', base, { ev: { ...base.evidence, certChainPem: '' } });
  // report structure
  const sp = (o: ForgeScenarioOptions) => nvSyn(o);
  const frame: Array<[string, ForgeScenarioOptions]> = [
    ['bad-signature', { spdm: { signature: 'bad' } }], ['signature-wrong-length', { spdm: { signature: new Uint8Array(95) } }], ['trailing-bytes', { spdm: { trailing: Uint8Array.of(0) } }],
    ['version-0x10', { spdm: { version: 0x10 } }], ['request-code', { spdm: { requestCode: 0xe1 } }], ['response-code', { spdm: { responseCode: 0x61 } }], ['num-blocks-header-lies', { spdm: { numBlocksHeader: 63 } }],
    ['rec-len-delta', { spdm: { recLenDelta: 4 } }], ['opaque-len-delta', { spdm: { opaqueLenDelta: 4 } }], ['opaque-tail', { spdm: { opaqueTail: Uint8Array.of(1, 0) } }], ['one-block', { spdm: { blocks: 1 } }], ['zero-blocks', { spdm: { blocks: 0 } }],
  ];
  for (const [n, o] of frame) await syn(`report-${n}`, 'reject', `Report structure: ${n}.`, sp(o), { tags: ['strictness'] });
  const sig2 = sp({});
  await syn('report-flip-request-nonce', 'reject', 'Request nonce edited.', sig2, { ev: { ...sig2.evidence, evidence: b64(flip(sig2.s.evidence.evidence, 10)) } });
  await syn('report-flip-measurement', 'reject', 'A measurement digest byte edited after signing.', sig2, { ev: { ...sig2.evidence, evidence: b64(flip(sig2.s.evidence.evidence, 60)) } });
  await syn('report-signed-by-other-key', 'reject', 'Transcript signed by a key that is not the device leaf.', sp({ spdm: { signer: forgeNvidiaDevicePki({ seed: 'other' }).leafKey } as never }));
  // chain faults
  const FAR_PAST = new Date('2019-01-01Z');
  const chainRows: Array<[string, ForgeScenarioOptions]> = [
    ['leaf-expired', { device: { override: { 0: { notBefore: new Date('2018-01-01Z'), notAfter: FAR_PAST } } } }],
    ['root-expired', { device: { override: { 4: { notBefore: new Date('2018-01-01Z'), notAfter: FAR_PAST } } } }],
    ['mid-not-yet-valid', { device: { override: { 2: { notBefore: new Date('2040-01-01Z'), notAfter: new Date('2041-01-01Z') } } } }],
    ['issuer-not-ca', { device: { override: { 3: { ca: false } } } }],
    ['issuer-no-basic-constraints', { device: { override: { 3: { ca: 'absent' } } } }],
    ['root-not-ca', { device: { override: { 4: { ca: false } } } }],
    ['cert-wrong-curve', { device: { override: { 1: { curve: 'P-256' } } } }],
    ['link-signed-by-other', { device: { override: { 1: { signedBy: forgeNvidiaDevicePki({ seed: 'foreign' }).rootKey } } } }],
  ];
  for (const [n, o] of chainRows) {
    const s = nvSyn(o);
    await syn(`chain-${n}`, 'reject', `Device chain defect: ${n}.`, s, { cfg: nvConfig(s) });
  }
  // collateral
  const col = nvSyn();
  const colRow = (id: string, intent: 'accept' | 'reject', description: string, n: NvSyn, o: { collateral?: JsonObject; policy?: JsonObject; ev?: JsonObject | null; now?: number } = {}) =>
    syn(`col-${id}`, intent, description, n, { cfg: nvConfig(n, { collateral: o.collateral ?? {}, ...(o.policy ? { policy: o.policy } : {}) }), ...(o.ev !== undefined ? { ev: o.ev } : {}), ...(o.now !== undefined ? { now: o.now } : {}), collateral: true });
  await colRow('positive-crl', 'accept', 'RIM signature, golden comparison, version binding and CRLs all pass (OCSP also supplied and enforced).', col);
  await colRow('rim-root-pin-wrong', 'reject', 'Another CoRIM root pin.', col, { collateral: { rimRootSpkiSha256: ['00'.repeat(32)] } });
  await colRow('collateral-absent', 'reject', 'No collateral supplied.', col, { ev: { ...col.evidence, collateral: undefined as never } });
  await colRow('revocation-crl-none-supplied', 'reject', 'CRL revocation required (default) and none supplied.', col, { ev: { ...col.evidence, collateral: nvidiaCollateralWire(col.s, { crls: [], ocsp: [] }) } });
  await colRow('revocation-optional-crls', 'accept', 'requireCrls false: CRLs optional when none are supplied (OCSP supplied is still enforced).', col, { collateral: { requireCrls: false }, ev: { ...col.evidence, collateral: nvidiaCollateralWire(col.s, { crls: [] }) } });
  await colRow('revocation-ocsp', 'accept', "revocation 'ocsp' with good OCSP responses.", col, { collateral: { revocation: 'ocsp' } });
  await colRow('revocation-both', 'accept', "revocation 'both'.", col, { collateral: { revocation: 'both' } });
  await colRow('revocation-ocsp-none-supplied', 'reject', "revocation 'ocsp' with no responses.", col, { collateral: { revocation: 'ocsp' }, ev: { ...col.evidence, collateral: nvidiaCollateralWire(col.s, { ocsp: [] }) } });
  const revokedCrl = [forgeNvidiaCrl(col.s.device, 3, { revoked: [col.s.device.certs[2]!.serialHex] }), col.s.crls[1]!];
  await colRow('crl-revoked-cert', 'reject', 'A chain certificate on the CRL.', col, { ev: { ...col.evidence, collateral: nvidiaCollateralWire(col.s, { crls: revokedCrl }) } });
  const staleCrl = [forgeNvidiaCrl(col.s.device, 3, { nextUpdate: new Date(NV_NOW - 1000) }), col.s.crls[1]!];
  await colRow('crl-stale', 'reject', 'A CRL past its nextUpdate.', col, { ev: { ...col.evidence, collateral: nvidiaCollateralWire(col.s, { crls: staleCrl }) } });
  await colRow('crl-missing-required-issuer', 'reject', 'requireCrlIssuers names an issuer without a CRL.', col, { collateral: { requireCrlIssuers: ['NVIDIA GH100 Identity', 'Nobody'] } });
  const driftGolden = nvSyn({ goldenOverride: { 0: '00'.repeat(48) } });
  await colRow('golden-mismatch', 'reject', 'A RIM golden digest differing from the report.', driftGolden);
  const verMis = nvSyn({ driverRimVersion: '1.2.3' });
  await colRow('driver-rim-version-mismatch', 'reject', "The driver RIM version is not the report's driver.", verMis);
  const vbMis = nvSyn({ vbiosRimVersion: '01.02.03.04.05' });
  await colRow('vbios-rim-version-mismatch', 'reject', "The VBIOS RIM version is not the report's VBIOS.", vbMis);
  const inactive = nvSyn({ inactive: [3] });
  await colRow('rim-entry-inactive', 'accept', 'An inactive RIM entry is not compared.', inactive);
  await colRow('firmware-min-driver-above', 'reject', 'Driver floor above the reported driver.', col, { collateral: { firmware: { minDriverVersion: '999.0.0' } } });
  await colRow('firmware-min-driver-equal', 'accept', 'Driver floor equal to the reported driver.', col, { collateral: { firmware: { minDriverVersion: '595.71.05' } } });
  await colRow('firmware-deny-driver', 'reject', 'Reported driver on the deny list.', col, { collateral: { firmware: { denyDriverVersions: ['595.71.05'] } } });
  await colRow('firmware-min-vbios-above', 'reject', 'VBIOS floor above the reported VBIOS.', col, { collateral: { firmware: { minVbiosVersion: 'ff.ff.ff.ff.ff' } } });
  await colRow('firmware-deny-vbios', 'reject', 'Reported VBIOS on the deny list.', col, { collateral: { firmware: { denyVbiosVersions: ['96.00.9f.00.04'] } } });
  const rimExpired = nvSyn({ corim: { leafValidity: [new Date('2020-01-01Z'), new Date('2021-01-01Z')] } });
  await colRow('rim-signer-expired', 'reject', 'The CoRIM signing certificate expired.', rimExpired);
  const other = nvSyn({ driver: '600.1.1' });
  await colRow('other-driver-positive', 'accept', 'Another driver version with matching RIMs.', other);
}
