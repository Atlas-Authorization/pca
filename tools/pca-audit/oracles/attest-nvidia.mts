// Oracle (TWO corpora, same generator: out/ref-attest-nvidia.json.gz holds every fn except verifyRim and collateralHook, out/ref-attest-nvidia-rim.json.gz holds those two): the NVIDIA GPU confidential-computing attestation modules of packages/pca/src: attest-nvidia-spdm.ts (SPDM GET_MEASUREMENTS transcript parse,
// device-chain verification against a pinned root, report signature, PCA challenge), attest-nvidia-rim.ts (Reference Integrity Manifests: XMLDSig / C14N 1.1 /
// ECDSA-P384-SHA384 verification, RIM ids, golden comparison, CRL revocation, the collateral hook, firmware policy, fetch helpers) and attest-nvidia-ocsp.ts
// (RFC 6960 request build, response verification, per-chain OCSP policy). TS reference. Writes out/ref-attest-nvidia.json.gz (strings over 400 characters live
// in the top-level "blobs" table and appear as {"$blob": id}: hydrate args and out before use).
// Inputs: the REAL public captures under fixtures/real-nvidia-cc (H100, own-H100, two GB100 GPUs, their RIMs, CRLs and OCSP pairs) with byte-level mutations,
// plus synthetic PKI / transcripts / RIMs / CRLs / OCSP responses forged with fixed public seeds (no private key reaches the corpus). The whole-verifier replay
// (createNvidiaSpdmVerifier with the collateral hook) lives in conformance/attestation-evidence-vectors.json (vendor nvidia-gpu-spdm); this corpus is the per-function surface.
//
// PORTING (fn(args) -> native entry point; JSON values; a reference throw ({"$throws"}) only requires the native to refuse; reasons are compared exactly except where noted)
//   bytes {"$bytes"}; chainPem = PEM bundle text, leaf first; cert summary = {subject, issuer, serial, notBefore, notAfter, spkiSha256, rawSha256, ca}
//   report summary (parseNvidiaSpdmEvidence) = {request:{version,code,param1,param2,nonce,slot}, response:{version,code,numBlocks,measurements:[{index,valueType,digest}],
//        responderNonce, opaque:{"<type>": bytes} (keys ascending numerically), signature}, signedBytesLength, signedBytesSha256 (hex)}
//   rim summary (VerifiedRim) = {tagId, product, version, golden:[{index,active,alternatives,size,hashes}] (ascending index), signerSubject}
//   constants []                                              -> the exported constants
//   parseReport [bytes]                                       -> report summary
//   formatVbiosVersion [bytes]                                -> string
//   spkiSha256Hex [certPem]                                   -> hex | throws
//   parsePemChain [pem]                                       -> [cert summary] | throws
//   verifyDeviceChain [pem, pins[], nowMs]                    -> {ok:true, leaf:cert summary, chain:[cert summary]} | {ok:false, reason}
//   verifySpdmSignature [evidence, chainPem]                  -> bool (signature of the parsed report under the chain's leaf key) | throws
//   spdmChallenge [expected]                                  -> bytes (32) | throws
//   verifyRim [xml, {rimRootSpkiSha256[], nowMs}]             -> {ok:true, rim: rim summary} | {ok:false, reason}
//   rimIds [bytes]                                            -> {chip, driver, vbios, driverVersion, vbiosVersion} | null   (nvidiaRimIdsForReport(parse(bytes)))
//   compareReport [bytes, driverRim, vbiosRim]                -> {ok:true, checked} | {ok:false, reason, mismatches?}; rims are rim summaries
//   checkRevocation [chainPem, crls[], nowMs, requireIssuers[], requireFor]  -> {ok:true, verifiedCrls} | {ok:false, reason}; requireFor "cdp"|"all"|"none"|[idx]
//   collateralHook [{opts, bundle, evidence, chainPem, nowMs}] -> {value: string|null} | {$throws}; opts = {rimRootSpkiSha256, revocation?, requireCrls?,
//        requireCrlIssuers?, requireCrlFor?, firmware?}; bundle = {driverRimXml, vbiosRimXml, crls?[], ocsp?[]} | null (the resolver returns undefined);
//        null value = the hook accepted
//   fetchRim [{id, response, baseUrl?}]                       -> {ok, value} | {ok:false, error}, requests; response = {status, body} (json) | {$throws}
//   fetchCrl [{url, response}]                                -> same, value = bytes
//   ocspRequest [certPem, issuerPem, opts]                    -> bytes (DER OCSPRequest, SHA-384 CertID unless opts.hash)  | throws
//   (OCSP failure reasons that start with 'OCSP response rejected:' or name an ASN.1 library schema / OID are library text: compare ok only for those)
//   ocspVerify [responseDer, {chainPem, certIndex, issuerIndex, nowMs, maxAgeMs?, expectedNonce?, clockSkewMs?}] -> NvidiaOcspResult
//   ocspUrls [certPem]                                        -> [string]
//   ocspChain [chainPem, responses[], nowMs, opts]            -> NvidiaChainOcspResult (opts: requireGood, maxAgeMs, clockSkewMs, expectedNonces as [bytes|null])
//   fetchOcsp [{certPem, issuerPem, response, opts}]          -> {ok:true, request, response} | {ok:false, error}; requests = [{url, method, contentType}]
//   asn1TimesWellFormed [der]                                 -> bool: every GeneralizedTime / UTCTime inside the DER value is a well-formed DER time with in-range fields (no calendar roll-over);
//        the contents of OCTET STRING / BIT STRING are opaque and never inspected (allAsn1TimesWellFormed over the lane's own ASN.1 reader; a time the reader itself refuses to parse is false)
import { Oracle, seed } from './lib.mjs';
import { b64u, B, unb, hex, fx, fxt, chr, flip, EXPECTED, refWriteBlobs } from './attest-roots-kit.mts';
import { createHash, X509Certificate } from 'node:crypto';

const SP: any = await import('../../../packages/pca/src/attest-nvidia-spdm.ts');
const RM: any = await import('../../../packages/pca/src/attest-nvidia-rim.ts');
const OC: any = await import('../../../packages/pca/src/attest-nvidia-ocsp.ts');
const FS: any = await import('../../../packages/pca/src/test-support/forge-spdm.ts');
const FX: any = await import('../../../packages/pca/src/test-support/forge-x509.ts');
const o = new Oracle('attest-nvidia', 'tools/pca-audit/oracles/attest-nvidia.mts', 'TS-reference oracle for the NVIDIA GPU-CC attestation modules (SPDM, RIM, OCSP, collateral hook).');
const o2 = new Oracle('attest-nvidia-rim', 'tools/pca-audit/oracles/attest-nvidia.mts', 'TS-reference oracle for the NVIDIA RIM XMLDSig verification and the collateral hook (second half of attest-nvidia; same generator).');
const add = (fn: string, name: string, args: any[], out: any) => (fn === 'verifyRim' || fn === 'collateralHook' ? o2 : o).add(fn, name, args, out);
const sha = (b: Uint8Array | Buffer) => createHash('sha256').update(b).digest('hex');
const jr = (v: any): any => {
  if (v instanceof Uint8Array) return { $bytes: b64u(v) };
  if (v instanceof Map) return Object.fromEntries([...v.entries()].sort((a, b) => a[0] - b[0]).map(([k, x]) => [String(k), jr(x)]));
  if (v instanceof X509Certificate) return cert(v);
  if (Array.isArray(v)) return v.map(jr);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).filter((k) => v[k] !== undefined && typeof v[k] !== 'function').map((k) => [k, jr(v[k])]));
  return v;
};
const cert = (c: X509Certificate) => ({ subject: c.subject, issuer: c.issuer, serial: c.serialNumber, notBefore: c.validFrom, notAfter: c.validTo, spkiSha256: SP.spkiSha256Hex(c), rawSha256: sha(c.raw), ca: c.ca });
const sync = (fn: () => any) => { try { return jr(fn()); } catch (e: any) { return { $throws: e instanceof Error ? e.message : String(e) }; } };
const asyn = async (fn: () => Promise<any>) => { try { return jr(await fn()); } catch (e: any) { return { $throws: e instanceof Error ? e.message : String(e) }; } };
const reportSummary = (p: any) => ({ request: p.request, response: { ...p.response, numBlocks: p.response.numBlocks }, signedBytesLength: p.signedBytes.length, signedBytesSha256: sha(p.signedBytes) });
const ribSummary = (r: any) => ({ tagId: r.tagId, product: r.product, version: r.version, golden: [...r.golden.values()].sort((a: any, b: any) => a.index - b.index), signerSubject: r.signerSubject });
const ribFrom = (j: any) => ({ ...j, golden: new Map(j.golden.map((g: any) => [g.index, g])) });

// ---- fixtures ----
const NV = 'real-nvidia-cc';
const H100 = { report: new Uint8Array(fx(NV, 'h100-gpu-attestation-report.bin')), chain: fxt(NV, 'h100-device-cert-chain.pem') };
const OWN = { report: new Uint8Array(fx(NV, 'own-h100', 'h100-gpu-attestation-report.bin')), chain: fxt(NV, 'own-h100', 'h100-device-cert-chain.pem') };
const GB0 = { report: new Uint8Array(fx(NV, 'blackwell', 'gb100-gpu-attestation-report.bin')), chain: fxt(NV, 'blackwell', 'gb100-device-cert-chain.pem') };
const GB1 = { report: new Uint8Array(fx(NV, 'blackwell', 'gb100-gpu1-attestation-report.bin')), chain: fxt(NV, 'blackwell', 'gb100-gpu1-device-cert-chain.pem') };
const ROOT = 'a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4';
const RIMROOT = 'dec1dc316477aa851eebdf51327ae9f864bc8d89254657ed1e7eb9168af1e1a3';
const NOW_H = 1_791_498_000_000;
const NOW_B = Date.parse('2026-10-09T00:33:00Z');
const NOW_O = Date.parse('2026-10-08T23:08:00Z');
const RIMS = {
  h100d: fxt(NV, 'collateral', 'driver-rim-NV_GPU_DRIVER_GH100_580.95.05.xml'), h100v: fxt(NV, 'collateral', 'vbios-rim-NV_GPU_VBIOS_G520_0280_895_9600D00003.xml'),
  ownd: fxt(NV, 'own-h100', 'driver-rim.xml'), ownv: fxt(NV, 'own-h100', 'vbios-rim.xml'), gbd: fxt(NV, 'blackwell', 'driver-rim.xml'), gbv: fxt(NV, 'blackwell', 'vbios-rim.xml'),
};
const CRL = { h1: new Uint8Array(fx(NV, 'collateral', 'l1-root.crl')), h2: new Uint8Array(fx(NV, 'collateral', 'l2-gh100.crl')), g1: new Uint8Array(fx(NV, 'blackwell', 'l1-root.crl')), g2: new Uint8Array(fx(NV, 'blackwell', 'l2-gb100.crl')) };
const OCSPF = (n: string, v = 'nonce') => new Uint8Array(fx(NV, 'ocsp', `${n}.${v}.resp.der`));
const OCSPQ = (n: string, v = 'nonce') => new Uint8Array(fx(NV, 'ocsp', `${n}.${v}.req.der`));
const OCSPN = ['0-leaf-fmc', '1-brom', '2-provisioner-ica', '3-identity'];
const NONCE = new Uint8Array(Buffer.from('0123456789abcdef0123456789abcdef', 'hex'));

// ---- constants ----
add('constants', 'all', [], jr({ NVIDIA_SPDM_SUITE: SP.NVIDIA_SPDM_SUITE, NVIDIA_OPAQUE: SP.NVIDIA_OPAQUE, NVIDIA_RIM_BASE_URL: RM.NVIDIA_RIM_BASE_URL, NVIDIA_GH100_CRL_URLS: RM.NVIDIA_GH100_CRL_URLS, NVIDIA_GB100_CRL_URLS: RM.NVIDIA_GB100_CRL_URLS, NVIDIA_OCSP_URL: OC.NVIDIA_OCSP_URL, NVIDIA_OCSP_DEFAULT_MAX_AGE_MS: OC.NVIDIA_OCSP_DEFAULT_MAX_AGE_MS }));

// ---- parse ----
const pr = (nm: string, b: Uint8Array) => add('parseReport', nm, [B(b)], sync(() => reportSummary(SP.parseNvidiaSpdmEvidence(b))));
pr('real-h100', H100.report); pr('real-own-h100', OWN.report); pr('real-gb100-gpu0', GB0.report); pr('real-gb100-gpu1', GB1.report);
for (const at of [0, 1, 4, 5, 36, 37, 38, 41, 44, 45, 100, 2000, 4000, H100.report.length - 97, H100.report.length - 96, H100.report.length - 1]) pr('h100-truncated-' + at, H100.report.subarray(0, at));
for (const at of [0, 1, 36, 38, 41, 44]) pr('h100-byte' + at + '-flipped', flip(H100.report, at, 0xff));
pr('h100-appended-byte', Buffer.concat([H100.report, Buffer.from([0])]));
pr('h100-signature-flipped', flip(H100.report, H100.report.length - 3));
pr('h100-prepended-byte', Buffer.concat([Buffer.from([0]), H100.report]));
pr('empty', new Uint8Array(0)); pr('zeros-300', new Uint8Array(300));
{
  const dev = FS.forgeNvidiaDevicePki({ seed: 'oracle/parse' });
  const f = (nm: string, opts: any = {}) => pr('forged-' + nm, FS.forgeSpdmTranscript({ signer: dev.leafKey, ...opts }).evidence);
  f('default'); f('version-1.0', { version: 0x10 }); f('version-1.2', { version: 0x12 }); f('request-code', { requestCode: 0xe1 }); f('response-code', { responseCode: 0x61 });
  f('blocks-1', { blocks: 1 }); f('blocks-0', { blocks: 0 }); f('blocks-255', { blocks: 255 }); f('blocks-header-lies-more', { numBlocksHeader: 65 }); f('blocks-header-lies-less', { numBlocksHeader: 63 });
  f('rec-len-short', { recLenDelta: -1 }); f('rec-len-long', { recLenDelta: 1 }); f('rec-len-huge', { recLenDelta: 100000 }); f('opaque-len-short', { opaqueLenDelta: -1 }); f('opaque-len-long', { opaqueLenDelta: 1 });
  f('opaque-tail-3', { opaqueTail: Uint8Array.of(1, 2, 3) }); f('opaque-tail-4-zero-tlv', { opaqueTail: Uint8Array.of(9, 0, 0, 0) }); f('opaque-tail-overrun-tlv', { opaqueTail: Uint8Array.of(9, 0, 5, 0, 1) });
  f('trailing', { trailing: Uint8Array.of(0) }); f('signature-bad', { signature: 'bad' }); f('signature-short', { signature: new Uint8Array(95) }); f('signature-long', { signature: new Uint8Array(97) });
  f('opaque-empty', { opaque: [] }); f('opaque-duplicate-type-last-wins', { opaque: [[3, Buffer.from('1.0')], [3, Buffer.from('2.0')]] });
  f('measurement-dmtf-short', { measurements: [{ index: 1, digest: new Uint8Array(48), dmtfSizeDelta: -1 }] });
  f('measurement-dmtf-long', { measurements: [{ index: 1, digest: new Uint8Array(48), dmtfSizeDelta: 1 }] });
  f('measurement-block-short', { measurements: [{ index: 1, digest: new Uint8Array(48), blockSizeDelta: -1 }] });
  f('measurement-block-too-small', { measurements: [{ index: 1, digest: new Uint8Array(0), blockSizeDelta: -49 }] });
  f('measurement-value-type-0', { measurements: [{ index: 1, digest: new Uint8Array(48), valueType: 0 }] });
  f('measurement-index-255', { measurements: [{ index: 255, digest: new Uint8Array(48) }] });
  f('measurement-digest-32', { measurements: [{ index: 1, digest: new Uint8Array(32) }] });
  f('measurement-digest-empty', { measurements: [{ index: 1, digest: new Uint8Array(0) }] });
  f('measurement-duplicate-index', { measurements: [{ index: 1, digest: new Uint8Array(48) }, { index: 1, digest: new Uint8Array(48).fill(1) }] });
  f('slot-3', { slot: 3 }); f('param1-0', { param1: 0 });
  f('challenge-short', { challenge: new Uint8Array(32) });
}
for (const [nm, hexv] of [['hopper', '009f009604000000'], ['blackwell', '1e00e40097000000'], ['empty', ''], ['one-byte', '01'], ['two-bytes', '0102'], ['odd-three', '010203'], ['eight-zero', '0000000000000000'], ['four', '01020304'], ['sixteen', '00112233445566778899aabbccddeeff']] as any[]) add('formatVbiosVersion', nm, [B(Buffer.from(hexv, 'hex'))], sync(() => SP.formatVbiosVersion(Buffer.from(hexv, 'hex'))));

// ---- certificates ----
const chainOf = (pem: string) => pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)!;
const pem5 = chainOf(H100.chain);
add('spkiSha256Hex', 'h100-root', [pem5[4]], sync(() => SP.spkiSha256Hex(new X509Certificate(pem5[4]!))));
add('spkiSha256Hex', 'h100-leaf', [pem5[0]], sync(() => SP.spkiSha256Hex(new X509Certificate(pem5[0]!))));
add('spkiSha256Hex', 'garbage', ['not a certificate'], sync(() => SP.spkiSha256Hex(new X509Certificate('not a certificate'))));
const pc = (nm: string, pem: string) => add('parsePemChain', nm, [pem], sync(() => SP.parsePemChain(pem)));
pc('h100', H100.chain); pc('gb100', GB0.chain); pc('single', pem5[4]!); pc('empty', ''); pc('garbage', 'hello'); pc('four-plus-root-six', [...pem5, pem5[4]].join('\n')); pc('max-5-ok', pem5.join('\n')); pc('crlf', pem5.join('\r\n')); pc('leading-text', 'x\n' + pem5.join('\n'));
pc('corrupt-body', pem5[0]!.replace(/MII/, 'MIJ')); pc('truncated-pem', pem5[0]!.slice(0, 300)); pc('bundle-with-crl-text', pem5[0] + '\n-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n');
const vc = (nm: string, pem: string, pins: string[], now: number) => add('verifyDeviceChain', nm, [pem, pins, now], sync(() => { const r = SP.verifyNvidiaDeviceChain(pem, pins, now); return r.ok ? { ok: true, leaf: cert(r.leaf), chain: r.chain.map(cert) } : r; }));
for (const [nm, c, now] of [['h100', H100, NOW_H], ['own-h100', OWN, NOW_H], ['gb100-gpu0', GB0, NOW_B], ['gb100-gpu1', GB1, NOW_B]] as any[]) {
  vc(nm, c.chain, [ROOT], now);
  vc(nm + '-pin-upper-case', c.chain, [ROOT.toUpperCase()], now);
  vc(nm + '-pin-wrong', c.chain, ['00'.repeat(32)], now);
  vc(nm + '-pins-empty', c.chain, [], now);
  vc(nm + '-pin-second-of-two', c.chain, ['00'.repeat(32), ROOT], now);
  vc(nm + '-before-validity', c.chain, [ROOT], Date.parse('2015-01-01T00:00:00Z'));
  vc(nm + '-after-validity', c.chain, [ROOT], Date.parse('2200-01-01T00:00:00Z'));
}
{
  const p = chainOf(H100.chain);
  vc('h100-root-missing', p.slice(0, 4).join('\n'), [ROOT], NOW_H);
  vc('h100-leaf-only', p[0]!, [ROOT], NOW_H);
  vc('h100-root-only', p[4]!, [ROOT], NOW_H);
  vc('h100-reordered', [p[1], p[0], p[2], p[3], p[4]].join('\n'), [ROOT], NOW_H);
  vc('h100-reversed', [...p].reverse().join('\n'), [ROOT], NOW_H);
  vc('h100-middle-dropped', [p[0], p[2], p[3], p[4]].join('\n'), [ROOT], NOW_H);
  vc('h100-duplicate-root', [...p, p[4]].join('\n'), [ROOT], NOW_H);
  vc('h100-leaf-flipped', p[0]!.replace('MII', 'MIJ'), [ROOT], NOW_H);
  vc('h100-mixed-with-gb100-leaf', [chainOf(GB0.chain)[0], ...p.slice(1)].join('\n'), [ROOT], NOW_H);
  for (const i of [0, 1, 2, 3]) {
    const der = Buffer.from(new X509Certificate(p[i]!).raw);
    const bad = new X509Certificate(Buffer.from(flip(der, der.length - 10))).toString();
    void bad;
    const flipped = FX.pemOf(flip(der, der.length - 5));
    vc(`h100-cert${i}-signature-flipped`, p.map((x, k) => (k === i ? flipped : x)).join('\n'), [ROOT], NOW_H);
  }
}
// forged device PKIs
const N0 = Date.parse('2026-10-20T00:00:00Z');
const dp = (nm: string, od: any = {}, pin?: string, now = N0, names?: any) => { const d = FS.forgeNvidiaDevicePki({ seed: 'oracle/dev/' + nm, ...(names ? { names } : {}), override: od }); vc('forged-' + nm, d.chainPem, [pin ?? d.rootSpkiSha256], now); return d; };
dp('ok'); dp('pin-other', {}, '00'.repeat(32));
dp('leaf-expired', { 0: { notAfter: new Date('2025-01-01Z') } }); dp('leaf-not-yet-valid', { 0: { notBefore: new Date('2027-01-01Z') } }); dp('root-expired', { 4: { notAfter: new Date('2025-01-01Z') } }); dp('mid-expired', { 2: { notAfter: new Date('2025-01-01Z') } });
dp('mid-not-ca', { 2: { ca: false } }); dp('mid-no-basic-constraints', { 2: { ca: 'absent' } }); dp('root-not-ca', { 4: { ca: false } }); dp('leaf-is-ca-ok', { 0: { ca: true } });
dp('leaf-p256', { 0: { curve: 'P-256' } }); dp('root-p256', { 4: { curve: 'P-256' } }); dp('mid-p256', { 3: { curve: 'P-256' } });
dp('link-signed-by-other-key', { 1: { signedBy: FX.forgeKey('oracle/other', 'P-384') } }); dp('root-self-signature-other', { 4: { signedBy: FX.forgeKey('oracle/other', 'P-384') } });
dp('subject-override', { 0: { subject: [['CN', 'Not A GPU']] } });
dp('three-certs', {}, undefined, N0, FS.nvidiaDeviceNames().filter((_: any, i: number) => [0, 3, 4].includes(i)));
dp('six-certs-too-long', {}, undefined, N0, [...FS.nvidiaDeviceNames(), FS.nvidiaDeviceNames()[4]]);
{
  const d = FS.forgeNvidiaDevicePki({ seed: 'oracle/dev/ok' });
  vc('forged-at-2020-10-17-intermediates-not-yet-valid', d.chainPem, [d.rootSpkiSha256], Date.parse('2020-10-17T00:00:00Z'));
  vc('forged-just-before-leaf-not-before', d.chainPem, [d.rootSpkiSha256], Date.parse('2020-10-16T23:59:59Z'));
  vc('forged-now-fraction', d.chainPem, [d.rootSpkiSha256], N0 + 0.5);
  vc('forged-now-zero', d.chainPem, [d.rootSpkiSha256], 0);
}

// ---- signature / challenge ----
const sg = (nm: string, ev: Uint8Array, chain: string) => add('verifySpdmSignature', nm, [B(ev), chain], sync(() => { const rep = SP.parseNvidiaSpdmEvidence(ev); return SP.verifyNvidiaSpdmSignature(rep, SP.parsePemChain(chain)[0].publicKey); }));
sg('h100', H100.report, H100.chain); sg('own-h100', OWN.report, OWN.chain); sg('gb100-gpu0', GB0.report, GB0.chain); sg('gb100-gpu1', GB1.report, GB1.chain);
sg('h100-with-gb100-key', H100.report, GB0.chain); sg('gb100-gpu0-with-gpu1-key', GB0.report, GB1.chain);
for (const at of [10, 50, 1000, H100.report.length - 50, H100.report.length - 2]) sg('h100-flip-' + at, flip(H100.report, at), H100.chain);
sg('h100-nonce-edited', flip(H100.report, 10), H100.chain);
{
  const d = FS.forgeNvidiaDevicePki({ seed: 'oracle/sig' });
  sg('forged-ok', FS.forgeSpdmTranscript({ signer: d.leafKey }).evidence, d.chainPem);
  sg('forged-signed-by-other', FS.forgeSpdmTranscript({ signer: d.keys[1] }).evidence, d.chainPem);
  sg('forged-bad', FS.forgeSpdmTranscript({ signer: d.leafKey, signature: 'bad' }).evidence, d.chainPem);
  sg('forged-p256-leaf-key-with-p384-sig', FS.forgeSpdmTranscript({ signer: d.leafKey }).evidence, FS.forgeNvidiaDevicePki({ seed: 'oracle/sig', override: { 0: { curve: 'P-256' } } }).chainPem);
}
for (const [nm, e] of [['basic', EXPECTED], ['epoch-0', { ...EXPECTED, epoch: 0 }], ['unicode-nonce', { ...EXPECTED, nonce: 'é ' }], ['holder-empty', { ...EXPECTED, holderPub: '' }], ['grant-empty', { ...EXPECTED, grantRef: '' }], ['nonce-empty', { ...EXPECTED, nonce: '' }], ['epoch-negative', { ...EXPECTED, epoch: -1 }], ['epoch-fraction', { ...EXPECTED, epoch: 0.5 }], ['epoch-max', { ...EXPECTED, epoch: 2 ** 53 - 1 }], ['null', null]] as any[]) add('spdmChallenge', nm, [e], sync(() => SP.nvidiaSpdmChallenge(e)));

// ---- RIM verification ----
const vr = async (nm: string, xml: any, pins: string[], now: number) => add('verifyRim', nm, [xml, { rimRootSpkiSha256: pins, nowMs: now }], await asyn(async () => { const r = await RM.verifyNvidiaRim(xml, { rimRootSpkiSha256: pins, nowMs: now }); return r.ok ? { ok: true, rim: ribSummary(r.rim) } : r; }));
for (const [k, x, now] of [['h100-driver', RIMS.h100d, NOW_H], ['h100-vbios', RIMS.h100v, NOW_H], ['own-driver', RIMS.ownd, NOW_H], ['own-vbios', RIMS.ownv, NOW_H], ['gb100-driver', RIMS.gbd, NOW_B], ['gb100-vbios', RIMS.gbv, NOW_B]] as any[]) {
  await vr('real-' + k, x, [RIMROOT], now);
  await vr(`real-${k}-wrong-pin`, x, ['00'.repeat(32)], now);
  await vr(`real-${k}-before-validity`, x, [RIMROOT], Date.parse('2015-01-01Z'));
  await vr(`real-${k}-after-validity`, x, [RIMROOT], Date.parse('2200-01-01Z'));
}
await vr('real-pin-upper-case', RIMS.h100d, [RIMROOT.toUpperCase()], NOW_H);
await vr('real-no-pins', RIMS.h100d, [], NOW_H);
await vr('empty', '', [RIMROOT], NOW_H);
await vr('not-xml', 'hello', [RIMROOT], NOW_H);
await vr('xml-truncated', RIMS.h100d.slice(0, 5000), [RIMROOT], NOW_H);
await vr('number-input', 5 as any, [RIMROOT], NOW_H);
// a document over 4,000,000 characters is refused ('RIM: empty or oversized document'); too large for a corpus: native unit test builds it
await vr('nesting-65', '<a>'.repeat(65) + '</a>'.repeat(65), [RIMROOT], NOW_H);
await vr('nesting-64-not-softwareidentity', '<a>'.repeat(64) + '</a>'.repeat(64), [RIMROOT], NOW_H);
const edit = (nm: string, f: (x: string) => string, x = RIMS.h100d) => vr('real-edit-' + nm, f(x), [RIMROOT], NOW_H);
await edit('digest-value', (x) => x.replace(/<ds:DigestValue>(.)/, (_m, c) => `<ds:DigestValue>${c === 'A' ? 'B' : 'A'}`));
await edit('signature-value', (x) => x.replace(/<ds:SignatureValue>(.)/, (_m, c) => `<ds:SignatureValue>${c === 'A' ? 'B' : 'A'}`));
await edit('hash-digit', (x) => x.replace(/Hash0="(.)/, (_m, c) => `Hash0="${c === '0' ? '1' : '0'}`));
await edit('version', (x) => x.replace(/colloquialVersion="[^"]*"/, 'colloquialVersion="1.0.0"'));
await edit('product', (x) => x.replace(/product="GH100"/, 'product="GH101"'));
await edit('tag-id', (x) => x.replace(/tagId="(.)/, (_m, c) => `tagId="${c === 'a' ? 'b' : 'a'}`));
await edit('trailing-newline', (x) => x + '\n');
await edit('leading-bom', (x) => '﻿' + x);
await edit('comment-added', (x) => x.replace('<ns0:Payload', '<!-- c --><ns0:Payload'));
await edit('doctype-added', (x) => '<!DOCTYPE SoftwareIdentity>' + x.replace(/^<\?xml[^>]*\?>\s*/, ''));
await edit('pi-added', (x) => x.replace('<ns0:Payload', '<?pi x?><ns0:Payload'));
await edit('xml-attr-added', (x) => x.replace('<ns0:Payload', '<ns0:Payload xml:space="preserve"'));
await edit('signature-removed', (x) => x.replace(/<ds:Signature[\s\S]*<\/ds:Signature>/, ''));
await edit('keyinfo-removed', (x) => x.replace(/<ds:KeyInfo>[\s\S]*<\/ds:KeyInfo>/, ''));
await edit('first-certificate-dropped', (x) => x.replace(/<ds:X509Certificate>[^<]*<\/ds:X509Certificate>/, ''));
await edit('c14n-method-1.0', (x) => x.replace('xml-c14n11', 'REC-xml-c14n-20010315'));
await edit('signature-method-sha256', (x) => x.replace('ecdsa-sha384', 'ecdsa-sha256'));
await edit('digest-method-sha256', (x) => x.replace('xmldsig-more#sha384', 'xmlenc#sha256'));
await edit('reference-uri', (x) => x.replace('URI=""', 'URI="#x"'));
await edit('transform-order', (x) => x.replace(/(<ds:Transform [^>]*enveloped-signature"\/>)(<ds:Transform [^>]*>)/, '$2$1'));
await edit('resource-removed', (x) => x.replace(/<ns0:Resource [^>]*index="3"[^>]*\/>/, ''));
await edit('root-renamed', (x) => x.replace(/<SoftwareIdentity/, '<SoftwareIdentity2').replace('</SoftwareIdentity>', '</SoftwareIdentity2>'));
// forged CoRIM PKIs and RIMs
const sc = FS.forgeNvidiaScenario({ seed: 'oracle/rim' });
const CP = sc.corim;
const MEAS = (n = 4, over: any = {}) => Array.from({ length: n }, (_, i) => ({ index: i, active: true, hashes: [hex(new Uint8Array(48).fill(i + 1))], size: 48, ...over }));
const fr = async (nm: string, ro: any = {}, pin: string = CP.rootSpkiSha256, now = sc.nowMs) => { const xml = FS.forgeRim({ version: '595.71.05', measurements: MEAS(), signerChain: CP.certs, signerKey: CP.signerKey, ...ro }); await vr('forged-' + nm, xml, [pin], now); return xml; };
await fr('ok'); await fr('pin-other', {}, '00'.repeat(32)); await fr('unprefixed-signature', { unprefixedSignature: true });
await fr('comment', { comment: true }); await fr('doctype', { doctype: true }); await fr('processing-instruction', { processingInstruction: true }); await fr('xml-attr', { xmlAttrOnPayload: true });
await fr('extra-signature-sibling', { extraSignature: 'sibling' }); await fr('extra-signature-nested', { extraSignature: 'nested' }); await fr('wrapped-signature', { wrapSignature: true });
await fr('omit-meta', { omitMeta: true }); await fr('omit-payload', { omitPayload: true }); await fr('omit-keyinfo', { omitKeyInfo: true }); await fr('omit-digest', { omitDigestValue: true }); await fr('omit-signature-value', { omitSignatureValue: true });
await fr('digest-wrong', { digestOverride: Buffer.alloc(48, 7).toString('base64') }); await fr('signature-bytes-95', { signatureBytes: 95 }); await fr('signature-bytes-96-random', { signatureBytes: 96 }); await fr('signature-bytes-97', { signatureBytes: 97 });
await fr('signed-with-other-key', { signWith: FX.forgeKey('oracle/rim-other', 'P-384') });
await fr('c14n-1.0', { c14nUri: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315' }); await fr('c14n-exclusive', { c14nUri: 'http://www.w3.org/2001/10/xml-exc-c14n#' });
await fr('sig-method-sha256', { sigMethodUri: 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256' }); await fr('sig-method-rsa', { sigMethodUri: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' });
await fr('digest-method-sha256', { digestMethodUri: 'http://www.w3.org/2001/04/xmlenc#sha256' });
await fr('transforms-only-enveloped', { transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'] }); await fr('transforms-reversed', { transforms: ['http://www.w3.org/2006/12/xml-c14n11', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'] }); await fr('transforms-three', { transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2006/12/xml-c14n11', 'http://www.w3.org/2006/12/xml-c14n11'] });
await fr('reference-uri-fragment', { referenceUri: '#id' }); await fr('extra-reference', { extraReference: true });
await fr('root-renamed', { rootName: 'Other' });
await fr('measurements-1', { measurements: MEAS(1) }); await fr('measurements-0', { measurements: [] });
await fr('measurement-inactive', { measurements: MEAS(2, { active: false }) });
await fr('measurement-two-alternatives', { measurements: [{ index: 0, active: true, hashes: ['aa'.repeat(48), 'bb'.repeat(48)], size: 48 }] });
await fr('measurement-hash-uppercase', { measurements: [{ index: 0, active: true, hashes: ['AA'.repeat(48)], size: 48 }] });
await fr('measurement-size-mismatch', { measurements: [{ index: 0, active: true, hashes: ['aa'.repeat(48)], size: 47 }] });
await fr('measurement-alternatives-mismatch', { measurements: [{ index: 0, active: true, hashes: ['aa'.repeat(48)], size: 48, alternatives: 2 }] });
await fr('measurement-duplicate-index', { measurements: [{ index: 0, active: true, hashes: ['aa'.repeat(48)], size: 48 }, { index: 0, active: true, hashes: ['bb'.repeat(48)], size: 48 }] });
await fr('measurement-nonhex', { measurements: [{ index: 0, active: true, hashes: ['zz'.repeat(48)], size: 48 }] });
await fr('measurement-index-negative', { measurements: [{ index: -1, active: true, hashes: ['aa'.repeat(48)], size: 48 }] });
await fr('measurement-size-zero', { measurements: [{ index: 0, active: true, hashes: [''], size: 0 }] });
await fr('measurement-type-other-skipped', { measurements: [{ index: 0, active: true, hashes: ['aa'.repeat(48)], size: 48, type: 'Other' }, ...MEAS(1).map((m) => ({ ...m, index: 1 }))] });
await fr('measurement-unicode-name', { measurements: [{ index: 0, active: true, hashes: ['aa'.repeat(48)], size: 48, name: 'é"<&' }] });
await fr('version-unicode', { version: 'é"<&' });
await fr('product-other', { product: 'GB100' });
await fr('tag-id-custom', { tagId: 'custom-tag' });
await fr('leaf-expired-pki', {}, undefined, Date.parse('2030-01-01Z'));
{
  const exp = FS.forgeCorimPki({ seed: 'oracle/corim-exp', leafValidity: [new Date('2020-01-01Z'), new Date('2021-01-01Z')] });
  await fr('signer-expired', { signerChain: exp.certs, signerKey: exp.signerKey }, exp.rootSpkiSha256);
  const nca = FS.forgeCorimPki({ seed: 'oracle/corim-nca', override: { 1: { ca: false } } });
  await fr('intermediate-not-ca', { signerChain: nca.certs, signerKey: nca.signerKey }, nca.rootSpkiSha256);
  const p256 = FS.forgeCorimPki({ seed: 'oracle/corim-p256', override: { 0: { curve: 'P-256' } } });
  await fr('signer-p256', { signerChain: p256.certs, signerKey: p256.signerKey }, p256.rootSpkiSha256);
  await fr('chain-leaf-only', { signerChain: [CP.certs[0]] });
  await fr('chain-no-root', { signerChain: CP.certs.slice(0, 3) });
  await fr('chain-reversed', { signerChain: [...CP.certs].reverse() });
}

// ---- RIM ids ----
const ri = (nm: string, b: Uint8Array) => add('rimIds', nm, [B(b)], sync(() => { const rep = SP.parseNvidiaSpdmEvidence(b); return RM.nvidiaRimIdsForReport(rep) ?? null; }));
ri('real-h100', H100.report); ri('real-own-h100', OWN.report); ri('real-gb100-gpu0', GB0.report); ri('real-gb100-gpu1', GB1.report);
{
  const dev = FS.forgeNvidiaDevicePki({ seed: 'oracle/ids' });
  const base = FS.defaultOpaque();
  const withTypes = (over: [number, Uint8Array | null][]) => { const m = new Map<number, Uint8Array>(base.map(([t, v]: any) => [t, v])); for (const [t, v] of over) (v === null ? m.delete(t) : m.set(t, v)); return [...m.entries()]; };
  const f = (nm: string, ov: [number, Uint8Array | null][]) => ri('forged-' + nm, FS.forgeSpdmTranscript({ signer: dev.leafKey, opaque: withTypes(ov) }).evidence);
  const T = (s: string) => new Uint8Array(Buffer.from(s));
  f('default', []); f('chip-gb100', [[35, T('GB100')]]); f('chip-lowercase', [[35, T('gb100')]]); f('chip-gh100-explicit', [[35, T('GH100')]]); f('chip-too-short', [[35, T('GB')]]); f('chip-12', [[35, T('ABCDEFGHIJKL')]]); f('chip-13', [[35, T('ABCDEFGHIJKLM')]]);
  f('chip-with-dash', [[35, T('GB-100')]]); f('chip-empty', [[35, T('')]]); f('chip-nul-padded', [[35, Uint8Array.of(71, 66, 49, 48, 48, 0, 0)]]); f('chip-leading-digit', [[35, T('1B100')]]); f('chip-spaces-trimmed', [[35, T('  GB100 ')]]);
  for (const t of [3, 6, 15, 17, 18]) f('missing-' + t, [[t, null]]);
  f('driver-nul-padded', [[3, Uint8Array.of(53, 57, 53, 46, 55, 49, 0, 0, 0)]]); f('driver-empty', [[3, T('')]]); f('project-lowercase', [[17, T('g520')]]); f('sku-spaces', [[18, T(' 0280 ')]]);
  f('driver-latin1', [[3, Uint8Array.of(0xe9, 0x31)]]);
}

// ---- compare ----
const rimSum = async (xml: string, now: number) => { const r = await RM.verifyNvidiaRim(xml, { rimRootSpkiSha256: [RIMROOT], nowMs: now }); return ribSummary(r.rim); };
const cmp = (nm: string, rep: Uint8Array, d: any, v: any) => add('compareReport', nm, [B(rep), d, v], sync(() => RM.compareReportToRims(SP.parseNvidiaSpdmEvidence(rep), ribFrom(d), ribFrom(v))));
{
  const H = { d: await rimSum(RIMS.h100d, NOW_H), v: await rimSum(RIMS.h100v, NOW_H) };
  const O = { d: await rimSum(RIMS.ownd, NOW_H), v: await rimSum(RIMS.ownv, NOW_H) };
  const G = { d: await rimSum(RIMS.gbd, NOW_B), v: await rimSum(RIMS.gbv, NOW_B) };
  cmp('real-h100', H100.report, H.d, H.v); cmp('real-own-h100', OWN.report, O.d, O.v); cmp('real-gb100', GB0.report, G.d, G.v); cmp('real-gb100-gpu1', GB1.report, G.d, G.v);
  cmp('real-h100-vs-own-rims', H100.report, O.d, O.v); cmp('real-h100-vs-gb100-rims', H100.report, G.d, G.v); cmp('real-h100-swapped-rims', H100.report, H.v, H.d);
  const mod = (r: any, f: (g: any[]) => any[]) => ({ ...r, golden: f(r.golden) });
  cmp('real-h100-driver-hash-edited', H100.report, mod(H.d, (g) => g.map((x, i) => (x.active && i === g.findIndex((y) => y.active) ? { ...x, hashes: ['00'.repeat(48)] } : x))), H.v);
  cmp('real-h100-driver-hash-second-alternative-matches', H100.report, mod(H.d, (g) => g.map((x, i) => (x.active && i === g.findIndex((y) => y.active) ? { ...x, alternatives: 2, hashes: ['00'.repeat(48), ...x.hashes] } : x))), H.v);
  cmp('real-h100-driver-size-edited', H100.report, mod(H.d, (g) => g.map((x, i) => (x.active && i === g.findIndex((y) => y.active) ? { ...x, size: 32 } : x))), H.v);
  cmp('real-h100-all-inactive', H100.report, mod(H.d, (g) => g.map((x) => ({ ...x, active: false }))), mod(H.v, (g) => g.map((x) => ({ ...x, active: false }))));
  cmp('real-h100-driver-inactive', H100.report, mod(H.d, (g) => g.map((x) => ({ ...x, active: false }))), H.v);
  cmp('real-h100-both-active-same-index', H100.report, H.d, mod(H.v, (g) => [...g, { ...H.d.golden.find((x: any) => x.active) }]));
  cmp('real-h100-golden-index-beyond-report', H100.report, mod(H.d, (g) => [...g, { index: 200, active: true, alternatives: 1, size: 48, hashes: ['00'.repeat(48)] }]), H.v);
  cmp('real-h100-empty-rims', H100.report, { ...H.d, golden: [] }, { ...H.v, golden: [] });
  cmp('real-h100-truncated-report-fewer-blocks', FS.forgeSpdmTranscript({ signer: FS.forgeNvidiaDevicePki().leafKey, blocks: 10 }).evidence, H.d, H.v);
  cmp('real-h100-block35-nvdec-enabled-report', flip(H100.report, 0), H.d, H.v);
  // forged scenarios: NVDEC0 disabled / enabled, merge rules
  const s2 = (o2: any) => FS.forgeNvidiaScenario({ seed: 'oracle/cmp', ...o2 });
  const sum = async (s: any) => ({ d: await rimSumS(s.driverRimXml, s), v: await rimSumS(s.vbiosRimXml, s) });
  const rimSumS = async (xml: string, s: any) => { const r = await RM.verifyNvidiaRim(xml, { rimRootSpkiSha256: [s.rimRootSpkiSha256], nowMs: s.nowMs }); return ribSummary(r.rim); };
  for (const [nm, o3] of [['match', {}], ['nvdec-disabled', { nvdec0: 0x55, goldenOverride: { 34: '00'.repeat(48) } }], ['nvdec-enabled-mismatch', { nvdec0: 0x00, goldenOverride: { 34: '00'.repeat(48) } }], ['golden-mismatch', { goldenOverride: { 3: '00'.repeat(48) } }], ['inactive-mismatch-ignored', { goldenOverride: { 3: '00'.repeat(48) }, inactive: [3] }], ['overlap', { vbiosIndices: [0, 1, 2, 12], driverIndices: [12, 13, 14] }], ['no-active', { inactive: Array.from({ length: 64 }, (_, i) => i) }], ['driver-only', { vbiosIndices: [] }], ['more-golden-than-report', { vbiosIndices: Array.from({ length: 12 }, (_, i) => i), driverIndices: Array.from({ length: 52 }, (_, i) => i + 12) }]] as any[]) {
    const s = s2(o3); const r = await sum(s);
    cmp('forged-' + nm, s.spdm.evidence, r.d, r.v);
  }
}

// ---- revocation ----
const rv = (nm: string, chainPem: string, crls: Uint8Array[], now: number, issuers: string[] = [], req: any = 'cdp') => add('checkRevocation', nm, [chainPem, crls.map((c) => B(c)), now, issuers, req], sync(() => RM.checkNvidiaChainRevocation(SP.parsePemChain(chainPem), crls, now, issuers, req)));
rv('real-h100', H100.chain, [CRL.h2, CRL.h1], NOW_H);
rv('real-h100-require-issuers', H100.chain, [CRL.h2, CRL.h1], NOW_H, ['NVIDIA GH100 Identity', 'NVIDIA Device Identity CA']);
rv('real-h100-require-issuer-absent', H100.chain, [CRL.h2, CRL.h1], NOW_H, ['Nobody']);
rv('real-h100-only-l2', H100.chain, [CRL.h2], NOW_H); rv('real-h100-only-l1', H100.chain, [CRL.h1], NOW_H);
rv('real-h100-no-crls', H100.chain, [], NOW_H);
rv('real-h100-all', H100.chain, [CRL.h2, CRL.h1], NOW_H, [], 'all'); rv('real-h100-none', H100.chain, [], NOW_H, [], 'none'); rv('real-h100-none-with-crl', H100.chain, [CRL.h2], NOW_H, [], 'none');
rv('real-h100-index-list', H100.chain, [CRL.h2, CRL.h1], NOW_H, [], [2, 3]); rv('real-h100-index-root', H100.chain, [CRL.h2, CRL.h1], NOW_H, [], [4]); rv('real-h100-index-negative', H100.chain, [CRL.h2, CRL.h1], NOW_H, [], [-1]); rv('real-h100-index-fraction', H100.chain, [CRL.h2, CRL.h1], NOW_H, [], [1.5]);
rv('real-h100-crl-for-gb100', H100.chain, [CRL.g2, CRL.h1], NOW_H);
rv('real-h100-crl-garbage', H100.chain, [new Uint8Array([1, 2, 3])], NOW_H);
rv('real-h100-crl-flipped', H100.chain, [flip(CRL.h2, 100), CRL.h1], NOW_H);
rv('real-h100-crl-stale', H100.chain, [CRL.h2, CRL.h1], Date.parse('2030-01-01Z'));
rv('real-h100-crl-future', H100.chain, [CRL.h2, CRL.h1], Date.parse('2020-01-01Z'));
rv('real-gb100', GB0.chain, [CRL.g2, CRL.g1], NOW_B); rv('real-gb100-gpu1', GB1.chain, [CRL.g2, CRL.g1], NOW_B); rv('real-gb100-with-hopper-l2', GB0.chain, [CRL.h2, CRL.g1], NOW_B);
{
  const syn = (f: string) => new Uint8Array(fx(NV, 'collateral', 'synthetic', f));
  const sp = fxt(NV, 'collateral', 'synthetic', 'chain.pem');
  rv('synthetic-clean', sp, [syn('ica-clean.der'), syn('root-clean.der')], Date.parse('2026-10-08Z'), [], 'all');
  rv('synthetic-revoked-leaf', sp, [syn('ica-revoked.der'), syn('root-clean.der')], Date.parse('2026-10-08Z'), [], 'all');
  rv('synthetic-revoked-no-root-crl', sp, [syn('ica-revoked.der')], Date.parse('2026-10-08Z'), [], 'none');
  const d = FS.forgeNvidiaDevicePki({ seed: 'oracle/rev' });
  const crl = (idx: number, o3: any = {}) => FS.forgeNvidiaCrl(d, idx, o3);
  const serial = (i: number) => d.certs[i].serialHex;
  const T1 = Date.parse('2026-10-20Z');
  rv('forged-clean', d.chainPem, [crl(3), crl(4)], T1);
  rv('forged-clean-all', d.chainPem, [crl(2), crl(3), crl(4)], T1, [], 'all');
  rv('forged-revoked-identity', d.chainPem, [crl(4, { revoked: [serial(3)] }), crl(3)], T1);
  rv('forged-revoked-ica', d.chainPem, [crl(3, { revoked: [serial(2)] }), crl(4)], T1);
  rv('forged-revoked-leaf-by-ica-crl', d.chainPem, [crl(1, { revoked: [serial(0)] }), crl(3), crl(4)], T1, [], 'all');
  rv('forged-revoked-serial-padded', d.chainPem, [crl(3, { revoked: ['00' + serial(2)] }), crl(4)], T1);
  rv('forged-revoked-other-serial', d.chainPem, [crl(3, { revoked: ['abcdef'] }), crl(4)], T1);
  rv('forged-crl-stale', d.chainPem, [crl(3, { nextUpdate: new Date('2026-10-01Z') }), crl(4)], T1);
  rv('forged-crl-future', d.chainPem, [crl(3, { thisUpdate: new Date('2026-11-01Z') }), crl(4)], T1);
  rv('forged-crl-no-next-update', d.chainPem, [crl(3, { omitNextUpdate: true }), crl(4)], T1);
  rv('forged-crl-signed-by-other', d.chainPem, [crl(3, { signer: FX.forgeKey('oracle/rev-other', 'P-384') }), crl(4)], T1);
  rv('forged-crl-only-root', d.chainPem, [crl(4)], T1); rv('forged-crl-only-identity', d.chainPem, [crl(3)], T1);
  rv('forged-require-issuer-present', d.chainPem, [crl(3), crl(4)], T1, ['NVIDIA GH100 Identity']);
  rv('forged-require-issuer-absent', d.chainPem, [crl(3)], T1, ['NVIDIA Device Identity CA']);
  rv('forged-crl-number', d.chainPem, [crl(3, { crlNumber: 7 }), crl(4)], T1);
}

// ---- collateral hook ----
const hk = async (nm: string, sc2: any) => {
  let out: any;
  try {
    const bundle = sc2.bundle === null ? undefined : { driverRimXml: sc2.bundle.driverRimXml, vbiosRimXml: sc2.bundle.vbiosRimXml, ...(sc2.bundle.crls ? { crls: sc2.bundle.crls.map(unb2) } : {}), ...(sc2.bundle.ocsp ? { ocsp: sc2.bundle.ocsp.map(unb2) } : {}) };
    const hook = RM.nvidiaCollateralHook({ ...sc2.opts, resolve: () => bundle });
    const chain = SP.parsePemChain(sc2.chainPem);
    const report = SP.parseNvidiaSpdmEvidence(unb2(sc2.evidence));
    const v = await hook({ report, chain, leaf: chain[0], nowMs: sc2.nowMs });
    out = { value: v ?? null };
  } catch (e: any) { out = { $throws: e instanceof Error ? e.message : String(e) }; }
  add('collateralHook', nm, [sc2], out);
};
const unb2 = (x: any): Uint8Array => (x && typeof x === 'object' && '$bytes' in x ? unb(x.$bytes) : x);
const bundleOf = (d: string, v: string, crls?: Uint8Array[], ocsp?: Uint8Array[]) => ({ driverRimXml: d, vbiosRimXml: v, ...(crls ? { crls: crls.map(B) } : {}), ...(ocsp ? { ocsp: ocsp.map(B) } : {}) });
const HOOK = (over: any = {}, ev: any = H100, now = NOW_H, bundle: any = bundleOf(RIMS.h100d, RIMS.h100v, [CRL.h2, CRL.h1])) => ({ opts: { rimRootSpkiSha256: [RIMROOT], requireCrlIssuers: ['NVIDIA GH100 Identity', 'NVIDIA Device Identity CA'], ...over }, bundle, evidence: B(ev.report), chainPem: ev.chain, nowMs: now });
await hk('real-h100-ok', HOOK());
await hk('real-h100-crl-missing', HOOK({}, H100, NOW_H, bundleOf(RIMS.h100d, RIMS.h100v)));
await hk('real-h100-crl-not-required', HOOK({ requireCrls: false, requireCrlIssuers: undefined }, H100, NOW_H, bundleOf(RIMS.h100d, RIMS.h100v)));
await hk('real-h100-no-bundle', HOOK({}, H100, NOW_H, null));
await hk('real-h100-wrong-rim-root', HOOK({ rimRootSpkiSha256: ['00'.repeat(32)] }));
await hk('real-h100-rims-swapped', HOOK({}, H100, NOW_H, bundleOf(RIMS.h100v, RIMS.h100d, [CRL.h2, CRL.h1])));
await hk('real-h100-driver-rim-for-other-driver', HOOK({}, H100, NOW_H, bundleOf(RIMS.ownd, RIMS.h100v, [CRL.h2, CRL.h1])));
await hk('real-h100-blackwell-rims', HOOK({}, H100, NOW_H, bundleOf(RIMS.gbd, RIMS.gbv, [CRL.h2, CRL.h1])));
await hk('real-h100-ocsp-both', HOOK({ revocation: 'both' }, H100, NOW_O, bundleOf(RIMS.h100d, RIMS.h100v, [CRL.h2, CRL.h1], [1, 2, 3].map((i) => OCSPF(OCSPN[i]!)))));
await hk('real-h100-ocsp-only', HOOK({ revocation: 'ocsp' }, H100, NOW_O, bundleOf(RIMS.h100d, RIMS.h100v, undefined, [1, 2, 3].map((i) => OCSPF(OCSPN[i]!)))));
await hk('real-h100-ocsp-required-missing', HOOK({ revocation: 'ocsp' }, H100, NOW_O, bundleOf(RIMS.h100d, RIMS.h100v)));
await hk('real-h100-ocsp-stale', HOOK({ revocation: 'ocsp' }, H100, NOW_O + 72 * 3600_000, bundleOf(RIMS.h100d, RIMS.h100v, undefined, [1, 2, 3].map((i) => OCSPF(OCSPN[i]!)))));
await hk('real-h100-crl-mode-explicit', HOOK({ revocation: 'crl' }));
await hk('real-h100-require-crl-for-all', HOOK({ requireCrlFor: 'all' }));
await hk('real-h100-require-crl-for-list', HOOK({ requireCrlFor: [2, 3] }));
await hk('real-h100-require-crl-for-bad-list', HOOK({ requireCrlFor: [4] }));
await hk('real-h100-require-crl-for-malformed-construct', HOOK({ requireCrlFor: 'some' }));
await hk('real-h100-require-issuers-malformed-construct', HOOK({ requireCrlIssuers: [5] }));
await hk('construct-no-root-pin', { ...HOOK(), opts: { rimRootSpkiSha256: [] } });
await hk('construct-pin-missing', { ...HOOK(), opts: {} });
for (const [nm, fw] of [['min-driver-ok', { minDriverVersion: '580.95.05' }], ['min-driver-above', { minDriverVersion: '580.95.06' }], ['min-driver-shorter', { minDriverVersion: '580.95' }], ['min-driver-major', { minDriverVersion: '581' }], ['min-vbios-ok', { minVbiosVersion: '96.00.d0.00.03' }], ['min-vbios-above', { minVbiosVersion: '96.00.d0.00.04' }], ['min-vbios-upper-hex', { minVbiosVersion: '96.00.D0.00.03' }], ['deny-driver', { denyDriverVersions: ['580.95.05'] }], ['deny-driver-other', { denyDriverVersions: ['580.95.04'] }], ['deny-driver-trailing-zero-equal', { denyDriverVersions: ['580.95.05.0'] }], ['deny-vbios', { denyVbiosVersions: ['96.00.d0.00.03'] }], ['deny-vbios-other', { denyVbiosVersions: ['96.00.d0.00.02'] }], ['malformed-min-driver', { minDriverVersion: '58x' }], ['malformed-min-vbios', { minVbiosVersion: 'zz' }], ['malformed-deny-driver', { denyDriverVersions: ['x'] }], ['malformed-deny-not-array', { denyVbiosVersions: 'x' }], ['min-driver-number', { minDriverVersion: 580 }], ['firmware-array', []], ['firmware-null', null], ['firmware-string', 'x']] as any[]) await hk('real-h100-firmware-' + nm, HOOK({ firmware: fw }));
await hk('real-gb100-ok', { ...HOOK({}, GB0, NOW_B, bundleOf(RIMS.gbd, RIMS.gbv, [CRL.g2, CRL.g1])) , opts: { rimRootSpkiSha256: [RIMROOT], requireCrlIssuers: ['NVIDIA GB100 Identity', 'NVIDIA Device Identity CA'] } });
await hk('real-gb100-hopper-driver-rim', { ...HOOK({}, GB0, NOW_B, bundleOf(RIMS.h100d, RIMS.gbv, [CRL.g2, CRL.g1])), opts: { rimRootSpkiSha256: [RIMROOT] } });
await hk('real-gb100-chip-family-mismatch-chain', HOOK({}, { report: GB0.report, chain: H100.chain }, NOW_B, bundleOf(RIMS.gbd, RIMS.gbv, [CRL.g2, CRL.g1])));
await hk('real-gb100-ocsp-only', { ...HOOK({ revocation: 'ocsp' }, GB0, NOW_B, bundleOf(RIMS.gbd, RIMS.gbv, undefined, ['2-provisioner-ica', '3-identity'].map((n) => new Uint8Array(fx(NV, 'blackwell', 'ocsp', `${n}.nonce.resp.der`))))), opts: { rimRootSpkiSha256: [RIMROOT], revocation: 'ocsp' } });
{
  const s = FS.forgeNvidiaScenario({ seed: 'oracle/hook' });
  const SH = (over: any = {}, sc3: any = s, bundle: any = bundleOf(sc3.driverRimXml, sc3.vbiosRimXml, sc3.crls)) => ({ opts: { rimRootSpkiSha256: [sc3.rimRootSpkiSha256], ...over }, bundle, evidence: B(sc3.spdm.evidence), chainPem: sc3.device.chainPem, nowMs: sc3.nowMs });
  await hk('forged-ok', SH());
  await hk('forged-ok-ocsp', SH({ revocation: 'ocsp' }, s, bundleOf(s.driverRimXml, s.vbiosRimXml, undefined, s.ocsp)));
  await hk('forged-ok-both', SH({ revocation: 'both' }, s, bundleOf(s.driverRimXml, s.vbiosRimXml, s.crls, s.ocsp)));
  await hk('forged-driver-version-mismatch', SH({}, FS.forgeNvidiaScenario({ seed: 'oracle/hook', driverRimVersion: '1.2.3' })));
  await hk('forged-vbios-version-mismatch', SH({}, FS.forgeNvidiaScenario({ seed: 'oracle/hook', vbiosRimVersion: '01.02.03.04.05' })));
  await hk('forged-golden-mismatch', SH({}, FS.forgeNvidiaScenario({ seed: 'oracle/hook', goldenOverride: { 20: '00'.repeat(48) } })));
  await hk('forged-nvdec-disabled', SH({}, FS.forgeNvidiaScenario({ seed: 'oracle/hook', nvdec0: 0x55, goldenOverride: { 34: '00'.repeat(48) } })));
  await hk('forged-chip-family-leaf-subject-mismatch', SH({}, FS.forgeNvidiaScenario({ seed: 'oracle/hook', device: { override: { 0: { subject: [['CN', 'GB200 A01 GSP FMC LF']] } } } })));
  await hk('forged-revoked-identity', SH({}, s, bundleOf(s.driverRimXml, s.vbiosRimXml, [FS.forgeNvidiaCrl(s.device, 4, { revoked: [s.device.certs[3].serialHex] }), FS.forgeNvidiaCrl(s.device, 3)])));
  await hk('forged-driver-rim-wrong-signer', SH({}, FS.forgeNvidiaScenario({ seed: 'oracle/hook' }), bundleOf(FS.forgeRim({ version: '595.71.05', measurements: MEAS(2), signerChain: s.corim.certs, signerKey: FX.forgeKey('oracle/zz', 'P-384') }), s.vbiosRimXml, s.crls)));
  await hk('forged-ocsp-revoked', SH({ revocation: 'ocsp' }, s, bundleOf(s.driverRimXml, s.vbiosRimXml, undefined, [FS.forgeOcspResponse({ cert: s.device.certs[2], issuer: s.device.certs[3], status: 'revoked', reason: 1, thisUpdate: new Date(s.nowMs - 86400_000), nextUpdate: new Date(s.nowMs + 86400_000) }), s.ocsp[2]])));
  await hk('forged-ocsp-all-three-with-crl', SH({ revocation: 'both' }, s, bundleOf(s.driverRimXml, s.vbiosRimXml, s.crls, s.ocsp)));
}

// ---- fetch helpers ----
const fetchScript = (r: any, log: any[]) => async (url: any, init?: any) => { log.push({ url: String(url), method: init?.method ?? 'GET', contentType: init?.headers?.['content-type'] ?? null }); if (r.$throws) throw new Error(r.$throws); return new Response(r.bodyBytes ? Buffer.from(r.bodyBytes.$bytes, 'base64url') : JSON.stringify(r.body), { status: r.status ?? 200 }); };
const fe = async (fn: string, nm: string, sc4: any, call: (f: any) => Promise<any>) => { const log: any[] = []; let out: any; try { out = { ok: true, value: jr(await call(fetchScript(sc4.response, log))) }; } catch (e: any) { out = { ok: false, error: e instanceof Error ? e.message : String(e) }; } out.requests = log; add(fn, nm, [sc4], out); };
const RIMJSON = (xml: string) => ({ rim: Buffer.from(xml).toString('base64') });
await fe('fetchRim', 'ok', { id: 'NV_GPU_DRIVER_GH100_580.95.05', response: { body: RIMJSON('<a/>') } }, (f) => RM.fetchNvidiaRim('NV_GPU_DRIVER_GH100_580.95.05', { fetch: f }));
await fe('fetchRim', 'ok-base-url', { id: 'x', baseUrl: 'https://example.net/r/', response: { body: RIMJSON('é<a/>') } }, (f) => RM.fetchNvidiaRim('x', { fetch: f, baseUrl: 'https://example.net/r/' }));
await fe('fetchRim', 'http-404', { id: 'x', response: { status: 404, body: {} } }, (f) => RM.fetchNvidiaRim('x', { fetch: f }));
await fe('fetchRim', 'no-rim-member', { id: 'x', response: { body: {} } }, (f) => RM.fetchNvidiaRim('x', { fetch: f }));
await fe('fetchRim', 'rim-not-string', { id: 'x', response: { body: { rim: 5 } } }, (f) => RM.fetchNvidiaRim('x', { fetch: f }));
await fe('fetchRim', 'network-error', { id: 'x', response: { $throws: 'down' } }, (f) => RM.fetchNvidiaRim('x', { fetch: f }));
for (const [i, id] of ['a/b', '', 'a b', '../x', 'ok.id-1_2', 'é'].entries()) await fe('fetchRim', 'id-' + i, { id, response: { body: RIMJSON('<a/>') } }, (f) => RM.fetchNvidiaRim(id, { fetch: f }));
await fe('fetchCrl', 'ok', { url: 'https://crl.ndis.nvidia.com/crl/l1-root.crl', response: { bodyBytes: B(CRL.h1) } }, (f) => RM.fetchNvidiaCrl('https://crl.ndis.nvidia.com/crl/l1-root.crl', { fetch: f }));
await fe('fetchCrl', 'http-500', { url: 'https://x.example.net/a.crl', response: { status: 500, body: {} } }, (f) => RM.fetchNvidiaCrl('https://x.example.net/a.crl', { fetch: f }));
await fe('fetchCrl', 'network-error', { url: 'https://x.example.net/a.crl', response: { $throws: 'down' } }, (f) => RM.fetchNvidiaCrl('https://x.example.net/a.crl', { fetch: f }));
await fe('fetchCrl', 'empty-body', { url: 'https://x.example.net/a.crl', response: { bodyBytes: B(new Uint8Array(0)) } }, (f) => RM.fetchNvidiaCrl('https://x.example.net/a.crl', { fetch: f }));

// ---- OCSP ----
const H100C = chainOf(H100.chain).map((p) => new X509Certificate(p));
const oqa = async (nm: string, certPem: string, issuerPem: string, opts: any) => add('ocspRequest', nm, [certPem, issuerPem, jr(opts)], await asyn(() => OC.buildNvidiaOcspRequest(new X509Certificate(certPem), new X509Certificate(issuerPem), unb3(opts))));
const unb3 = (opts: any) => ({ ...opts, ...(opts.nonce && '$bytes' in opts.nonce ? { nonce: unb(opts.nonce.$bytes) } : {}) });
for (const i of [0, 1, 2, 3]) {
  await oqa(`real-${OCSPN[i]}-nonce`, pem5[i]!, pem5[i + 1]!, { nonce: B(NONCE) });
  await oqa(`real-${OCSPN[i]}-nononce`, pem5[i]!, pem5[i + 1]!, {});
}
for (const h of ['sha1', 'sha256', 'sha384', 'sha512', 'md5']) await oqa('hash-' + h, pem5[2]!, pem5[3]!, { hash: h });
for (const n of [1, 16, 32, 33, 0]) await oqa('nonce-len-' + n, pem5[2]!, pem5[3]!, { nonce: B(new Uint8Array(n).fill(7)) });
await oqa('wrong-issuer-pair', pem5[1]!, pem5[3]!, {});
await oqa('self-issued-root', pem5[4]!, pem5[4]!, {});
const ou = async (nm: string, pem: string) => add('ocspUrls', nm, [pem], await asyn(() => OC.nvidiaCertOcspUrls(new X509Certificate(pem))));
for (const i of [0, 1, 2, 3, 4]) await ou('h100-cert' + i, pem5[i]!);
await ou('gb100-identity', chainOf(GB0.chain)[3]!);
{ const d = FS.forgeNvidiaDevicePki({ seed: 'oracle/urls' }); await ou('forged-ica', d.certs[2].pem); await ou('forged-leaf', d.certs[0].pem); }
const ov = async (nm: string, resp: Uint8Array, a: any) => add('ocspVerify', nm, [B(resp), { ...a, ...(a.expectedNonce ? { expectedNonce: B(a.expectedNonce) } : {}) }], await asyn(async () => { const ch = SP.parsePemChain(a.chainPem); return OC.verifyNvidiaOcspResponse(resp, { cert: ch[a.certIndex], issuer: ch[a.issuerIndex ?? a.certIndex + 1], chain: ch, nowMs: a.nowMs, ...(a.maxAgeMs !== undefined ? { maxAgeMs: a.maxAgeMs } : {}), ...(a.expectedNonce ? { expectedNonce: a.expectedNonce } : {}), ...(a.clockSkewMs !== undefined ? { clockSkewMs: a.clockSkewMs } : {}) }); }));
const RA = (i: number, over: any = {}) => ({ chainPem: H100.chain, certIndex: i, nowMs: NOW_O, ...over });
for (const i of [0, 1, 2, 3]) for (const v of ['nonce', 'nononce']) await ov(`real-${OCSPN[i]}-${v}`, OCSPF(OCSPN[i]!, v), RA(i, v === 'nonce' ? { expectedNonce: NONCE } : {}));
await ov('real-nonce-required-absent', OCSPF('2-provisioner-ica', 'nononce'), RA(2, { expectedNonce: NONCE }));
await ov('real-nonce-wrong', OCSPF('2-provisioner-ica'), RA(2, { expectedNonce: new Uint8Array(16).fill(1) }));
await ov('real-nonce-prefix-only', OCSPF('2-provisioner-ica'), RA(2, { expectedNonce: NONCE.subarray(0, 8) }));
await ov('real-cert-for-other-index', OCSPF('2-provisioner-ica'), RA(3));
await ov('real-cert-leaf-unauthorized', OCSPF('0-leaf-fmc'), RA(0));
await ov('real-stale', OCSPF('2-provisioner-ica'), RA(2, { nowMs: NOW_O + 25 * 3600_000 }));
await ov('real-early', OCSPF('2-provisioner-ica'), RA(2, { nowMs: NOW_O - 3600_000 }));
await ov('real-early-with-skew', OCSPF('2-provisioner-ica'), RA(2, { nowMs: NOW_O - 3600_000, clockSkewMs: 3600_000 }));
await ov('real-max-age-short', OCSPF('2-provisioner-ica'), RA(2, { maxAgeMs: 1000 }));
await ov('real-max-age-short-no-next-update-bound', OCSPF('2-provisioner-ica'), RA(2, { maxAgeMs: 0 }));
await ov('real-chain-without-issuer-ica', OCSPF('2-provisioner-ica'), { ...RA(2), chainPem: [pem5[0], pem5[1], pem5[2], pem5[3]].join('\n') });
await ov('real-trailing-byte', Buffer.concat([OCSPF('2-provisioner-ica'), Buffer.from([0])]), RA(2));
await ov('real-truncated', OCSPF('2-provisioner-ica').subarray(0, 500), RA(2));
await ov('real-empty', new Uint8Array(0), RA(2)); await ov('real-garbage', new Uint8Array([9, 9]), RA(2));
for (const at of [30, 80, 200, 300, 500, 700, 900, 1000]) await ov('real-byte' + at + '-flipped', flip(OCSPF('2-provisioner-ica'), at), RA(2));
await ov('real-gb100-identity', new Uint8Array(fx(NV, 'blackwell', 'ocsp', '3-identity.nonce.resp.der')), { chainPem: GB0.chain, certIndex: 3, nowMs: Date.parse('2026-10-09T00:33:00Z'), expectedNonce: NONCE });
await ov('real-gb100-brom-gpu0', new Uint8Array(fx(NV, 'blackwell', 'ocsp', 'gpu0-1-brom.nonce.resp.der')), { chainPem: GB0.chain, certIndex: 1, nowMs: Date.parse('2026-10-09T00:33:00Z'), expectedNonce: NONCE });
await ov('real-gb100-brom-gpu0-for-gpu1-chain', new Uint8Array(fx(NV, 'blackwell', 'ocsp', 'gpu0-1-brom.nonce.resp.der')), { chainPem: GB1.chain, certIndex: 1, nowMs: Date.parse('2026-10-09T00:33:00Z') });
// forged responses
{
  const d = FS.forgeNvidiaDevicePki({ seed: 'oracle/ocsp' });
  const T1 = Date.parse('2026-10-20T00:00:00Z');
  const tu = new Date(T1 - 60_000), nu = new Date(T1 + 86400_000);
  const RES = FS.forgeOcspResponderCert(d.certs[3], d.keys[3], { seed: 'oracle/responder' });
  const base = (o3: any = {}) => FS.forgeOcspResponse({ cert: d.certs[2], issuer: d.certs[3], thisUpdate: tu, nextUpdate: nu, ...o3 });
  const FA = (over: any = {}) => ({ chainPem: d.chainPem, certIndex: 2, nowMs: T1, ...over });
  const fo = (nm: string, o3: any, over: any = {}) => ov('forged-' + nm, base(o3), FA(over));
  await fo('good-issuer', {}); await fo('good-issuer-key-id', { responderId: 'key' }); await fo('revoked', { status: 'revoked', reason: 1 }); await fo('revoked-no-reason', { status: 'revoked' }); await fo('unknown', { status: 'unknown' });
  await fo('revoked-reason-6', { status: 'revoked', reason: 6, revokedAt: new Date('2026-01-01T00:00:00Z') });
  await fo('good-no-next-update', { nextUpdate: undefined }); await fo('good-no-next-update-old', { nextUpdate: undefined, thisUpdate: new Date(T1 - 8 * 86400_000) });
  await fo('good-delegated', { responder: { kind: 'delegated', cert: RES } }); await fo('good-delegated-name-id', { responder: { kind: 'delegated', cert: RES }, responderId: 'name' });
  await fo('delegated-not-embedded', { responder: { kind: 'delegated', cert: RES, embed: false } });
  await fo('delegated-wrong-eku', { responder: { kind: 'delegated', cert: FS.forgeOcspResponderCert(d.certs[3], d.keys[3], { seed: 'oracle/responder', eku: ['1.3.6.1.5.5.7.3.1'] }) } });
  await fo('delegated-no-eku', { responder: { kind: 'delegated', cert: FS.forgeOcspResponderCert(d.certs[3], d.keys[3], { seed: 'oracle/responder', eku: null }) } });
  await fo('delegated-expired', { responder: { kind: 'delegated', cert: FS.forgeOcspResponderCert(d.certs[3], d.keys[3], { seed: 'oracle/responder', notAfter: new Date('2026-01-01Z') }) } });
  await fo('delegated-not-yet-valid', { responder: { kind: 'delegated', cert: FS.forgeOcspResponderCert(d.certs[3], d.keys[3], { seed: 'oracle/responder', notBefore: new Date('2027-01-01Z') }) } });
  await fo('delegated-signed-by-other-ca', { responder: { kind: 'delegated', cert: FS.forgeOcspResponderCert(d.certs[0], d.keys[0], { seed: 'oracle/responder' }) } });
  await fo('delegated-signed-by-root', { responder: { kind: 'delegated', cert: FS.forgeOcspResponderCert(d.certs[4], d.keys[4], { seed: 'oracle/responder' }) } });
  await fo('delegated-signature-by-other-key', { responder: { kind: 'delegated', cert: RES }, signer: FX.forgeKey('oracle/zz', 'P-384') });
  await fo('delegated-embedded-other-cert', { responder: { kind: 'delegated', cert: RES }, embedCerts: [FS.forgeOcspResponderCert(d.certs[3], d.keys[3], { seed: 'oracle/responder2' })] });
  await fo('issuer-signature-by-other-key', { signer: FX.forgeKey('oracle/zz', 'P-384') });
  await fo('issuer-id-by-other-name', { responder: { kind: 'delegated', cert: d.certs[3] }, responderId: 'name' });
  for (const h of ['sha1', 'sha256', 'sha512']) await fo('certid-' + h, { certIdHash: h });
  await fo('serial-other', { serialOverride: Uint8Array.of(1, 2, 3) }); await fo('duplicate-single-responses', { duplicate: true });
  await fo('serial-leading-zero', { serialOverride: Buffer.concat([Buffer.from([0]), Buffer.from(d.certs[2].serialHex.length % 2 ? '0' + d.certs[2].serialHex : d.certs[2].serialHex, 'hex')]) });
  await fo('status-1-malformed', { responseStatus: 1 }); await fo('status-2-internal', { responseStatus: 2 }); await fo('status-3-try-later', { responseStatus: 3 }); await fo('status-5-sigrequired', { responseStatus: 5 }); await fo('status-6-unauthorized', { responseStatus: 6 });
  await fo('response-type-other', { responseType: '1.3.6.1.5.5.7.48.1.2' }); await fo('trailing-garbage', { trailing: Uint8Array.of(0) });
  await fo('nonce-echoed', { nonce: NONCE }, { expectedNonce: NONCE }); await fo('nonce-echoed-not-required', { nonce: NONCE }); await fo('nonce-wrong', { nonce: NONCE }, { expectedNonce: new Uint8Array(16).fill(9) }); await fo('nonce-absent-required', {}, { expectedNonce: NONCE });
  await fo('nonce-32-bytes', { nonce: new Uint8Array(32).fill(5) }, { expectedNonce: new Uint8Array(32).fill(5) });
  await fo('this-update-future', { thisUpdate: new Date(T1 + 3600_000), producedAt: new Date(T1 + 3600_000), nextUpdate: new Date(T1 + 86400_000) }); await fo('this-update-future-skew', { thisUpdate: new Date(T1 + 3600_000), producedAt: new Date(T1 + 3600_000), nextUpdate: new Date(T1 + 86400_000) }, { clockSkewMs: 3600_000 });
  await fo('produced-at-future', { producedAt: new Date(T1 + 3600_000) }); await fo('next-update-past', { nextUpdate: new Date(T1 - 1000) }); await fo('next-update-equals-now', { nextUpdate: new Date(T1) }); await fo('next-update-before-this-update', { nextUpdate: new Date(T1 - 3600_000), thisUpdate: new Date(T1 - 60_000) });
  await fo('older-than-max-age', { thisUpdate: new Date(T1 - 8 * 86400_000), nextUpdate: new Date(T1 + 86400_000) }); await fo('older-than-max-age-custom', {}, { maxAgeMs: 1000 });
  await fo('wrong-cert-index', {}, { certIndex: 1 });
  await fo('chain-index-for-issuer-itself', {}, { certIndex: 3 });
  // out-of-range ASN.1 times (patched in place so the DER length is unchanged; thisUpdate is rejected before any signature work)
  const patch = (b: Uint8Array, find: string, repl: string) => { const s = Buffer.from(b).toString('latin1'); const i = s.indexOf(find); return i < 0 ? b : new Uint8Array(Buffer.from(s.slice(0, i) + repl + s.slice(i + find.length), 'latin1')); };
  const tstr = (dt: Date) => dt.toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '');
  const bb = base();
  await ov('forged-time-month-00', patch(bb, tstr(tu), tstr(tu).slice(0, 4) + '00' + tstr(tu).slice(6)), FA());
  await ov('forged-time-month-13', patch(bb, tstr(tu), tstr(tu).slice(0, 4) + '13' + tstr(tu).slice(6)), FA());
  await ov('forged-time-day-32', patch(bb, tstr(tu), tstr(tu).slice(0, 6) + '32' + tstr(tu).slice(8)), FA());
  await ov('forged-time-day-00', patch(bb, tstr(tu), tstr(tu).slice(0, 6) + '00' + tstr(tu).slice(8)), FA());
  await ov('forged-time-feb-30', patch(bb, tstr(tu), '20260230' + tstr(tu).slice(8)), FA());
  await ov('forged-time-hour-24', patch(bb, tstr(tu), tstr(tu).slice(0, 8) + '24' + tstr(tu).slice(10)), FA());
  await ov('forged-time-minute-60', patch(bb, tstr(tu), tstr(tu).slice(0, 10) + '60' + tstr(tu).slice(12)), FA());
  await ov('forged-time-second-60', patch(bb, tstr(tu), tstr(tu).slice(0, 12) + '60' + tstr(tu).slice(14)), FA());
  await ov('forged-time-no-z', patch(bb, tstr(tu), tstr(tu).slice(0, -1) + '0'), FA());
  // chain-level policy
  const oc = async (nm: string, resp: Uint8Array[], o4: any = {}, now = T1, chainPem = d.chainPem) => add('ocspChain', nm, [chainPem, resp.map((r) => B(r)), now, jr(o4)], await asyn(async () => OC.checkNvidiaChainOcsp(SP.parsePemChain(chainPem), resp, now, { ...o4, ...(o4.expectedNonces ? { expectedNonces: o4.expectedNonces.map((x: any) => (x === null ? undefined : unb2(x))) } : {}) })));
  const g = (i: number, o3: any = {}) => FS.forgeOcspResponse({ cert: d.certs[i], issuer: d.certs[i + 1], thisUpdate: tu, nextUpdate: nu, ...o3 });
  await oc('good-aia', [g(2), g(3)]); await oc('good-all-required-leaf-missing', [g(1), g(2), g(3)], { requireGood: 'all' }); await oc('good-all-four', [g(0), g(1), g(2), g(3)], { requireGood: 'all' }); await oc('good-explicit', [g(1), g(2), g(3)], { requireGood: [1, 2, 3] });
  await oc('missing-required', [g(2)]); await oc('empty-list', []); await oc('revoked', [g(2, { status: 'revoked' }), g(3)]); await oc('unknown-required', [g(2, { status: 'unknown' }), g(3)]); await oc('unknown-not-required', [g(1, { status: 'unknown' }), g(2), g(3)]);
  await oc('duplicate-for-cert', [g(2), g(2), g(3)]); await oc('response-for-no-cert', [g(2), g(3), FS.forgeOcspResponse({ cert: d.certs[4], issuer: d.certs[4], thisUpdate: tu, nextUpdate: nu })]); await oc('garbage-response', [g(2), g(3), Uint8Array.of(9, 9)]);
  await oc('stale-response', [g(2), g(3)], {}, T1 + 3 * 86400_000); await oc('custom-max-age', [g(2), g(3)], { maxAgeMs: 1000 }); await oc('clock-skew-future', [g(2, { thisUpdate: new Date(T1 + 1000), producedAt: new Date(T1 + 1000) }), g(3)], { clockSkewMs: 5000 });
  await oc('nonces', [g(2, { nonce: NONCE }), g(3, { nonce: NONCE })], { expectedNonces: [null, null, B(NONCE), B(NONCE)] }); await oc('nonce-missing', [g(2), g(3)], { expectedNonces: [null, null, B(NONCE), null] });
  await oc('require-index-root', [g(2), g(3)], { requireGood: [4] }); await oc('require-index-negative', [g(2), g(3)], { requireGood: [-1] }); await oc('require-index-fraction', [g(2), g(3)], { requireGood: [1.5] });
  await oc('chain-too-short', [g(2)], {}, T1, d.certs[3].pem + d.certs[4].pem); await oc('chain-single', [g(2)], {}, T1, d.certs[4].pem);
  await oc('real-h100', [1, 2, 3].map((i) => OCSPF(OCSPN[i]!)), { expectedNonces: [null, B(NONCE), B(NONCE), B(NONCE)] }, NOW_O, H100.chain);
  await oc('real-h100-aia-only-two', [2, 3].map((i) => OCSPF(OCSPN[i]!)), {}, NOW_O, H100.chain);
  await oc('real-h100-leaf-unauthorized', [0, 2, 3].map((i) => OCSPF(OCSPN[i]!)), {}, NOW_O, H100.chain);
  await oc('real-h100-two-versions-of-same', [OCSPF('2-provisioner-ica'), OCSPF('2-provisioner-ica', 'nononce'), OCSPF('3-identity')], {}, NOW_O, H100.chain);
  await oc('real-h100-stale-48h', [2, 3].map((i) => OCSPF(OCSPN[i]!)), {}, NOW_O + 48 * 3600_000, H100.chain);
  await oc('real-h100-nonce-wrong', [2, 3].map((i) => OCSPF(OCSPN[i]!)), { expectedNonces: [null, null, B(new Uint8Array(16).fill(1)), null] }, NOW_O, H100.chain);
  await oc('real-h100-require-all', [1, 2, 3].map((i) => OCSPF(OCSPN[i]!)), { requireGood: 'all' }, NOW_O, H100.chain);
  await oc('real-h100-chain-without-leaf', [1].map((i) => OCSPF(OCSPN[i]!)), {}, NOW_O, pem5.slice(1).join('\n'));
}
// fetchNvidiaOcsp
{
  const logs: any[] = [];
  const fo2 = async (nm: string, sc5: any, opts: any = {}) => {
    const log: any[] = [];
    let out: any;
    try {
      const r = await OC.fetchNvidiaOcsp(new X509Certificate(sc5.certPem), new X509Certificate(sc5.issuerPem), { fetch: async (url: any, init: any) => { log.push({ url: String(url), method: init?.method, contentType: init?.headers?.['content-type'] ?? null, bodyBytes: Buffer.from(init?.body ?? []).length }); if (sc5.response.$throws) throw new Error(sc5.response.$throws); return new Response(Buffer.from(sc5.response.bodyBytes?.$bytes ?? '', 'base64url'), { status: sc5.response.status ?? 200 }); }, ...(opts.url ? { url: opts.url } : {}), ...(opts.nonce ? { nonce: unb(opts.nonce.$bytes) } : {}) });
      out = { ok: true, request: jr(r.request), response: jr(r.response) };
    } catch (e: any) { out = { ok: false, error: e instanceof Error ? e.message : String(e) }; }
    out.requests = log;
    add('fetchOcsp', nm, [{ ...sc5, ...(Object.keys(opts).length ? { opts } : {}) }], out);
  };
  const mk = (resp: any) => ({ certPem: pem5[2], issuerPem: pem5[3], response: resp });
  await fo2('ok', mk({ bodyBytes: B(OCSPF('2-provisioner-ica', 'nononce')) })); await fo2('ok-nonce-custom-url', mk({ bodyBytes: B(OCSPF('2-provisioner-ica')) }), { url: 'http://ocsp.example.net/', nonce: B(NONCE) });
  await fo2('http-500', mk({ status: 500, bodyBytes: B(new Uint8Array(0)) })); await fo2('network-error', mk({ $throws: 'down' })); await fo2('empty-body', mk({ bodyBytes: B(new Uint8Array(0)) }));
  void logs;
}

// ---- allAsn1TimesWellFormed: DER in, bool out (single-byte lengths: every value here is short) ----
{
  const asn1: any = await import('asn1js');
  const tlv = (tag: number, body: Uint8Array | Buffer) => Buffer.concat([Buffer.from([tag, body.length]), body]);
  const gt = (t: string) => tlv(0x18, Buffer.from(t, 'latin1')), ut = (t: string) => tlv(0x17, Buffer.from(t, 'latin1'));
  const seq = (...k: Buffer[]) => tlv(0x30, Buffer.concat(k));
  const wf = (nm: string, der: Uint8Array | Buffer) => add('asn1TimesWellFormed', nm, [B(der)], (() => { try { return OC.allAsn1TimesWellFormed(asn1.fromBER(Uint8Array.from(der).buffer).result, asn1); } catch { return false; } })()); // a time the ASN.1 reader itself refuses is not well formed
  for (const [nm, t] of [['ok', '20250228120000Z'], ['leap-day', '20240229000000Z'], ['not-leap-day', '20250229000000Z'], ['century-not-leap', '21000229000000Z'], ['400-leap', '20000229000000Z'], ['month-00', '20250001000000Z'], ['month-13', '20251301000000Z'], ['day-00', '20250100000000Z'], ['day-32', '20250132000000Z'], ['apr-31', '20250431000000Z'],
    ['hour-24', '20250101240000Z'], ['minute-60', '20250101006000Z'], ['second-60', '20250101000060Z'], ['fraction', '20250101000000.5Z'], ['fraction-trailing-zero', '20250101000000.50Z'], ['fraction-empty', '20250101000000.Z'], ['no-z', '20250101000000'], ['offset', '20250101000000+0000'], ['no-seconds', '202501010000Z'], ['empty', ''], ['year-0000', '00000101000000Z']] as const) wf('generalized-' + nm, gt(t));
  for (const [nm, t] of [['ok-20xx', '250228120000Z'], ['ok-19xx', '991231235959Z'], ['pivot-49', '490229000000Z'], ['pivot-50', '500229000000Z'], ['leap-00-is-2000', '000229000000Z'], ['month-13', '251301000000Z'], ['day-31-feb', '250231000000Z'], ['no-seconds', '2502281200Z'], ['fraction', '250228120000.5Z'], ['four-digit-year', '20250228120000Z']] as const) wf('utc-' + nm, ut(t));
  wf('nested-good', seq(seq(gt('20250101000000Z')), tlv(0xa0, ut('250101000000Z'))));
  wf('nested-one-bad-deep', seq(seq(gt('20250101000000Z'), seq(tlv(0xa1, gt('20250230000000Z'))))));
  wf('bad-time-inside-octet-string-opaque', seq(tlv(0x04, gt('20251301000000Z')), gt('20250101000000Z')));
  wf('bad-time-inside-bit-string-opaque', seq(tlv(0x03, Buffer.concat([Buffer.from([0]), gt('20251301000000Z')]))));
  wf('no-times', seq(tlv(0x02, Buffer.from([1])), tlv(0x05, Buffer.alloc(0))));
  wf('real-response', OCSPF('2-provisioner-ica'));
}

refWriteBlobs(o, 'attest-nvidia');
refWriteBlobs(o2, 'attest-nvidia-rim');
void seed; void chr; void sha; void H100C;
