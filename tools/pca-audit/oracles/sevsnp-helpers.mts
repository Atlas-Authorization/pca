// Oracle: the pure helpers of packages/pca/src/hardware-sevsnp.ts that do not need AMD hardware or a certificate chain: toHex, splitPemCertificates, the report
// parser, the P-384 key / signature helpers, the policy gate, the default identity derivation and the AMD KDS VCEK fetch over an INJECTED transport.
// The certificate helpers (extractTbsCertificate, extractVcekPublicKey, checkVcekReportBinding) run over certificates built here: ECDSA P-384 leaves carrying the AMD VCEK
// extension profile, keys derived from labels (public only in the corpus). NOT here: verifyAmdCertChain and verifyGenuineSevSnpReport need AMD's RSA-4096 root, so they are
// exercised by the real Milan / Genoa chains of ref-attest-eat (every lane has it).
// Writes out/ref-sevsnp-helpers.json.gz. Deterministic: P-384 / ECDSA signatures are RFC 6979; the VCEK key comes from seed(label) and only its PUBLIC point is in the corpus.
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw = the native throws)
//   {"$bytes": b64u} = bytes ; {"$bigint": "<decimal>"} = a 64-bit unsigned integer (report u64 fields, policy minima)
//   toHex [bytes] -> lowercase hex                  splitPemCertificates [pem] -> [each "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----" block, text unchanged]
//   parseReport [reportBytes] -> every ParsedSevSnpReport field (bytes as {$bytes}, u64 as {$bigint}, versions as {major,minor,build}) PLUS signed_len, signed_sha256 (hex of SHA-256 of bytes [0,0x2a0)) and raw_len (signed / raw themselves are not repeated); throws below 0x2e8+72 bytes
//   ecdsaP384PublicKey [sec1] -> {"point": {"$bytes": 97 byte uncompressed SEC1}} (a compressed 49-byte point is accepted and expanded) ; throws on an off-curve / malformed point
//   signatureToCompact [{r, s}] -> {"$bytes": 96 byte r||s big-endian}   (r, s are 72-byte LITTLE-ENDIAN, only the value matters; zero or >= the group order throws)
//   verifyReportSignature [reportBytes, vcekSec1|null-for-malformed] -> bool (SHA-384 of the signed region, ECDSA P-384, high-S accepted; never throws)
//   checkPolicy [reportBytes, policy] -> string | null (reasons compared exactly); policy: hex lists lowercase-compared; minReportedTcb / minCommittedTcb / minLaunchTcb {$bigint}; requireVmpl number | "any"; requireEcdsaP384 false disables the algo gate; allowDebug true
//   deriveIdentity [reportBytes, weightsFromHostData] -> {model_id:"", weights_digest, weights_measured:false, runtime_measurement: hex(measurement), operator: hex(chip_id)}
//   fetchVcek [chipId, reportedTcb, opts] -> {url, bytes} | {$throws}; opts {product?, baseUrl?, status, body: {"$bytes"}}: the transport is a fetch that records the URL and answers {ok: 2xx, status, body}; "noFetch": true = no transport and no global fetch (throws)
//   extractTbsCertificate [certDer] -> {"$bytes": the tbsCertificate TLV} ; throws on a non-SEQUENCE, trailing bytes after the certificate, or a first inner element that is not a SEQUENCE
//   extractVcekPublicKey [certDer] -> {"point": 97-byte SEC1, "tbs": bytes} ; throws unless the certificate parses and its key is EC secp384r1
//   checkVcekReportBinding [tbsBytes, reportBytes] -> string | null (reasons compared exactly except after "VCEK extensions malformed:": prefix only). hwID = the raw 64-byte extnValue; each SPL = one minimal DER INTEGER 0..255;
//        reported_tcb bytes: bootloader 0, tee 1, snp 6, microcode 7 (little-endian u64); a critical AMD extension is refused; hwID is checked before the SPLs, SPL order bootloader, tee, snp, microcode
//   constants [] -> {SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384, SEV_SNP_POLICY_DEBUG_BIT {$bigint}, AMD_MILAN_ARK_SPKI_SHA384}
import { Oracle, refWrite, seed } from './lib.mjs';
import { adder } from './foundation.mjs';
import { p384 } from '@noble/curves/p384';
import { sha256 } from '@noble/hashes/sha2';
const H: any = await import('../../../packages/pca/src/hardware-sevsnp.ts');
const o = new Oracle('sevsnp-helpers', 'tools/pca-audit/oracles/sevsnp-helpers.mts', 'TS-reference oracle for the pure helpers of packages/pca/src/hardware-sevsnp.ts.');
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const parsed = (b: Uint8Array) => { const r = H.parseSevSnpReport(b); const { signed, raw, ...rest } = r; return { ...rest, signed_len: signed.length, signed_sha256: hex(sha256(signed)), raw_len: raw.length }; };
const REF: Record<string, (...a: any[]) => any> = {
  toHex: (b) => H.toHex(b), splitPemCertificates: (p) => H.splitPemCertificates(p), parseReport: (b) => parsed(b),
  ecdsaP384PublicKey: (b) => H.ecdsaP384PublicKey(b), signatureToCompact: (s) => H.sevSnpSignatureToCompact(s),
  verifyReportSignature: (b, k) => H.verifySevSnpReportSignature(H.parseSevSnpReport(b), H.ecdsaP384PublicKey(k)),
  checkPolicy: (b, p) => H.checkSevSnpPolicy(H.parseSevSnpReport(b), p),
  deriveIdentity: (b, w) => H.makeDefaultDeriveIdentity(w)(H.parseSevSnpReport(b)),
  fetchVcek: async (chip, tcb, op) => { const seen: string[] = []; const { status, body, noFetch, ...rest } = op;
    const o2: any = { ...rest }; if (!noFetch) o2.fetch = async (u: string) => { seen.push(u); return { ok: status >= 200 && status < 300, status, arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) }; };
    else { const g = (globalThis as any).fetch; (globalThis as any).fetch = undefined; try { await H.fetchVcekFromKds(chip, tcb, o2); } finally { (globalThis as any).fetch = g; } return null; }
    const r = await H.fetchVcekFromKds(chip, tcb, o2); return { url: seen[0], bytes: r }; },
  extractTbsCertificate: (c) => H.extractTbsCertificate(c), checkVcekReportBinding: (t, r) => H.checkVcekReportBinding(t, H.parseSevSnpReport(r)),
  extractVcekPublicKey: async (c) => { const r = await H.extractVcekPublicKey(c); return { point: r.key.point, tbs: r.tbs }; },
  constants: () => ({ SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384: H.SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384, SEV_SNP_POLICY_DEBUG_BIT: H.SEV_SNP_POLICY_DEBUG_BIT, AMD_MILAN_ARK_SPKI_SHA384: H.AMD_MILAN_ARK_SPKI_SHA384 }),
};
const add = adder(o, REF);

const k48 = (l: string) => { const k = new Uint8Array([...seed(l), ...seed(l + '/2')].slice(0, 48)); k[0] &= 0x7f; return k; };
const sk = k48('sevsnp/vcek'), sk2 = k48('sevsnp/other'); // 48-byte P-384 scalars; only the public points are in the corpus
const PK = p384.getPublicKey(sk, false), PK2 = p384.getPublicKey(sk2, false), PKC = p384.getPublicKey(sk, true);
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const le = (n: bigint, len: number) => { const u = new Uint8Array(len); for (let i = 0; i < len; i++) { u[i] = Number(n & 0xffn); n >>= 8n; } return u; };
function mk(f: any = {}, sign = true, key: Uint8Array = sk): Uint8Array {
  const b = new Uint8Array(0x4a0); const dv = new DataView(b.buffer);
  dv.setUint32(0, f.version ?? 5, true); dv.setUint32(4, f.guest_svn ?? 3, true); dv.setBigUint64(8, f.policy ?? 0x30000n, true);
  b.set(f.family_id ?? fill(16, 0x11), 0x10); b.set(f.image_id ?? fill(16, 0x22), 0x20); dv.setUint32(0x30, f.vmpl ?? 0, true); dv.setUint32(0x34, f.algo ?? 1, true);
  dv.setBigUint64(0x38, f.current_tcb ?? 0x0102030405060708n, true); dv.setBigUint64(0x40, f.platform_info ?? 5n, true);
  b.set(f.report_data ?? fill(64, 0x33), 0x50); b.set(f.measurement ?? fill(48, 0x44), 0x90); b.set(f.host_data ?? fill(32, 0x55), 0xc0); b.set(f.id_key_digest ?? fill(48, 0x66), 0xe0); b.set(f.author_key_digest ?? fill(48, 0x77), 0x110);
  b.set(f.report_id ?? fill(32, 0x88), 0x140); b.set(f.report_id_ma ?? fill(32, 0x99), 0x160); dv.setBigUint64(0x180, f.reported_tcb ?? 0x0807060504030201n, true);
  b[0x188] = f.fam ?? 0x19; b[0x189] = f.mod ?? 1; b[0x18a] = f.step ?? 2; b.set(f.chip_id ?? fill(64, 0xaa), 0x1a0); dv.setBigUint64(0x1e0, f.committed_tcb ?? 0x0807060504030201n, true);
  b[0x1e8] = 7; b[0x1e9] = 55; b[0x1ea] = 1; b[0x1ec] = 6; b[0x1ed] = 54; b[0x1ee] = 1; dv.setBigUint64(0x1f0, f.launch_tcb ?? 0x0807060504030201n, true); dv.setBigUint64(0x1f8, 0x10n, true); dv.setBigUint64(0x200, 0x20n, true);
  if (sign) { const sig = p384.sign(sha384(b.slice(0, 0x2a0)), key); b.set(le(sig.r, 72), 0x2a0); b.set(le(sig.s, 72), 0x2e8); } else { b.set(f.sigR ?? fill(72, 1), 0x2a0); b.set(f.sigS ?? fill(72, 1), 0x2e8); }
  return b;
}
import { sha384 } from '@noble/hashes/sha2';
const PEM_LABEL = ['PRIVATE', 'KEY'].join(' '); // junk PEM label assembled at runtime
const R0 = mk();

// toHex / PEM
for (const [n, b] of [['empty', new Uint8Array(0)], ['all-bytes', Uint8Array.from({ length: 256 }, (_, i) => i)], ['single', Uint8Array.of(0x0a)], ['hi', Uint8Array.of(0xff, 0x00, 0x7f)]] as any[]) await add('toHex', n, [b]);
const C1 = '-----BEGIN CERTIFICATE-----\nMIIB\nAAAA\n-----END CERTIFICATE-----', C2 = '-----BEGIN CERTIFICATE-----\nZZZZ\n-----END CERTIFICATE-----';
for (const [n, p] of [['one', C1], ['two', C1 + '\n' + C2 + '\n'], ['junk-between', 'junk\n' + C1 + '\nmore junk\r\n' + C2 + '\ntrailing'], ['crlf', C1.replace(/\n/g, '\r\n') + '\r\n' + C2.replace(/\n/g, '\r\n')], ['empty', ''], ['no-cert', 'hello'], ['private-key-block', `-----BEGIN ${PEM_LABEL}-----\nAA\n-----END ${PEM_LABEL}-----`],
  ['unterminated', '-----BEGIN CERTIFICATE-----\nAAAA\n'], ['end-only', '-----END CERTIFICATE-----'], ['nested-begin', '-----BEGIN CERTIFICATE-----\nA\n-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----'], ['adjacent', C1 + C2], ['empty-body', '-----BEGIN CERTIFICATE----------END CERTIFICATE-----'], ['lowercase-label', '-----begin certificate-----\nAA\n-----end certificate-----'],
  ['trailing-spaces-marker', '-----BEGIN CERTIFICATE----- \nAA\n-----END CERTIFICATE----- '], ['unicode', 'ü\n' + C1 + '\n😀']] as any[]) await add('splitPemCertificates', n, [p]);

// parseReport
const FLD: [string, any][] = [['default', {}], ['v2', { version: 2 }], ['v0', { version: 0 }], ['maxes', { version: 0xffffffff, guest_svn: 0xffffffff, policy: 0xffffffffffffffffn, vmpl: 3, current_tcb: 0xffffffffffffffffn, platform_info: 0xffffffffffffffffn, reported_tcb: 0xffffffffffffffffn, committed_tcb: 0xffffffffffffffffn, launch_tcb: 0xffffffffffffffffn, fam: 255, mod: 255, step: 255 }],
  ['debug-policy', { policy: 0x80000n | 0x30000n }], ['algo-2', { algo: 2 }], ['vmpl-1', { vmpl: 1 }], ['zero-chip', { chip_id: fill(64, 0) }], ['unsigned', { sigR: fill(72, 0xff), sigS: fill(72, 0xee) }]];
for (const [n, f] of FLD) await add('parseReport', n, [mk(f, n === 'default' || !n.startsWith('unsigned'))]);
for (const [n, b] of [['too-short-0', new Uint8Array(0)], ['too-short-0x330', new Uint8Array(0x330)], ['min-len-0x330-1', new Uint8Array(0x32f)], ['min-len-0x330', R0.slice(0, 0x330)], ['truncated-sig-region', R0.slice(0, 0x400)], ['oversize', (() => { const x = new Uint8Array(0x4a0 + 64); x.set(R0); x.fill(7, 0x4a0); return x; })()], ['all-ones', fill(0x4a0, 0xff)], ['all-zero', new Uint8Array(0x4a0)]] as any[]) await add('parseReport', n, [b]);

// ecdsaP384PublicKey / signatureToCompact
for (const [n, k] of [['uncompressed', PK], ['compressed', PKC], ['other', PK2], ['empty', new Uint8Array(0)], ['short', PK.slice(0, 96)], ['long', new Uint8Array([...PK, 0])], ['off-curve', (() => { const x = PK.slice(); x[96] ^= 1; return x; })()], ['infinity-0x00', Uint8Array.of(0)], ['bad-prefix', (() => { const x = PK.slice(); x[0] = 5; return x; })()], ['x-over-p', new Uint8Array([4, ...fill(96, 0xff)])], ['hybrid-0x06', (() => { const x = PK.slice(); x[0] = 6; return x; })()]] as any[]) await add('ecdsaP384PublicKey', n, [k]);
const N = p384.CURVE.n; const sg = (r: bigint, s: bigint) => ({ r: le(r, 72), s: le(s, 72) });
for (const [n, r, s] of [['one-one', 1n, 1n], ['mid', 0x1234567890abcdefn, 0xfedcba0987654321n], ['n-1', N - 1n, N - 1n], ['r-zero', 0n, 5n], ['s-zero', 5n, 0n], ['r-n', N, 5n], ['s-n', 5n, N], ['r-n+1', N + 1n, 5n], ['both-big', (1n << 576n) - 1n, (1n << 576n) - 1n], ['high-bytes-beyond-48-matter', 5n | (1n << 400n), 7n]] as any[]) await add('signatureToCompact', n, [sg(r, s)]);
// verify
await add('verifyReportSignature', 'valid', [R0, PK]); await add('verifyReportSignature', 'valid-compressed-key', [R0, PKC]); await add('verifyReportSignature', 'wrong-key', [R0, PK2]); await add('verifyReportSignature', 'signed-with-other', [mk({}, true, sk2), PK]);
{ const t = R0.slice(); t[0x90] ^= 1; await add('verifyReportSignature', 'tampered-measurement', [t, PK]); const u = R0.slice(); u[0x2a0] ^= 1; await add('verifyReportSignature', 'tampered-r', [u, PK]); const w = R0.slice(); w[0x2e8 + 40] ^= 1; await add('verifyReportSignature', 'tampered-s', [w, PK]); const x = R0.slice(); x[0x2a0 + 60] = 1; await add('verifyReportSignature', 'r-high-bytes', [x, PK]); const y = R0.slice(); y[0x4a0 - 1] ^= 1; await add('verifyReportSignature', 'trailer-not-signed', [y, PK]); const z = R0.slice(); z[0x300] ^= 1; await add('verifyReportSignature', 'unsigned-trailer-bytes-ok', [z, PK]); }
await add('verifyReportSignature', 'zero-signature', [mk({ sigR: fill(72, 0), sigS: fill(72, 0) }, false), PK]); await add('verifyReportSignature', 'unsigned-garbage', [mk({}, false), PK]);
{ const hs = mk({}, true); const r = BigInt('0x' + [...hs.slice(0x2e8, 0x2e8 + 72)].reverse().map((x) => x.toString(16).padStart(2, '0')).join('')); const hi = mk({}, false); hi.set(hs.slice(0x2a0, 0x2a0 + 72), 0x2a0); hi.set(le(N - (r % N), 72), 0x2e8); await add('verifyReportSignature', 'high-s-form-of-signature', [hi, PK]); }
// policy
const P0 = {}; const CP = (n: string, p: any, f: any = {}) => add('checkPolicy', n, [mk(f, false), p]);
const M0 = hex(fill(48, 0x44)), HD = hex(fill(32, 0x55)), CH = hex(fill(64, 0xaa));
await CP('empty-policy', P0); await CP('algo-not-p384', P0, { algo: 2 }); await CP('algo-gate-off', { requireEcdsaP384: false }, { algo: 2 }); await CP('algo-gate-true', { requireEcdsaP384: true }, { algo: 2 }); await CP('algo-gate-undefined-explicit', { requireEcdsaP384: undefined }, { algo: 0 });
await CP('debug-denied', P0, { policy: 0x80000n }); await CP('debug-allowed', { allowDebug: true }, { policy: 0x80000n }); await CP('debug-allow-false', { allowDebug: false }, { policy: 0x80000n }); await CP('debug-allow-truthy-not-true', { allowDebug: 1 }, { policy: 0x80000n }); await CP('debug-bit-18-not-debug', P0, { policy: 0x40000n }); await CP('debug-bit-20-not-debug', P0, { policy: 0x100000n });
await CP('svn-ok', { minGuestSvn: 3 }); await CP('svn-below', { minGuestSvn: 4 }); await CP('svn-zero', { minGuestSvn: 0 }); await CP('svn-str-ignored', { minGuestSvn: '9' }); await CP('svn-nan', { minGuestSvn: { $num: 'NaN' } }); await CP('svn-neg', { minGuestSvn: -1 });
for (const [k, fk] of [['minReportedTcb', 'reported_tcb'], ['minCommittedTcb', 'committed_tcb'], ['minLaunchTcb', 'launch_tcb']] as any[]) { const V = 0x0807060504030201n; await CP(k + '-eq', { [k]: { $bigint: V.toString() } }); await CP(k + '-above', { [k]: { $bigint: (V + 1n).toString() } }); await CP(k + '-zero', { [k]: { $bigint: '0' } }); await CP(k + '-number-ignored', { [k]: 5 }); await CP(k + '-below-report', { [k]: { $bigint: '5' } }, { [fk]: 3n }); }
await CP('vmpl-default-0', P0, { vmpl: 0 }); await CP('vmpl-default-denies-1', P0, { vmpl: 1 }); await CP('vmpl-any', { requireVmpl: 'any' }, { vmpl: 3 }); await CP('vmpl-required-1', { requireVmpl: 1 }, { vmpl: 1 }); await CP('vmpl-required-mismatch', { requireVmpl: 2 }, { vmpl: 1 }); await CP('vmpl-str', { requireVmpl: '0' }, { vmpl: 0 }); await CP('vmpl-null', { requireVmpl: null }, { vmpl: 1 });
await CP('measurement-ok', { measurements: [M0] }); await CP('measurement-upper-ok', { measurements: [M0.toUpperCase()] }); await CP('measurement-bad', { measurements: ['00'.repeat(48)] }); await CP('measurement-empty-list-ungated', { measurements: [] }); await CP('measurement-one-of', { measurements: ['00'.repeat(48), M0] }); await CP('measurement-not-array', { measurements: M0 }); await CP('measurement-element-num', { measurements: [5] });
await CP('hostdata-ok', { hostData: [HD] }); await CP('hostdata-bad', { hostData: ['aa'.repeat(32)] }); await CP('hostdata-empty-list', { hostData: [] }); await CP('chip-ok', { chipIds: [CH] }); await CP('chip-bad', { chipIds: ['bb'.repeat(64)] }); await CP('chip-empty', { chipIds: [] });
await CP('order-algo-before-debug', P0, { algo: 3, policy: 0x80000n }); await CP('order-debug-before-svn', { minGuestSvn: 99 }, { policy: 0x80000n }); await CP('order-svn-before-tcb', { minGuestSvn: 99, minReportedTcb: { $bigint: '18446744073709551615' } }); await CP('order-tcb-before-vmpl', { minReportedTcb: { $bigint: '18446744073709551615' } }, { vmpl: 2 }); await CP('order-vmpl-before-measurement', { measurements: ['00'] }, { vmpl: 2 });
await CP('all-gates-ok', { measurements: [M0], hostData: [HD], chipIds: [CH], minGuestSvn: 1, minReportedTcb: { $bigint: '1' }, minCommittedTcb: { $bigint: '1' }, minLaunchTcb: { $bigint: '1' }, requireVmpl: 0 }); await CP('policy-null', null); await CP('policy-undefined-members', { measurements: undefined, hostData: undefined });
// identity
for (const [n, f] of [['default', {}], ['other-chip', { chip_id: Uint8Array.from({ length: 64 }, (_, i) => i) }], ['other-meas', { measurement: Uint8Array.from({ length: 48 }, (_, i) => 255 - i) }], ['host-data', { host_data: Uint8Array.from({ length: 32 }, (_, i) => i * 3) }]] as any[]) { await add('deriveIdentity', n + '/hostdata-true', [mk(f, false), true]); await add('deriveIdentity', n + '/hostdata-false', [mk(f, false), false]); }
// KDS fetch
const BODY = Uint8Array.from({ length: 40 }, (_, i) => i), CHIP = Uint8Array.from({ length: 64 }, (_, i) => i + 1);
const FV = (n: string, tcb: bigint, op: any, chip = CHIP) => add('fetchVcek', n, [chip, { $bigint: tcb.toString() }, { status: 200, body: BODY, ...op }]);
await FV('default-milan', 0x0807060504030201n, {}); await FV('genoa', 0x0807060504030201n, { product: 'Genoa' }); await FV('turin-base', 0n, { product: 'Turin', baseUrl: 'https://kds.example/vcek/v1' }); await FV('max-tcb', 0xffffffffffffffffn, {}); await FV('tcb-spread', 0xa1b2c3d4e5f60718n, {}); await FV('base-trailing-slash', 1n, { baseUrl: 'https://x.example/v1/' });
await FV('status-404', 1n, { status: 404 }); await FV('status-500', 1n, { status: 500 }); await FV('status-204-ok-empty', 1n, { status: 204, body: new Uint8Array(0) }); await FV('status-301', 1n, { status: 301 }); await FV('short-chip', 1n, {}, Uint8Array.of(1, 2, 3)); await FV('empty-chip', 1n, {}, new Uint8Array(0)); await FV('empty-product', 1n, { product: '' });
await FV('no-fetch-available', 1n, { noFetch: true });
// certificate helpers: forged P-384 leaves with the AMD VCEK extension profile (deterministic keys and RFC 6979 signatures)
{
  const FX: any = await import('../../../packages/pca/src/test-support/forge-x509.ts');
  const { extension, integer, seq, octets, oid, ctx, boolean: bool } = FX; const O = { hwid: '1.3.6.1.4.1.3704.1.4', bl: '1.3.6.1.4.1.3704.1.3.1', tee: '1.3.6.1.4.1.3704.1.3.2', snp: '1.3.6.1.4.1.3704.1.3.3', ucode: '1.3.6.1.4.1.3704.1.3.8' };
  const CHIPX = fill(64, 0xaa); // the default report: chip_id aa.., reported_tcb 0x0807060504030201 -> bootloader 1, tee 2, snp 7, microcode 8
  const amd = (v: any = {}, crit: any = {}) => [extension(O.bl, !!crit.bl, v.blRaw ?? integer(v.bl ?? 1)), extension(O.tee, !!crit.tee, v.teeRaw ?? integer(v.tee ?? 2)), extension(O.snp, !!crit.snp, v.snpRaw ?? integer(v.snp ?? 7)), extension(O.ucode, !!crit.ucode, v.ucodeRaw ?? integer(v.ucode ?? 8)), extension(O.hwid, !!crit.hwid, v.chip ?? CHIPX)];
  const cert = (extensions: Uint8Array[], curve = 'P-384') => FX.forgeCert({ subject: [['CN', 'SEV-VCEK']], issuer: [['CN', 'SEV-Milan']], subjectKey: FX.forgeKey('sevsnp-helpers/leaf', curve), signer: FX.forgeKey('sevsnp-helpers/issuer', 'P-384'), serial: 1n, notBefore: new Date('2022-01-01Z'), notAfter: new Date('2040-01-01Z'), extensions }).der as Uint8Array;
  const tbsOf = (extensions: Uint8Array[]) => H.extractTbsCertificate(cert(extensions)) as Uint8Array;
  const GOODC = cert(amd()), GOODT = tbsOf(amd());
  // extractTbsCertificate
  await add('extractTbsCertificate', 'vcek', [GOODC]); await add('extractTbsCertificate', 'no-extensions', [cert([])]); await add('extractTbsCertificate', 'p256-leaf', [cert(amd(), 'P-256')]);
  await add('extractTbsCertificate', 'empty', [new Uint8Array(0)]); await add('extractTbsCertificate', 'trailing-byte', [new Uint8Array([...GOODC, 0])]); await add('extractTbsCertificate', 'truncated', [GOODC.slice(0, GOODC.length - 1)]); await add('extractTbsCertificate', 'truncated-inside-tbs', [GOODC.slice(0, 40)]);
  await add('extractTbsCertificate', 'not-a-sequence', [(() => { const x = GOODC.slice(); x[0] = 0x31; return x; })()]); await add('extractTbsCertificate', 'inner-not-a-sequence', [seq(integer(5), integer(6))]); await add('extractTbsCertificate', 'empty-sequence', [seq()]);
  await add('extractTbsCertificate', 'minimal-nested', [seq(seq())]); await add('extractTbsCertificate', 'nested-with-rest', [seq(seq(integer(1)), octets(Uint8Array.of(9)))]); await add('extractTbsCertificate', 'indefinite-length', [Uint8Array.of(0x30, 0x80, 0x30, 0x00, 0x00, 0x00)]);
  await add('extractTbsCertificate', 'non-minimal-length', [Uint8Array.of(0x30, 0x81, 0x02, 0x30, 0x00)]); await add('extractTbsCertificate', 'length-overruns', [Uint8Array.of(0x30, 0x05, 0x30, 0x00)]); await add('extractTbsCertificate', 'pem-text', [new TextEncoder().encode('-----BEGIN CERTIFICATE-----')]);
  // extractVcekPublicKey
  await add('extractVcekPublicKey', 'vcek', [GOODC]); await add('extractVcekPublicKey', 'no-extensions', [cert([])]); await add('extractVcekPublicKey', 'p256-leaf-refused', [cert(amd(), 'P-256')]);
  await add('extractVcekPublicKey', 'empty', [new Uint8Array(0)]); await add('extractVcekPublicKey', 'garbage', [fill(64, 0x30)]); await add('extractVcekPublicKey', 'trailing-byte', [new Uint8Array([...GOODC, 0])]); await add('extractVcekPublicKey', 'truncated', [GOODC.slice(0, GOODC.length - 3)]);
  // checkVcekReportBinding
  const BIND = (n: string, t: Uint8Array, f: any = {}) => add('checkVcekReportBinding', n, [t, mk(f, false)]);
  await BIND('match', GOODT); await BIND('chip-mismatch', GOODT, { chip_id: fill(64, 0xab) }); await BIND('chip-last-byte', tbsOf(amd({ chip: (() => { const c = CHIPX.slice(); c[63] ^= 1; return c; })() })));
  await BIND('chip-63-bytes', tbsOf(amd({ chip: fill(63, 0xaa) }))); await BIND('chip-65-bytes', tbsOf(amd({ chip: fill(65, 0xaa) }))); await BIND('chip-empty', tbsOf(amd({ chip: new Uint8Array(0) }))); await BIND('chip-wrapped-in-octet-string', tbsOf(amd({ chip: octets(fill(62, 0xaa)) })));
  for (const k of ['bl', 'tee', 'snp', 'ucode']) { await BIND(k + '-mismatch', tbsOf(amd({ [k]: 9 }))); await BIND(k + '-critical', tbsOf(amd({}, { [k]: true }))); await BIND(k + '-missing', tbsOf(amd().filter((_, i) => i !== ['bl', 'tee', 'snp', 'ucode'].indexOf(k))));
    await BIND(k + '-not-integer', tbsOf(amd({ [k + 'Raw']: octets(Uint8Array.of(1)) }))); await BIND(k + '-negative', tbsOf(amd({ [k + 'Raw']: Uint8Array.of(0x02, 0x01, 0x80) }))); await BIND(k + '-non-minimal', tbsOf(amd({ [k + 'Raw']: Uint8Array.of(0x02, 0x02, 0x00, 0x01) })));
    await BIND(k + '-over-255', tbsOf(amd({ [k + 'Raw']: Uint8Array.of(0x02, 0x02, 0x01, 0x00) }))); await BIND(k + '-three-bytes', tbsOf(amd({ [k + 'Raw']: Uint8Array.of(0x02, 0x03, 0x00, 0x80, 0x00) }))); await BIND(k + '-empty-integer', tbsOf(amd({ [k + 'Raw']: Uint8Array.of(0x02, 0x00) })));
    await BIND(k + '-trailing', tbsOf(amd({ [k + 'Raw']: Uint8Array.of(0x02, 0x01, 0x01, 0x00) }))); await BIND(k + '-empty-value', tbsOf(amd({ [k + 'Raw']: new Uint8Array(0) }))); }
  await BIND('hwid-critical', tbsOf(amd({}, { hwid: true }))); await BIND('hwid-missing', tbsOf(amd().slice(0, 4))); await BIND('no-extensions', tbsOf([])); await BIND('unrelated-extension-only', tbsOf([FX.ext.basicConstraints(true, 0)]));
  await BIND('extra-extensions-ok', tbsOf([FX.ext.basicConstraints(false), ...amd(), FX.ext.subjectKeyId(FX.forgeKey('sevsnp-helpers/leaf', 'P-384'))])); await BIND('reordered-ok', tbsOf(amd().reverse()));
  // SPL values 128..255 take the 0x00 sign pad; TCB bytes 2..5 are not bound
  await BIND('spl-high-values', tbsOf(amd({ bl: 0x80, tee: 0xff, snp: 0xc8, ucode: 0x81 })), { reported_tcb: 0x81c80000_0000ff80n }); await BIND('spl-zero', tbsOf(amd({ bl: 0, tee: 0, snp: 0, ucode: 0 })), { reported_tcb: 0n });
  await BIND('middle-tcb-bytes-ignored', GOODT, { reported_tcb: 0x0807ffffffff0201n }); await BIND('committed-tcb-not-bound', GOODT, { committed_tcb: 0n, launch_tcb: 0n, current_tcb: 0n });
  await BIND('order-hwid-before-spl', tbsOf(amd({ bl: 9, chip: fill(64, 1) }))); await BIND('order-bl-before-tee', tbsOf(amd({ bl: 9, tee: 9 }))); await BIND('order-snp-before-ucode', tbsOf(amd({ snp: 9, ucode: 9 })));
  await BIND('duplicate-extension', tbsOf([...amd(), extension(O.bl, false, integer(1))])); await BIND('critical-flag-false-encoded', tbsOf([seq(oid(O.bl), Uint8Array.of(0x01, 0x01, 0x00), octets(integer(1))), ...amd().slice(1)]));
  await BIND('value-not-octet-string', tbsOf([seq(oid(O.bl), integer(1)), ...amd().slice(1)])); await BIND('tbs-empty', new Uint8Array(0)); await BIND('tbs-trailing', new Uint8Array([...GOODT, 0])); await BIND('tbs-not-sequence', octets(GOODT));
  await BIND('whole-certificate-instead-of-tbs', GOODC); await BIND('empty-extensions-sequence', seq(integer(1), ctx(3, seq()))); await BIND('two-extension-blocks', seq(ctx(3, seq(...amd())), ctx(3, seq(...amd())))); await BIND('extensions-not-last', seq(ctx(3, seq(...amd())), integer(1)));
  await BIND('bare-tbs-with-only-extensions', seq(ctx(3, seq(...amd())))); void bool;
}
await add('constants', 'all', []);
refWrite(o, 'sevsnp-helpers');
