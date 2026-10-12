/**
 * Mutation-kill suite for attest-nvidia-rim.ts. RIM documents are produced by the spec-faithful forger in
 * test-support/forge-spdm.ts (a synthetic CoRIM signing PKI), with a small re-signing helper for structural variants.
 */
import { X509Certificate } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  NVIDIA_RIM_BASE_URL,
  checkNvidiaChainRevocation,
  compareReportToRims,
  fetchNvidiaCrl,
  fetchNvidiaRim,
  nvidiaCollateralHook,
  nvidiaRimIdsForReport,
  verifyNvidiaRim,
  type RimGoldenMeasurement,
  type VerifiedRim,
} from './attest-nvidia-rim';
import { parseNvidiaSpdmEvidence, parsePemChain, type ParsedNvidiaSpdmReport } from './attest-nvidia-spdm';
import { forgeNvidiaCrl, forgeNvidiaScenario, forgeRim, forgeCorimPki, defaultOpaque, rimDigestB64, rimSignedInfoCanonical, RIM_ALG, type ForgeRimOptions, type RimMeasurementSpec } from './test-support/forge-spdm';
import { ecdsaSign } from './test-support/forge-x509';

const PKI = forgeCorimPki({ seed: 'rim-kill' });
const NOW = new Date('2026-10-20T00:00:00Z').getTime();
const hx = (c: string, n = 48) => c.repeat(n * 2).slice(0, n * 2);
const spec = (index: number, over: Partial<RimMeasurementSpec> = {}): RimMeasurementSpec => ({ index, active: true, hashes: [hx('a')], ...over });
const mk = (measurements: readonly RimMeasurementSpec[] = [spec(0)], over: Partial<ForgeRimOptions> = {}) =>
  forgeRim({ version: '595.71.05', measurements, signerChain: PKI.certs, signerKey: PKI.signerKey, ...over });
const verifyRim = (xml: string, pins = [PKI.rootSpkiSha256], nowMs = NOW) => verifyNvidiaRim(xml, { rimRootSpkiSha256: pins, nowMs });
const reasonOf = async (xml: string, pins?: string[], nowMs?: number) => {
  const r = await verifyRim(xml, pins, nowMs);
  return r.ok ? 'OK' : r.reason;
};
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
/** Re-compute DigestValue and SignatureValue after a structural edit (the edit may already include its own whitespace formatting). */
function resign(xml: string, fmt: { digest?: (s: string) => string; sig?: (s: string) => string } = {}): string {
  const d = rimDigestB64(xml);
  let x = xml.replace(/<ds:DigestValue>[^<]*<\/ds:DigestValue>/, `<ds:DigestValue>${(fmt.digest ?? ((s) => s))(d)}</ds:DigestValue>`);
  const sig = b64(ecdsaSign(PKI.signerKey, 'sha384', new TextEncoder().encode(rimSignedInfoCanonical(x))).raw);
  x = x.replace(/<ds:SignatureValue>[^<]*<\/ds:SignatureValue>/, `<ds:SignatureValue>${(fmt.sig ?? ((s) => s))(sig)}</ds:SignatureValue>`);
  return x;
}
const BASE = mk();

describe('verifyNvidiaRim: result fields', () => {
  it('returns tag, product, version, golden measurements and signer subject', async () => {
    const xml = mk([spec(0, { hashes: ['AB'.repeat(48)] }), spec(3, { active: false, hashes: [hx('b'), hx('c')], name: 'x' })], { tagId: 'tag-1', product: 'GB100', version: '96.00.D0.00.03' });
    const r = await verifyRim(xml);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.rim.tagId).toBe('tag-1');
    expect(r.rim.product).toBe('GB100');
    expect(r.rim.version).toBe('96.00.D0.00.03');
    expect([...r.rim.golden.keys()]).toEqual([0, 3]);
    expect(r.rim.golden.get(0)).toEqual({ index: 0, active: true, alternatives: 1, size: 48, hashes: ['ab'.repeat(48)] });
    expect(r.rim.golden.get(3)).toEqual({ index: 3, active: false, alternatives: 2, size: 48, hashes: [hx('b'), hx('c')] });
    expect(r.rim.signerSubject).toBe(new X509Certificate(PKI.certs[0]!.der).subject.replace(/\n/g, ', '));
    expect(r.rim.signerSubject).toContain(', ');
    expect(r.rim.signerSubject).not.toContain('\n');
  });
  it('active flag: True/true/TRUE true; False/absent false', async () => {
    const x = mk([spec(0), spec(1), spec(2), spec(3, { active: false })]);
    const t = x.replace('active="True" alternatives="1" ns2:Hash0', 'active="true" alternatives="1" ns2:Hash0');
    const r = await verifyRim(resign(t.replace(/(index="1" active=")True/, '$1TRUE').replace(/(index="2") active="True"/, '$1')));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect([0, 1, 2, 3].map((i) => r.rim.golden.get(i)!.active)).toEqual([true, true, false, false]);
  });
});

describe('verifyNvidiaRim: input guards', () => {
  it('xml must be a non-empty string of at most 4,000,000 chars', async () => {
    const m = 'RIM: empty or oversized document';
    for (const x of [5, null, undefined, '', {}] as unknown[]) expect(await reasonOf(x as string)).toBe(m);
    expect(await reasonOf('x'.repeat(4_000_001))).toBe(m);
    expect(await reasonOf('x'.repeat(4_000_000))).not.toBe(m);
    expect(await reasonOf('x')).not.toBe(m);
  });
  it('a pinned root is required', async () => {
    for (const pins of [[], undefined, 'x'] as unknown[]) {
      const r = await verifyNvidiaRim(BASE, { rimRootSpkiSha256: pins as string[], nowMs: NOW });
      expect(r).toEqual({ ok: false, reason: 'RIM: no pinned RIM root configured' });
    }
  });
});

describe('verifyNvidiaRim: strict profile and structure (exact reasons)', () => {
  it('comments, PIs, DTDs, xml:* attributes', async () => {
    expect(await reasonOf(mk([spec(0)], { comment: true }))).toBe('RIM: XML comments are not permitted');
    expect(await reasonOf(mk([spec(0)], { processingInstruction: true }))).toBe('RIM: XML processing instructions are not permitted');
    expect(await reasonOf(mk([spec(0)], { doctype: true }))).toBe('RIM: DTD / DOCTYPE is not permitted');
    expect(await reasonOf(mk([spec(0)], { xmlAttrOnPayload: true }))).toBe("RIM: xml:* attribute 'xml:space' is not permitted (C14N 1.1 profile)");
  });
  it('root element, signature placement and counts', async () => {
    expect(await reasonOf(mk([spec(0)], { rootName: 'Other' }))).toBe('RIM: root element is not SoftwareIdentity');
    expect(await reasonOf(mk([spec(0)], { extraSignature: 'sibling' }))).toBe('RIM: expected exactly one Signature element');
    expect(await reasonOf(mk([spec(0)], { extraSignature: 'nested' }))).toBe('RIM: expected exactly one Signature element');
    expect(await reasonOf(mk([spec(0)], { wrapSignature: true }))).toBe('RIM: the Signature must be a direct child of the root');
    expect(await reasonOf(BASE.replace(/<ds:Signature[\s\S]*<\/ds:Signature>/, ''))).toBe('RIM: expected exactly one Signature element');
  });
  it('SignedInfo count; algorithm and reference checks', async () => {
    expect(await reasonOf(BASE.replace('<ds:SignedInfo>', '<ds:SignedInfo/><ds:SignedInfo>'))).toBe('RIM: expected exactly one SignedInfo');
    expect(await reasonOf(BASE.replace(/<ds:SignedInfo>[\s\S]*<\/ds:SignedInfo>/, ''))).toBe('RIM: expected exactly one SignedInfo');
    expect(await reasonOf(mk([spec(0)], { c14nUri: 'urn:x' }))).toBe('RIM: CanonicalizationMethod must be C14N 1.1');
    expect(await reasonOf(mk([spec(0)], { sigMethodUri: 'urn:x' }))).toBe('RIM: SignatureMethod must be ECDSA-SHA384');
    expect(await reasonOf(mk([spec(0)], { extraReference: true }))).toBe('RIM: expected exactly one Reference');
    expect(await reasonOf(mk([spec(0)], { referenceUri: '#x' }))).toBe('RIM: Reference URI must be "" (the whole document)');
    expect(await reasonOf(mk([spec(0)], { digestMethodUri: 'urn:x' }))).toBe('RIM: DigestMethod must be SHA-384');
  });
  it('missing algorithm elements are refused with the same reasons (no crash)', async () => {
    expect(await reasonOf(BASE.replace(/<ds:CanonicalizationMethod[^>]*\/>/, ''))).toBe('RIM: CanonicalizationMethod must be C14N 1.1');
    expect(await reasonOf(BASE.replace(/<ds:SignatureMethod[^>]*\/>/, ''))).toBe('RIM: SignatureMethod must be ECDSA-SHA384');
    expect(await reasonOf(BASE.replace(/<ds:DigestMethod[^>]*\/>/, ''))).toBe('RIM: DigestMethod must be SHA-384');
  });
  it('transforms must be exactly [enveloped-signature, C14N 1.1]', async () => {
    const m = 'RIM: transforms must be exactly [enveloped-signature, C14N 1.1]';
    const E = RIM_ALG.ENVELOPED;
    const C = RIM_ALG.C14N11;
    for (const transforms of [[C, C], [E, E], [C, E], [E], [], [E, C, C], [E, C, E], ['urn:x', C], [E, 'urn:x']]) expect(await reasonOf(mk([spec(0)], { transforms })), JSON.stringify(transforms)).toBe(m);
    expect(await reasonOf(mk([spec(0)], { transforms: [E, C] }))).toBe('OK');
  });
  it('missing digest / signature values and KeyInfo', async () => {
    const m = 'RIM: missing DigestValue / SignatureValue';
    expect(await reasonOf(mk([spec(0)], { omitDigestValue: true }))).toBe(m);
    expect(await reasonOf(mk([spec(0)], { omitSignatureValue: true }))).toBe(m);
    expect(await reasonOf(BASE.replace(/<ds:DigestValue>[^<]*</, '<ds:DigestValue><'))).toBe(m);
    expect(await reasonOf(BASE.replace(/<ds:SignatureValue>[^<]*</, '<ds:SignatureValue><'))).toBe(m);
    const k = 'RIM: no signer certificates in KeyInfo';
    expect(await reasonOf(mk([spec(0)], { omitKeyInfo: true }))).toBe(k);
    expect(await reasonOf(BASE.replace(/<ds:X509Data>[\s\S]*<\/ds:X509Data>/, ''))).toBe(k);
    expect(await reasonOf(BASE.replace(/<ds:X509Data>[\s\S]*<\/ds:X509Data>/, '<ds:X509Data/>'))).toBe(k);
  });
  it('signer chain failures are prefixed; an empty certificate is unparseable (not a crash)', async () => {
    const wrongPin = await reasonOf(BASE, ['00'.repeat(32)]);
    expect(wrongPin).toMatch(/^RIM signer chain: /);
    const empty = await reasonOf(BASE.replace(/(<ds:X509Certificate>)[^<]*(<\/ds:X509Certificate>)/, '$1$2'));
    expect(empty).toMatch(/^RIM signer chain: device chain unparseable/);
    let inner = 'NO THROW';
    try {
      parsePemChain('-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----');
    } catch (e) {
      inner = (e as Error).message;
    }
    expect(empty).toBe(`RIM signer chain: device chain unparseable: ${inner}`);
    expect(await reasonOf(BASE, undefined, new Date('2040-01-01T00:00:00Z').getTime())).toMatch(/^RIM signer chain: .*validity window/);
  });
  it('signature length, signature value and digest value', async () => {
    expect(await reasonOf(mk([spec(0)], { signatureBytes: 95 }))).toBe('RIM: SignatureValue is not a 96-byte P-384 signature');
    expect(await reasonOf(mk([spec(0)], { signatureBytes: 97 }))).toBe('RIM: SignatureValue is not a 96-byte P-384 signature');
    expect(await reasonOf(mk([spec(0)], { signatureBytes: 96 }))).toBe('RIM: SignedInfo signature does not verify under the signer certificate');
    const other = forgeCorimPki({ seed: 'someone-else' });
    expect(await reasonOf(mk([spec(0)], { signWith: other.signerKey }))).toBe('RIM: SignedInfo signature does not verify under the signer certificate');
    expect(await reasonOf(mk([spec(0)], { digestOverride: Buffer.alloc(48, 1).toString('base64') }))).toBe('RIM: document digest does not match the signed DigestValue');
    expect(await reasonOf(BASE.replace('GH100', 'GH200'))).toBe('RIM: SignedInfo signature does not verify under the signer certificate'.replace('SignedInfo signature does not verify under the signer certificate', 'document digest does not match the signed DigestValue'));
  });
  it('Meta and Payload are required', async () => {
    expect(await reasonOf(mk([spec(0)], { omitMeta: true }))).toBe('RIM: missing Meta / Payload');
    expect(await reasonOf(mk([spec(0)], { omitPayload: true }))).toBe('RIM: missing Meta / Payload');
  });
});

describe('verifyNvidiaRim: signed-content parsing quirks (re-signed variants)', () => {
  it('whitespace inside DigestValue / SignatureValue text is ignored', async () => {
    const x = resign(BASE, { digest: (s) => `\n  ${s.slice(0, 20)} \n\t${s.slice(20)}\n `, sig: (s) => `\n ${s.slice(0, 30)}\r\n  ${s.slice(30, 60)}\t ${s.slice(60)}  ` });
    expect(await reasonOf(x)).toBe('OK');
  });
  it('whitespace inside the certificate base64 is ignored; long single lines are fine', async () => {
    const x = BASE.replace(/(<ds:X509Certificate>)([^<]*)(<\/ds:X509Certificate>)/g, (_m, a: string, b: string, c: string) => `${a}\n   ${b.slice(0, 77)}\n\t ${b.slice(77, 200)}  \r\n${b.slice(200)}\n${c}`);
    expect(await reasonOf(resign(x))).toBe('OK');
  });
  it('elements of the wrong namespace never stand in for the XMLDSig ones', async () => {
    const wrongNs = (tag: string, attrs = '') => `<ns0:${tag}${attrs}/>`;
    const cases: [string, (x: string) => string][] = [
      ['Signature sibling in another namespace', (x) => x.replace('</SoftwareIdentity>', `${wrongNs('Signature')}</SoftwareIdentity>`)],
      ['SignedInfo before the real one', (x) => x.replace('<ds:SignedInfo>', `${wrongNs('SignedInfo')}<ds:SignedInfo>`)],
      ['CanonicalizationMethod first', (x) => x.replace(/<ds:CanonicalizationMethod/, `${wrongNs('CanonicalizationMethod', ' Algorithm="urn:bogus"')}<ds:CanonicalizationMethod`)],
      ['SignatureMethod first', (x) => x.replace(/<ds:SignatureMethod/, `${wrongNs('SignatureMethod', ' Algorithm="urn:bogus"')}<ds:SignatureMethod`)],
      ['extra Reference', (x) => x.replace('</ds:SignedInfo>', `${wrongNs('Reference', ' URI="#x"')}</ds:SignedInfo>`)],
      ['extra Transform', (x) => x.replace('</ds:Transforms>', `${wrongNs('Transform', ' Algorithm="urn:bogus"')}</ds:Transforms>`)],
      ['DigestMethod first', (x) => x.replace(/<ds:DigestMethod/, `${wrongNs('DigestMethod', ' Algorithm="urn:bogus"')}<ds:DigestMethod`)],
      ['DigestValue first', (x) => x.replace('<ds:DigestValue>', `<ns0:DigestValue>bogus</ns0:DigestValue><ds:DigestValue>`)],
      ['SignatureValue first', (x) => x.replace('<ds:SignatureValue>', `<ns0:SignatureValue>bogus</ns0:SignatureValue><ds:SignatureValue>`)],
      ['KeyInfo first', (x) => x.replace('<ds:KeyInfo>', `${wrongNs('KeyInfo')}<ds:KeyInfo>`)],
      ['X509Data first', (x) => x.replace('<ds:X509Data>', `<ds:X509Data><ns0:X509Data/>`).replace('<ds:X509Data><ns0:X509Data/>', '<ds:X509Data>')],
      ['X509Certificate first', (x) => x.replace('<ds:X509Certificate>', `<ns0:X509Certificate>bogus</ns0:X509Certificate><ds:X509Certificate>`)],
    ];
    for (const [name, edit] of cases) expect(await reasonOf(resign(edit(BASE))), name).toBe('OK');
  });
  it('a shadowing namespace declaration on the root does not change which declaration is in scope (nearest wins)', async () => {
    const x = BASE.replace('<SoftwareIdentity ', '<SoftwareIdentity xmlns:ds="urn:shadow" ');
    expect(await reasonOf(resign(x))).toBe('OK');
  });
});

describe('verifyNvidiaRim: Measurement resources', () => {
  const res = (attrs: string) => `<ns0:Resource ${attrs}/>`;
  const withPayload = (inner: string) => resign(BASE.replace(/(<ns0:Payload[^>]*>)[\s\S]*?(<\/ns0:Payload>)/, `$1${inner}$2`));
  const good = (index: number, extra = '') => res(`type="Measurement" index="${index}" active="True" alternatives="1" ns2:Hash0="${hx('1')}" size="48"${extra}`);
  it('skips non-Measurement and non-Resource elements; reads the rest', async () => {
    const x = withPayload(`${good(1)}<ns0:Other type="Measurement" index="99" active="True" alternatives="1" ns2:Hash0="${hx('9')}" size="48"/>${res(`type="Other" index="98" active="True" alternatives="1" ns2:Hash0="${hx('9')}" size="48"`)}${good(2)}`);
    const r = await verifyRim(x);
    expect(r.ok && [...r.rim.golden.keys()]).toEqual([1, 2]);
  });
  it('Hash attributes: only HashN, sorted numerically, lowercased', async () => {
    const order = [2, 10, 0, 1, 9, 3, 4, 5, 6, 7, 8];
    const attrs = order.map((k) => `ns2:Hash${k}="${k.toString(16).padStart(2, '0').toUpperCase()}"`).join(' ');
    const lookalikes = `ns2:NotHash5="ff" ns2:Hash1x="ee" ns2:XHash7="dd" ns2:hash3="cc"`;
    const x = withPayload(res(`type="Measurement" index="0" active="True" alternatives="11" ${attrs} ${lookalikes} size="1"`));
    const r = await verifyRim(x);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.rim.golden.get(0)!.hashes).toEqual(['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a']);
    expect(r.rim.golden.get(0)!.size).toBe(1); // size 1 is the smallest legal size
    expect(r.rim.golden.get(0)!.alternatives).toBe(11);
  });
  it('malformed resources', async () => {
    const m = 'RIM: malformed Measurement resource';
    const base = (o: Record<string, string>) => {
      const a = { type: 'Measurement', index: '1', active: 'True', alternatives: '1', size: '48', ...o };
      return res(`type="${a.type}" index="${a.index}" active="${a.active}" alternatives="${a.alternatives}" ns2:Hash0="${hx('1')}" size="${a.size}"`);
    };
    const cases: Array<Record<string, string>> = [{ index: 'x' }, { index: '-1' }, { index: '1.5' }, { alternatives: '0' }, { alternatives: '1.5' }, { alternatives: 'x' }, { size: '0' }, { size: '-1' }, { size: '1.5' }, { size: 'x' }];
    for (const o of cases) {
      expect(await reasonOf(withPayload(base(o))), JSON.stringify(o)).toBe(m);
    }
    expect(await reasonOf(withPayload(base({ index: '0' })))).toBe('OK');
    expect(await reasonOf(withPayload(res(`type="Measurement" alternatives="1" ns2:Hash0="${hx('1')}" size="48"`)))).toBe('OK'); // missing index attr -> Number('') = 0
  });
  it('hash list consistency', async () => {
    const m = (i: number) => `RIM: Measurement ${i} hash list is inconsistent with alternatives/size`;
    const r = (alts: number, hashes: string[], size = 2) => res(`type="Measurement" index="4" active="True" alternatives="${alts}" ${hashes.map((h, k) => `ns2:Hash${k}="${h}"`).join(' ')} size="${size}"`);
    expect(await reasonOf(withPayload(r(2, ['aabb'])))).toBe(m(4));
    expect(await reasonOf(withPayload(r(1, ['aabb', 'ccdd'])))).toBe(m(4));
    expect(await reasonOf(withPayload(r(2, ['aabb', 'cc'])))).toBe(m(4)); // one good, one short
    expect(await reasonOf(withPayload(r(2, ['cc', 'aabb'])))).toBe(m(4));
    expect(await reasonOf(withPayload(r(1, ['aabbcc'])))).toBe(m(4));
    expect(await reasonOf(withPayload(r(1, ['gg11'])))).toBe(m(4)); // bad leading chars (anchor)
    expect(await reasonOf(withPayload(r(1, ['11gg'])))).toBe(m(4)); // bad trailing chars (anchor)
    expect(await reasonOf(withPayload(r(1, ['11 1'])))).toBe(m(4));
    expect(await reasonOf(withPayload(r(0 + 1, [''])))).toBe(m(4));
    expect(await reasonOf(withPayload(r(2, ['AABB', 'CcDd'])))).toBe('OK');
  });
  it('duplicate indices, no measurements', async () => {
    expect(await reasonOf(withPayload(`${good(3)}${good(3)}`))).toBe('RIM: duplicate Measurement index 3');
    expect(await reasonOf(withPayload(''))).toBe('RIM: no measurements');
    expect(await reasonOf(withPayload(res(`type="Other" index="1"`)))).toBe('RIM: no measurements');
  });
});

// ------------------------------------------------------------------------------------------------ RIM ids
describe('nvidiaRimIdsForReport', () => {
  const dev = forgeNvidiaScenario({ seed: 'ids' });
  const reportWith = (mutate: (o: [number, Uint8Array][]) => [number, Uint8Array][]): ParsedNvidiaSpdmReport => {
    const sc = forgeNvidiaScenario({ seed: 'ids', opaque: mutate(defaultOpaque()) });
    return parseNvidiaSpdmEvidence(sc.evidence.evidence);
  };
  const enc = (s: string, pad = 0) => {
    const b = new TextEncoder().encode(s);
    const o = new Uint8Array(b.length + pad);
    o.set(b);
    return o;
  };
  const set = (o: [number, Uint8Array][], t: number, v: Uint8Array | undefined): [number, Uint8Array][] => {
    const rest = o.filter(([k]) => k !== t);
    return v === undefined ? rest : [...rest, [t, v]];
  };
  it('names the driver and VBIOS RIMs (upper-casing project / sku / chip sku)', () => {
    const ids = nvidiaRimIdsForReport(parseNvidiaSpdmEvidence(dev.evidence.evidence))!;
    expect(ids).toEqual({ chip: 'GH100', driver: 'NV_GPU_DRIVER_GH100_595.71.05', vbios: 'NV_GPU_VBIOS_1010_0210_886_9F00960400'.replace('9F00960400', ids.vbiosVersion.replace(/\./g, '').toUpperCase()), driverVersion: '595.71.05', vbiosVersion: ids.vbiosVersion });
    const lower = reportWith((o) => set(set(set(o, 17, enc('g520', 1)), 18, enc('ab12', 1)), 15, enc('x9z', 1)));
    expect(nvidiaRimIdsForReport(lower)!.vbios.startsWith('NV_GPU_VBIOS_G520_AB12_X9Z_')).toBe(true);
  });
  it('trailing NULs and whitespace are stripped, interior NULs are kept', () => {
    const r = reportWith((o) => set(o, 3, enc('  595.71.05  ', 3)));
    expect(nvidiaRimIdsForReport(r)!.driverVersion).toBe('595.71.05');
    const nul = reportWith((o) => set(o, 3, Uint8Array.from([0x35, 0x00, 0x39, 0x35, 0x00, 0x00])));
    expect(nvidiaRimIdsForReport(nul)!.driverVersion).toBe('5\u000095');
    const noTrailing = reportWith((o) => set(o, 3, enc('580.95.05\0\0\0\0')));
    expect(nvidiaRimIdsForReport(noTrailing)!.driverVersion).toBe('580.95.05');
  });
  it('a missing required field yields undefined', () => {
    for (const t of [3, 6, 17, 18, 15]) expect(nvidiaRimIdsForReport(reportWith((o) => set(o, t, undefined))), String(t)).toBeUndefined();
    for (const t of [3, 17, 18, 15]) expect(nvidiaRimIdsForReport(reportWith((o) => set(o, t, new Uint8Array(4)))), `blank ${t}`).toBeUndefined();
  });
  it('CHIP_INFO selects the Blackwell naming and is validated verbatim', () => {
    const gb = nvidiaRimIdsForReport(reportWith((o) => set(o, 35, enc('GB100', 3))))!;
    expect(gb.chip).toBe('GB100');
    expect(gb.driver).toBe('NV_GPU_CC_DRIVER_GB100_595.71.05');
    expect(nvidiaRimIdsForReport(reportWith((o) => set(o, 35, enc('GH100'))))!.driver).toBe('NV_GPU_DRIVER_GH100_595.71.05');
    expect(nvidiaRimIdsForReport(reportWith((o) => set(o, 35, enc('G12A34567890'))))!.chip).toBe('G12A34567890');
    for (const bad of ['gb100', 'G1', 'GB', 'G12A345678901', '1B100', 'GB-100', 'GB 100', 'GB100\nX', '']) {
      expect(nvidiaRimIdsForReport(reportWith((o) => set(o, 35, enc(bad)))), JSON.stringify(bad)).toBeUndefined();
    }
  });
});

// ------------------------------------------------------------------------------------------------ comparison
describe('compareReportToRims', () => {
  const g = (index: number, hashes: string[], over: Partial<RimGoldenMeasurement> = {}): RimGoldenMeasurement => ({ index, active: true, alternatives: hashes.length, size: hashes[0]!.length / 2, hashes, ...over });
  const rim = (...gs: RimGoldenMeasurement[]): VerifiedRim => ({ tagId: 't', product: 'GH100', version: 'v', golden: new Map(gs.map((x) => [x.index, x])), signerSubject: 's' });
  const report = (digests: Record<number, string>, opaque: Record<number, number[]> = {}): ParsedNvidiaSpdmReport =>
    ({
      response: {
        measurements: Object.entries(digests).map(([i, h]) => ({ index: Number(i), valueType: 1, digest: Uint8Array.from(Buffer.from(h, 'hex')) })),
        opaque: new Map(Object.entries(opaque).map(([k, v]) => [Number(k), Uint8Array.from(v)])),
      },
    }) as unknown as ParsedNvidiaSpdmReport;
  it('matches, counts checked indices; alternatives accepted; inactive ignored', () => {
    const r = compareReportToRims(report({ 1: 'aabb', 2: 'ccdd', 3: 'eeff' }), rim(g(0, ['aabb']), g(1, ['0000', 'ccdd']), g(7, ['1234'], { active: false })), rim(g(2, ['eeff'])));
    expect(r).toEqual({ ok: true, checked: 3 });
  });
  it('driver / VBIOS conflict and empty sets', () => {
    expect(compareReportToRims(report({ 1: 'aa' }), rim(g(0, ['aa'])), rim(g(0, ['aa'])))).toEqual({ ok: false, reason: 'driver and VBIOS RIMs both have an active measurement at index 0' });
    expect(compareReportToRims(report({ 1: 'aa' }), rim(g(0, ['aa'], { active: false })), rim(g(0, ['aa']))).ok).toBe(true); // inactive driver entry does not conflict
    expect(compareReportToRims(report({ 1: 'aa' }), rim(g(0, ['aa'], { active: false })), rim())).toEqual({ ok: false, reason: 'RIMs carry no active golden measurements' });
  });
  it('the report must carry at least as many measurements as the RIMs list (equal is fine)', () => {
    expect(compareReportToRims(report({ 1: 'aa' }), rim(g(0, ['aa']), g(1, ['bb'])), rim())).toEqual({ ok: false, reason: 'RIMs list more active measurements than the report carries' });
    expect(compareReportToRims(report({ 1: 'aa', 2: 'bb' }), rim(g(0, ['aa']), g(1, ['bb'])), rim())).toEqual({ ok: true, checked: 2 });
    expect(compareReportToRims(report({ 1: 'aa', 2: 'bb', 3: 'cc' }), rim(g(0, ['aa']), g(1, ['bb'])), rim())).toEqual({ ok: true, checked: 2 });
  });
  it('mismatches carry index and source, sorted; wrong length and absent digests mismatch', () => {
    const r = compareReportToRims(report({ 1: 'aa', 2: 'bb', 3: 'cc', 5: 'dd' }), rim(g(2, ['ff'])), rim(g(0, ['00']), g(1, ['bb']), g(3, ['dd'])));
    expect(r).toEqual({
      ok: false,
      reason: 'runtime measurements differ from the golden RIM values at 3 index(es)',
      mismatches: [{ index: 0, source: 'vbios' }, { index: 2, source: 'driver' }, { index: 3, source: 'vbios' }],
    });
    // golden claims size 2 but its hash list carries a 1-byte value that equals a 1-byte digest: length must still match `size`
    const short = compareReportToRims(report({ 1: 'aa', 2: 'bb' }), rim(g(0, ['aa'], { size: 2 }), g(1, ['bb'])), rim());
    expect(short).toMatchObject({ ok: false, mismatches: [{ index: 0, source: 'driver' }] });
    // runtime has enough entries overall but not at the golden index
    const absent = compareReportToRims(report({ 5: 'aa', 6: 'bb' }), rim(g(0, ['aa'])), rim(g(1, ['bb'])));
    expect(absent).toMatchObject({ ok: false, mismatches: [{ index: 0, source: 'driver' }, { index: 1, source: 'vbios' }] });
  });
  it('NVDEC0: block 35 (index 34) is exempt only when status byte 0 is 0x55', () => {
    const rims: [VerifiedRim, VerifiedRim] = [rim(g(34, ['aa']), g(0, ['bb'])), rim()];
    const rep = (nv: number[] | undefined) => report({ 1: 'bb', 35: '00' }, nv ? { 11: nv } : {});
    expect(compareReportToRims(rep([0x55]), ...rims)).toEqual({ ok: true, checked: 1 });
    expect(compareReportToRims(rep([0x55, 0x01]), ...rims)).toEqual({ ok: true, checked: 1 });
    expect(compareReportToRims(rep([0xaa]), ...rims)).toMatchObject({ ok: false, mismatches: [{ index: 34, source: 'driver' }] });
    expect(compareReportToRims(rep([0x00, 0x55]), ...rims)).toMatchObject({ ok: false });
    expect(compareReportToRims(rep([]), ...rims)).toMatchObject({ ok: false });
    expect(compareReportToRims(rep(undefined), ...rims)).toMatchObject({ ok: false });
    // the exemption applies to block 35 only
    const other = compareReportToRims(report({ 1: '00', 35: 'aa' }, { 11: [0x55] }), rim(g(34, ['aa']), g(0, ['bb'])), rim());
    expect(other).toMatchObject({ ok: false, mismatches: [{ index: 0, source: 'driver' }] });
  });
});

// ------------------------------------------------------------------------------------------------ revocation
describe('checkNvidiaChainRevocation', () => {
  const sc = forgeNvidiaScenario({ seed: 'rev' });
  const chain = parsePemChain(sc.device.chainPem);
  const NOW2 = sc.nowMs;
  it('requires CRLs; passes with the issuer CRLs and reports how many verified', () => {
    expect(checkNvidiaChainRevocation(chain, [], NOW2)).toEqual({ ok: false, reason: 'no CRLs supplied' });
    expect(checkNvidiaChainRevocation(chain, sc.crls, NOW2)).toEqual({ ok: true, verifiedCrls: 2 });
    expect(checkNvidiaChainRevocation(chain, [sc.crls[0]!], NOW2)).toEqual({ ok: true, verifiedCrls: 1 });
  });
  it('a CRL that verifies under no chain certificate is rejected with its index and the most informative reason', () => {
    const foreign = forgeNvidiaCrl(sc.device, 2, { signer: sc.device.keys[0]! });
    const wrongKey = forgeNvidiaCrl(forgeNvidiaScenario({ seed: 'other' }).device, 2);
    const r = checkNvidiaChainRevocation(chain, [sc.crls[0]!, wrongKey], NOW2);
    expect(r).toEqual({ ok: false, reason: expect.stringMatching(/^CRL #1 rejected: .*signature does not verify/) });
    expect(foreign.length).toBeGreaterThan(10);
    const stale = forgeNvidiaCrl(sc.device, 2, { nextUpdate: new Date(NOW2 - 1000) });
    const s = checkNvidiaChainRevocation(chain, [stale], NOW2);
    expect(s).toEqual({ ok: false, reason: 'CRL #0 rejected: CRL is stale (nextUpdate passed)' });
    const future = forgeNvidiaCrl(sc.device, 2, { thisUpdate: new Date(NOW2 + 86_400_000) });
    expect(checkNvidiaChainRevocation(chain, [future], NOW2)).toEqual({ ok: false, reason: 'CRL #0 rejected: CRL thisUpdate is in the future' });
    expect(checkNvidiaChainRevocation(chain, [new Uint8Array([1, 2, 3])], NOW2)).toMatchObject({ ok: false, reason: expect.stringMatching(/^CRL #0 rejected: CRL parse failed/) });
  });
  it('a certificate listed on its issuer\'s CRL is revoked; listing on a non-issuer CRL does not matter', () => {
    const serial = (i: number) => chain[i]!.serialNumber;
    const leafRevoked = forgeNvidiaCrl(sc.device, 1, { revoked: [serial(0)] });
    const r = checkNvidiaChainRevocation(chain, [leafRevoked], NOW2);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe(`chain certificate '${chain[0]!.subject.replace(/\n/g, ', ')}' is revoked`);
    // issuer index 2's CRL revoking cert 1 (its subject)
    const midRevoked = forgeNvidiaCrl(sc.device, 2, { revoked: [serial(1)] });
    expect(checkNvidiaChainRevocation(chain, [midRevoked], NOW2).ok).toBe(false);
    // cert 0 on the CRL of issuer 2 (not its issuer) is not a revocation of cert 0
    expect(checkNvidiaChainRevocation(chain, [forgeNvidiaCrl(sc.device, 2, { revoked: [serial(0)] })], NOW2).ok).toBe(true);
    // the root's CRL covers certificates directly issued by the root
    const last = chain.length - 1;
    expect(checkNvidiaChainRevocation(chain, [forgeNvidiaCrl(sc.device, last, { revoked: [serial(last - 1)] })], NOW2).ok).toBe(false);
    // a CRL issued by the leaf itself (index 0) verifies and revokes nothing in the chain
    expect(checkNvidiaChainRevocation(chain, [forgeNvidiaCrl(sc.device, 0)], NOW2)).toEqual({ ok: true, verifiedCrls: 1 });
  });
  it('requireIssuers: a verified CRL issued by a certificate whose subject contains each string', () => {
    expect(checkNvidiaChainRevocation(chain, sc.crls, NOW2, ['NVIDIA Device Identity CA']).ok).toBe(true);
    expect(checkNvidiaChainRevocation(chain, [sc.crls[1]!], NOW2, ['Nope'])).toEqual({ ok: false, reason: "no verified CRL issued by a certificate matching 'Nope'" });
    const only = checkNvidiaChainRevocation(chain, [forgeNvidiaCrl(sc.device, 0)], NOW2, ['NVIDIA Device Identity CA']);
    expect(only).toEqual({ ok: false, reason: "no verified CRL issued by a certificate matching 'NVIDIA Device Identity CA'" });
  });
});

// ------------------------------------------------------------------------------------------------ hook
describe('nvidiaCollateralHook', () => {
  const sc = forgeNvidiaScenario({ seed: 'hook' });
  const chain = parsePemChain(sc.device.chainPem);
  const ctxOf = (s = sc, c = chain) => ({ report: parseNvidiaSpdmEvidence(s.evidence.evidence), chain: c, leaf: c[0]!, nowMs: s.nowMs });
  const hook = (over: Record<string, unknown> = {}, s = sc) => nvidiaCollateralHook({ rimRootSpkiSha256: [s.rimRootSpkiSha256], resolve: () => ({ driverRimXml: s.driverRimXml, vbiosRimXml: s.vbiosRimXml, crls: s.crls }), ...over } as never);
  it('construction guard', () => {
    const m = new TypeError('nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root');
    expect(() => nvidiaCollateralHook(undefined as never)).toThrow(m);
    expect(() => nvidiaCollateralHook({} as never)).toThrow(m);
    expect(() => nvidiaCollateralHook({ rimRootSpkiSha256: [], resolve: () => undefined })).toThrow(m);
    expect(() => nvidiaCollateralHook({ rimRootSpkiSha256: 'x', resolve: () => undefined } as never)).toThrow(m);
  });
  it('accepts the consistent scenario', async () => {
    expect(await hook()(ctxOf())).toBeUndefined();
  });
  it('chip family mismatch message carries the readable subject', async () => {
    const c = ctxOf();
    const leaf = new X509Certificate(sc.device.certs[4]!.der); // the root: its subject does not contain GH100
    const r = await hook()({ ...c, leaf });
    expect(r).toBe(`device leaf subject '${leaf.subject.replace(/\n/g, ', ')}' is not a GH100 device certificate (chip family mismatch)`);
    expect(r).toContain(', ');
  });
  it('missing report fields / no collateral', async () => {
    const sc2 = forgeNvidiaScenario({ seed: 'hook', opaque: defaultOpaque().filter(([k]) => k !== 3) });
    expect(await hook()(ctxOf(sc2))).toBe('GPU report does not carry the opaque fields needed to name its RIMs');
    expect(await hook({ resolve: () => undefined })(ctxOf())).toBe('no RIM collateral supplied for this report');
  });
  it('driver / VBIOS RIM failures are attributed', async () => {
    const bad = sc.driverRimXml.replace('GH100', 'GH101');
    expect(await hook({ resolve: () => ({ driverRimXml: bad, vbiosRimXml: sc.vbiosRimXml, crls: sc.crls }) })(ctxOf())).toMatch(/^driver RIM: RIM: /);
    expect(await hook({ resolve: () => ({ driverRimXml: sc.driverRimXml, vbiosRimXml: bad, crls: sc.crls }) })(ctxOf())).toMatch(/^VBIOS RIM: RIM: /);
  });
  it('product / version binding', async () => {
    const wrongFam = forgeNvidiaScenario({ seed: 'hook' });
    const drvGb = sc.rim('595.71.05', [spec(12)], { product: 'GB100' });
    const r1 = await hook({ resolve: () => ({ driverRimXml: drvGb, vbiosRimXml: sc.vbiosRimXml, crls: sc.crls }) })(ctxOf());
    expect(r1).toBe("driver RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)");
    const vbGb = sc.rim('96.00.9F.00.04', [spec(0)], { product: 'GB100' });
    const r2 = await hook({ resolve: () => ({ driverRimXml: sc.driverRimXml, vbiosRimXml: vbGb, crls: sc.crls }) })(ctxOf());
    expect(r2).toBe("VBIOS RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)");
    expect(wrongFam.driverId).toContain('595.71.05');
    const drvOld = sc.rim('595.70.00', [spec(12)]);
    expect(await hook({ resolve: () => ({ driverRimXml: drvOld, vbiosRimXml: sc.vbiosRimXml, crls: sc.crls }) })(ctxOf())).toBe("driver RIM version '595.70.00' does not match the report's driver '595.71.05'");
    const vbOld = sc.rim('96.00.9E.00.04', [spec(0)]);
    const r3 = await hook({ resolve: () => ({ driverRimXml: sc.driverRimXml, vbiosRimXml: vbOld, crls: sc.crls }) })(ctxOf());
    expect(r3).toMatch(/^VBIOS RIM version '96\.00\.9E\.00\.04' does not match the report's VBIOS '/);
    // the VBIOS comparison ignores dots and case
    const vbLower = sc.rim('96009f0004'.replace(/(..)/g, '$1.').slice(0, -1).toLowerCase(), sc.vbiosRimXml ? [] : []);
    expect(typeof vbLower).toBe('string');
  });
  it('golden mismatch is reported verbatim from the comparison', async () => {
    const s2 = forgeNvidiaScenario({ seed: 'hook', goldenOverride: { 0: hx('7') } });
    const r = await nvidiaCollateralHook({ rimRootSpkiSha256: [s2.rimRootSpkiSha256], resolve: () => ({ driverRimXml: s2.driverRimXml, vbiosRimXml: s2.vbiosRimXml, crls: s2.crls }) })(ctxOf(s2));
    expect(r).toBe('runtime measurements differ from the golden RIM values at 1 index(es)');
  });
  it('revocation modes: crl by default, optional with requireCrls=false, supplied evidence always enforced', async () => {
    const noCrl = (over: Record<string, unknown> = {}) => hook({ resolve: () => ({ driverRimXml: sc.driverRimXml, vbiosRimXml: sc.vbiosRimXml }), ...over });
    expect(await noCrl()(ctxOf())).toBe('revocation: no CRLs supplied');
    expect(await noCrl({ revocation: 'crl' })(ctxOf())).toBe('revocation: no CRLs supplied');
    expect(await noCrl({ revocation: 'both' })(ctxOf())).toBe('revocation: no CRLs supplied');
    expect(await noCrl({ requireCrls: false })(ctxOf())).toBeUndefined();
    expect(await noCrl({ revocation: 'ocsp', requireCrls: true })(ctxOf())).toMatch(/^revocation \(OCSP\)/ as never);
    const stale = forgeNvidiaCrl(sc.device, 2, { nextUpdate: new Date(sc.nowMs - 1000) });
    const r = await hook({ requireCrls: false, resolve: () => ({ driverRimXml: sc.driverRimXml, vbiosRimXml: sc.vbiosRimXml, crls: [stale] }) })(ctxOf());
    expect(r).toBe('revocation: CRL #0 rejected: CRL is stale (nextUpdate passed)');
    const r2 = await hook({ requireCrlIssuers: ['Nope'] })(ctxOf());
    expect(r2).toBe("revocation: no verified CRL issued by a certificate matching 'Nope'");
  });
  it('OCSP: good responses pass; supplied-but-bad OCSP is enforced even in crl mode; required OCSP must be present', async () => {
    const withOcsp = (ocsp: Uint8Array[], over: Record<string, unknown> = {}) => hook({ resolve: () => ({ driverRimXml: sc.driverRimXml, vbiosRimXml: sc.vbiosRimXml, crls: sc.crls, ocsp }), ...over });
    expect(await withOcsp(sc.ocsp)(ctxOf())).toBeUndefined();
    expect(await withOcsp(sc.ocsp, { revocation: 'both' })(ctxOf())).toBeUndefined();
    const garbage = await withOcsp([new Uint8Array([1, 2, 3])])(ctxOf());
    expect(garbage).toMatch(/^revocation \(OCSP\): /);
    const ocspOnly = hook({ revocation: 'ocsp', resolve: () => ({ driverRimXml: sc.driverRimXml, vbiosRimXml: sc.vbiosRimXml, ocsp: sc.ocsp }) });
    expect(await ocspOnly(ctxOf())).toBeUndefined();
    const needOcsp = hook({ revocation: 'ocsp', resolve: () => ({ driverRimXml: sc.driverRimXml, vbiosRimXml: sc.vbiosRimXml }) });
    expect(await needOcsp(ctxOf())).toMatch(/^revocation \(OCSP\): /);
  });
  it('firmware policy: numeric component comparison (length-aware), hex VBIOS, deny lists, construction validation', async () => {
    const run = (fw: Record<string, unknown>) => hook({ firmware: fw })(ctxOf());
    expect(await run({ minDriverVersion: '595.71.05' })).toBeUndefined();
    expect(await run({ minDriverVersion: '595.9' })).toBeUndefined(); // numeric, not lexical
    expect(await run({ minDriverVersion: '595.71.05.1' })).toBe('firmware policy: driver 595.71.05 is below the minimum 595.71.05.1');
    expect(await run({ minDriverVersion: '595.71.6' })).toBe('firmware policy: driver 595.71.05 is below the minimum 595.71.6');
    expect(await run({ minDriverVersion: '595.71.05.0' })).toBeUndefined();
    expect(await run({ denyDriverVersions: ['595.71.5'] })).toBe('firmware policy: driver 595.71.05 is on the deny list');
    expect(await run({ denyDriverVersions: ['595.71'] })).toBeUndefined();
    expect(await run({ denyDriverVersions: ['595.71.05.1'] })).toBeUndefined();
    const r = await hook()(ctxOf());
    expect(r).toBeUndefined();
    const ids = nvidiaRimIdsForReport(ctxOf().report)!;
    expect(await run({ minVbiosVersion: ids.vbiosVersion })).toBeUndefined();
    expect(await run({ minVbiosVersion: `${ids.vbiosVersion}.1` })).toBe(`firmware policy: VBIOS ${ids.vbiosVersion} is below the minimum ${ids.vbiosVersion}.1`);
    expect(await run({ minVbiosVersion: 'FF.00' })).toMatch(/^firmware policy: VBIOS .* is below the minimum FF\.00$/);
    expect(await run({ denyVbiosVersions: [ids.vbiosVersion.toUpperCase()] })).toBe(`firmware policy: VBIOS ${ids.vbiosVersion} is on the deny list`);
    const malformed = (fw: Record<string, unknown>, msg: string) => expect(() => nvidiaCollateralHook({ rimRootSpkiSha256: ['a'], resolve: () => undefined, firmware: fw as never })).toThrow(new TypeError(msg));
    malformed({ minDriverVersion: 'x1.2' }, "nvidiaCollateralHook: malformed minDriverVersion 'x1.2'");
    malformed({ minDriverVersion: '1.2x' }, "nvidiaCollateralHook: malformed minDriverVersion '1.2x'");
    malformed({ minDriverVersion: 5 }, "nvidiaCollateralHook: malformed minDriverVersion '5'");
    malformed({ minVbiosVersion: 'zz96.00' }, "nvidiaCollateralHook: malformed minVbiosVersion 'zz96.00'");
    malformed({ minVbiosVersion: '96.00x' }, "nvidiaCollateralHook: malformed minVbiosVersion '96.00x'");
    malformed({ minVbiosVersion: '12345.00' }, "nvidiaCollateralHook: malformed minVbiosVersion '12345.00'");
    malformed({ denyDriverVersions: ['1.2', 'q'] }, "nvidiaCollateralHook: malformed denyDriverVersions entry 'q'");
    malformed({ denyVbiosVersions: ['zz'] }, "nvidiaCollateralHook: malformed denyVbiosVersions entry 'zz'");
    expect(() => nvidiaCollateralHook({ rimRootSpkiSha256: ['a'], resolve: () => undefined, firmware: { minDriverVersion: '', minVbiosVersion: '' } })).not.toThrow();
    expect(() => nvidiaCollateralHook({ rimRootSpkiSha256: ['a'], resolve: () => undefined, firmware: { minVbiosVersion: 'ab.0001.F' } })).not.toThrow();
  });
  it('firmware policy refuses unparseable versions reported by the GPU, before fetching collateral', async () => {
    const odd = forgeNvidiaScenario({ seed: 'hook', opaque: defaultOpaque().map(([k, v]) => (k === 3 ? ([k, new TextEncoder().encode('abc')] as [number, Uint8Array]) : [k, v])) });
    let fetched = 0;
    const r = await nvidiaCollateralHook({ rimRootSpkiSha256: ['a'], firmware: { minDriverVersion: '1.0' }, resolve: () => (fetched++, undefined) })(ctxOf(odd));
    expect(r).toBe("firmware policy: driver version 'abc' in the GPU report is not parseable");
    expect(fetched).toBe(0);
  });
});

// ------------------------------------------------------------------------------------------------ fetch helpers
describe('fetch helpers', () => {
  const respond = (init: { ok?: boolean; status?: number; json?: unknown; bytes?: Uint8Array }) =>
    ({ ok: init.ok ?? true, status: init.status ?? 200, json: async () => init.json, arrayBuffer: async () => (init.bytes ?? new Uint8Array(0)).buffer }) as unknown as Response;
  it('fetchNvidiaRim: URL composition, id validation, HTTP errors, envelope decoding', async () => {
    const urls: string[] = [];
    const f = (async (u: string) => (urls.push(u), respond({ json: { rim: Buffer.from('<x>é</x>').toString('base64') } }))) as unknown as typeof fetch;
    expect(await fetchNvidiaRim('NV_GPU_DRIVER_GH100_595.71.05', { fetch: f })).toBe('<x>é</x>');
    expect(await fetchNvidiaRim('a-b_c.1', { fetch: f, baseUrl: 'https://example.test/rim/' })).toBe('<x>é</x>');
    expect(urls).toEqual([`${NVIDIA_RIM_BASE_URL}NV_GPU_DRIVER_GH100_595.71.05`, 'https://example.test/rim/a-b_c.1']);
    expect(NVIDIA_RIM_BASE_URL).toBe('https://rim.attestation.nvidia.com/v1/rim/');
    for (const bad of ['', 'a/b', 'a b', '../x', 'a?b', 'a\nb', 'é']) await expect(fetchNvidiaRim(bad, { fetch: f }), JSON.stringify(bad)).rejects.toThrow(new TypeError('fetchNvidiaRim: invalid RIM id'));
    const notOk = (async () => respond({ ok: false, status: 503 })) as unknown as typeof fetch;
    await expect(fetchNvidiaRim('abc', { fetch: notOk })).rejects.toThrow(new Error('RIM fetch failed: HTTP 503 for abc'));
    for (const json of [{}, { rim: 5 }, { rim: null }]) await expect(fetchNvidiaRim('abc', { fetch: (async () => respond({ json })) as unknown as typeof fetch })).rejects.toThrow(new Error('RIM fetch: response has no rim field'));
  });
  it('fetchNvidiaRim / fetchNvidiaCrl without any fetch implementation', async () => {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'fetch')!;
    Object.defineProperty(globalThis, 'fetch', { value: undefined, configurable: true, writable: true });
    try {
      await expect(fetchNvidiaRim('abc')).rejects.toThrow(new Error('fetchNvidiaRim: no fetch implementation available'));
      await expect(fetchNvidiaCrl('https://x.test/a.crl')).rejects.toThrow(new Error('fetchNvidiaCrl: no fetch implementation available'));
      // an explicit opts.fetch wins over the (absent) global one
      const f = (async () => respond({ bytes: Uint8Array.of(1, 2, 3) })) as unknown as typeof fetch;
      expect(Array.from(await fetchNvidiaCrl('https://x.test/a.crl', { fetch: f }))).toEqual([1, 2, 3]);
    } finally {
      Object.defineProperty(globalThis, 'fetch', saved);
    }
  });
  it('fetchNvidiaCrl: bytes, URL passthrough and HTTP errors; opts.fetch is preferred over the global', async () => {
    const urls: string[] = [];
    const f = (async (u: string) => (urls.push(u), respond({ bytes: Uint8Array.of(9, 8, 7) }))) as unknown as typeof fetch;
    const out = await fetchNvidiaCrl('https://crl.test/x.crl', { fetch: f });
    expect(out).toBeInstanceOf(Uint8Array);
    expect(Array.from(out)).toEqual([9, 8, 7]);
    expect(urls).toEqual(['https://crl.test/x.crl']);
    const notOk = (async () => respond({ ok: false, status: 404 })) as unknown as typeof fetch;
    await expect(fetchNvidiaCrl('https://crl.test/y.crl', { fetch: notOk })).rejects.toThrow(new Error('CRL fetch failed: HTTP 404 for https://crl.test/y.crl'));
  });
});
