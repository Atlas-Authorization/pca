// x509 unit rows (strict DER / role / validity readers shared by the chain verifiers) of the attestation-evidence vectors.
// Each row is `{ id, vendor: 'x509', fn, input, intent, expect }`; `expect` is `{ok:true,value}` or `{ok:false,error}` (the exact
// message of the TypeScript reader). TEST/TOOLING ONLY.
import { b64, runX509Vector, type Json, type JsonObject, type X509Fn, type X509Result } from './attestation-wire';
import { FORGE_NA, FORGE_NB } from './forge-amd';
import { bitString, boolean, cat, ctx, derTime, ext, extension, forgeCert, forgeKey, integer, octets, oid, seq, tlv } from './forge-x509';

export interface X509Vector {
  id: string;
  vendor: 'x509';
  tags: string[];
  fn: X509Fn;
  intent: 'accept' | 'reject';
  description: string;
  input: JsonObject;
  expect: X509Result;
}

const K = forgeKey('x509/subject', 'P-384');
const S = forgeKey('x509/signer', 'P-384');
const cert = (extensions: Uint8Array[], o: { nb?: Date; na?: Date } = {}): Uint8Array =>
  forgeCert({ subject: [['CN', 'unit']], issuer: [['CN', 'issuer']], subjectKey: K, signer: S, serial: 7n, notBefore: o.nb ?? FORGE_NB, notAfter: o.na ?? FORGE_NA, extensions }).der;
const hdr = (b: Uint8Array): number => (b[1]! & 0x80 ? 2 + (b[1]! & 0x7f) : 2);
/** The TBS of a certificate whose [3] block is exactly `block` (or no block when undefined). */
const tbsOf = (block: Uint8Array | undefined, extensions: Uint8Array[] = []): Uint8Array => {
  const der = cert(extensions.length ? extensions : [ext.basicConstraints(false)]);
  const outer = hdr(der);
  const tbsStart = outer;
  const tbsHdr = hdr(der.subarray(tbsStart));
  const content = der.subarray(tbsStart + tbsHdr);
  // walk TBS children, drop the [3] element, append `block`
  let p = 0;
  const kept: Uint8Array[] = [];
  const total = (() => {
    const l = der[tbsStart + 1]!;
    if (!(l & 0x80)) return l;
    let n = 0;
    for (let i = 0; i < (l & 0x7f); i++) n = n * 256 + der[tbsStart + 2 + i]!;
    return n;
  })();
  while (p < total) {
    const l = content[p + 1]!;
    const nb = l & 0x80 ? l & 0x7f : 0;
    let len = nb ? 0 : l;
    for (let i = 0; i < nb; i++) len = len * 256 + content[p + 2 + i]!;
    const end = p + 2 + nb + len;
    if (content[p] !== 0xa3) kept.push(content.slice(p, end));
    p = end;
  }
  return tlv(0x30, ...kept, ...(block ? [block] : []));
};
const withBlock = (...exts: Uint8Array[]) => ctx(3, seq(...exts));
const crit = extension('1.2.3.4.5', true, octets(Uint8Array.of(1)));

export function buildX509Vectors(): X509Vector[] {
  const out: X509Vector[] = [];
  const add = (id: string, fn: X509Fn, description: string, input: JsonObject, o: { tags?: string[] } = {}) => {
    const expect = runX509Vector(fn, input);
    out.push({ id: `x509-${id}`, vendor: 'x509', tags: o.tags ?? [], fn, intent: expect.ok ? 'accept' : 'reject', description, input, expect });
  };
  const role = (id: string, d: string, der: Uint8Array) => add(`role-${id}`, 'read_cert_role_info', d, { cert: b64(der) });
  const CA = [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])];
  role('ca-pathlen-0', 'CA with pathLen 0 and keyCertSign.', cert(CA));
  role('ca-no-pathlen', 'CA without a path length.', cert([ext.basicConstraints(true), ext.keyUsage(['keyCertSign', 'cRLSign'])]));
  role('leaf-ca-false', 'End entity, BasicConstraints CA:FALSE (DEFAULT encoded).', cert([ext.basicConstraints(false)]));
  role('no-extensions', 'No extensions at all.', cert([]));
  role('key-usage-digital-signature', 'keyUsage without keyCertSign.', cert([ext.keyUsage(['digitalSignature'])]));
  role('key-usage-unused-bits-8', 'keyUsage BIT STRING declaring 8 unused bits.', cert([extension('2.5.29.15', true, bitString(Uint8Array.of(0x04), 8))]));
  role('key-usage-unused-bits-7', 'keyUsage BIT STRING declaring 7 unused bits is allowed.', cert([extension('2.5.29.15', true, bitString(Uint8Array.of(0x80), 7))]));
  role('key-usage-too-short', 'keyUsage BIT STRING with no bit byte.', cert([extension('2.5.29.15', true, tlv(0x03, Uint8Array.of(0)))]));
  role('duplicate-basic-constraints', 'Two BasicConstraints.', cert([ext.basicConstraints(true, 0), ext.basicConstraints(true, 0)]));
  role('duplicate-key-usage', 'Two keyUsage.', cert([ext.keyUsage(['keyCertSign']), ext.keyUsage(['keyCertSign'])]));
  role('basic-constraints-trailing-data', 'BasicConstraints with a stray INTEGER.', cert([extension('2.5.29.19', true, seq(boolean(true), integer(0), integer(0)))]));
  role('basic-constraints-negative-pathlen', 'Negative pathLenConstraint.', cert([extension('2.5.29.19', true, seq(boolean(true), tlv(0x02, Uint8Array.of(0x80))))]));
  role('basic-constraints-pathlen-3-bytes', 'Three-byte pathLenConstraint.', cert([extension('2.5.29.19', true, seq(boolean(true), tlv(0x02, Uint8Array.of(0, 1, 1))))]));
  role('basic-constraints-bool-2-bytes', 'cA BOOLEAN of two bytes.', cert([extension('2.5.29.19', true, seq(tlv(0x01, Uint8Array.of(0xff, 0xff))))]));
  role('basic-constraints-not-sequence', 'BasicConstraints value that is not a SEQUENCE.', cert([extension('2.5.29.19', true, tlv(0x31, new Uint8Array(0)))]));
  role('extension-value-not-octet-string', 'Extension value that is not an OCTET STRING.', cert([seq(oid('2.5.29.19'), tlv(0x05, Uint8Array.of(1)))]));
  role('extension-not-sequence', 'An extension that is not a SEQUENCE.', cert([tlv(0x31, new Uint8Array(0))]));
  role('extensions-not-sequence', 'The [3] block holding a SET.', tbsToCert(tbsOf(ctx(3, tlv(0x31, new Uint8Array(0))))));
  const good = cert(CA);
  role('trailing-zero-byte', 'A zero byte after the certificate.', cat(good, Uint8Array.of(0)));
  role('trailing-ff-byte', 'A 0xFF byte after the certificate.', cat(good, Uint8Array.of(0xff)));
  role('not-a-sequence', 'Outer tag is not SEQUENCE.', cat(Uint8Array.of(0x31), good.subarray(1)));
  role('empty', 'Empty input.', new Uint8Array(0));
  role('truncated', 'Certificate truncated.', good.subarray(0, good.length - 3));
  const oh = hdr(good);
  const outerLen = good.length - oh;
  role('outer-length-leading-zero', 'Outer length encoded with a leading zero length byte.', cat(Uint8Array.of(0x30, 0x83, 0x00, (outerLen >> 8) & 255, outerLen & 255), good.subarray(oh)));
  role('outer-length-multibyte-tag', 'Multi-byte tag form.', cat(Uint8Array.of(0x1f, 0x01), good.subarray(2)));
  role('extension-octet-length-long-form-below-128', 'An OCTET STRING length in long form below 128.', cert([seq(oid('2.5.29.19'), Uint8Array.of(0x04, 0x81, 0x03, 0x30, 0x01, 0x00))]));
  // extension tables
  const tbs = (block: Uint8Array | undefined, exts: Uint8Array[] = []) => b64(tbsOf(block, exts));
  const goodExts = [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign']), extension('1.2.3.4', false, octets(Uint8Array.of(9)))];
  add('tbs-ok', 'parse_tbs_extensions', 'Three extensions, flags and exact value bytes.', { tbs: tbs(undefined, goodExts) });
  add('tbs-duplicate-oid', 'parse_tbs_extensions', 'The same extension twice.', { tbs: tbs(withBlock(extension('1.2.3', false, octets(Uint8Array.of(1))), extension('1.2.3', false, octets(Uint8Array.of(2))))) });
  add('tbs-two-blocks', 'parse_tbs_extensions', 'Two [3] blocks.', { tbs: tbs(cat(withBlock(...goodExts), withBlock(...goodExts))) });
  add('tbs-empty-extensions', 'parse_tbs_extensions', 'An empty Extensions SEQUENCE.', { tbs: tbs(ctx(3, seq())) });
  add('tbs-block-not-last', 'parse_tbs_extensions', 'Another element after the [3] block.', { tbs: tbs(cat(withBlock(...goodExts), tlv(0xa1, Uint8Array.of(1)))) });
  add('tbs-trailing-in-extensions', 'parse_tbs_extensions', 'Bytes after the Extensions SEQUENCE inside [3].', { tbs: tbs(ctx(3, cat(seq(...goodExts), Uint8Array.of(0, 0)))) });
  add('tbs-extensions-not-sequence', 'parse_tbs_extensions', 'Extensions that is a SET.', { tbs: tbs(ctx(3, tlv(0x31, new Uint8Array(0)))) });
  const one = (inner: Uint8Array) => ({ tbs: tbs(withBlock(inner)) });
  add('tbs-critical-explicit-false', 'parse_tbs_extensions', 'critical encoded as an explicit FALSE.', one(seq(oid('1.2.3'), tlv(0x01, Uint8Array.of(0)), octets(Uint8Array.of(1)))));
  add('tbs-critical-0x01', 'parse_tbs_extensions', 'critical TRUE encoded as 0x01.', one(seq(oid('1.2.3'), tlv(0x01, Uint8Array.of(1)), octets(Uint8Array.of(1)))));
  add('tbs-critical-true', 'parse_tbs_extensions', 'critical TRUE encoded as 0xFF.', one(seq(oid('1.2.3'), tlv(0x01, Uint8Array.of(0xff)), octets(Uint8Array.of(1)))));
  add('tbs-extension-trailing-bytes', 'parse_tbs_extensions', 'A second OCTET STRING inside an extension.', one(seq(oid('1.2.3'), octets(Uint8Array.of(1)), octets(Uint8Array.of(2)))));
  add('tbs-value-not-octet-string', 'parse_tbs_extensions', 'A value that is not an OCTET STRING.', one(seq(oid('1.2.3'), tlv(0x05, Uint8Array.of(1)))));
  add('tbs-oid-not-oid', 'parse_tbs_extensions', 'An identifier that is not an OID.', one(seq(tlv(0x04, Uint8Array.of(0x2a)), octets(Uint8Array.of(1)))));
  add('tbs-oid-nonminimal-arc', 'parse_tbs_extensions', 'An OID arc with a leading 0x80.', one(seq(tlv(0x06, Uint8Array.of(0x2a, 0x80, 0x01)), octets(Uint8Array.of(1)))));
  add('tbs-oid-truncated', 'parse_tbs_extensions', 'An OID ending mid-arc.', one(seq(tlv(0x06, Uint8Array.of(0x2a, 0x83)), octets(Uint8Array.of(1)))));
  add('tbs-oid-empty', 'parse_tbs_extensions', 'An empty OID.', one(seq(tlv(0x06, new Uint8Array(0)), octets(Uint8Array.of(1)))));
  add('tbs-oid-first-arc-forms', 'parse_tbs_extensions', 'First-arc forms 0.x, 1.x, 2.x.', { tbs: tbs(withBlock(extension('0.9.1', true, octets(Uint8Array.of(1))), extension('1.39.5', false, octets(Uint8Array.of(1))), extension('2.100.3', false, octets(Uint8Array.of(1))))) });
  add('tbs-no-extensions', 'parse_tbs_extensions', 'A TBS without a [3] block.', { tbs: tbs(undefined, []) });
  add('tbs-trailing-after', 'parse_tbs_extensions', 'A byte after the TBS.', { tbs: b64(cat(tbsOf(undefined, goodExts), Uint8Array.of(0))) });
  add('tbs-not-a-sequence', 'parse_tbs_extensions', 'A TBS that is not a SEQUENCE.', { tbs: b64(Uint8Array.of(1, 2, 3)) });
  add('cert-extensions-ok', 'parse_cert_extensions', 'Whole-certificate form.', { cert: b64(cert(goodExts)) });
  add('cert-extensions-trailing', 'parse_cert_extensions', 'Whole-certificate form with a trailing byte.', { cert: b64(cat(cert(goodExts), Uint8Array.of(0))) });
  add('tbs-of-certificate', 'tbs_of_certificate', 'The TBS bytes of a certificate.', { cert: b64(cert(goodExts)) });
  add('tbs-of-certificate-trailing', 'tbs_of_certificate', 'Trailing bytes after the certificate.', { cert: b64(cat(cert(goodExts), Uint8Array.of(0))) });
  // critical-extension rule
  add('critical-none', 'unrecognised_critical_extension', 'Only recognised critical extensions.', { cert: b64(cert(CA)) });
  add('critical-unknown', 'unrecognised_critical_extension', 'An unknown critical extension.', { cert: b64(cert([...CA, crit])) });
  add('critical-unknown-noncritical', 'unrecognised_critical_extension', 'An unknown non-critical extension.', { cert: b64(cert([...CA, extension('1.2.3.4.5', false, octets(Uint8Array.of(1)))])) });
  add('critical-recognised-override', 'unrecognised_critical_extension', 'A caller-supplied recognised set that includes the extension.', { cert: b64(cert([...CA, crit])), recognised: ['2.5.29.19', '2.5.29.15', '1.2.3.4.5'] });
  add('critical-malformed', 'unrecognised_critical_extension', 'A malformed extension table.', { cert: b64(cert([seq(oid('1.2.3'), tlv(0x01, Uint8Array.of(1)), octets(Uint8Array.of(1)))])) });
  // chain roles
  const leaf = cert([ext.basicConstraints(false)]);
  const ca1 = cert([ext.basicConstraints(true, 1), ext.keyUsage(['keyCertSign'])]);
  const ca2 = cert([ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])]);
  const root = cert([ext.basicConstraints(true, 5), ext.keyUsage(['keyCertSign', 'cRLSign'])]);
  const chain = (...c: Uint8Array[]) => ({ chain: c.map(b64) });
  add('chain-ok-4', 'check_chain_roles', 'Leaf, CA pathLen 0, CA pathLen 1, root pathLen 5.', chain(leaf, ca2, ca1, root));
  add('chain-single', 'check_chain_roles', 'A bare root has no relationship to check.', chain(root));
  add('chain-pathlen-exceeded', 'check_chain_roles', 'pathLen 0 above another intermediate.', chain(leaf, ca2, ca2, root));
  add('chain-leaf-ca', 'check_chain_roles', 'A leaf asserting CA:TRUE.', chain(cert([ext.basicConstraints(true)]), ca2, root));
  add('chain-issuer-ca-false', 'check_chain_roles', 'An issuer with CA:FALSE.', chain(leaf, cert([ext.basicConstraints(false)]), root));
  add('chain-issuer-no-bc', 'check_chain_roles', 'An issuer without BasicConstraints.', chain(leaf, cert([ext.keyUsage(['keyCertSign'])]), root));
  add('chain-issuer-no-cert-sign', 'check_chain_roles', 'An issuer keyUsage without keyCertSign.', chain(leaf, cert([ext.basicConstraints(true, 0), ext.keyUsage(['digitalSignature'])]), root));
  add('chain-issuer-no-key-usage-ok', 'check_chain_roles', 'An issuer without keyUsage is tolerated.', chain(leaf, cert([ext.basicConstraints(true, 0)]), root));
  add('chain-parse-failure', 'check_chain_roles', 'A certificate that does not parse.', chain(leaf, Uint8Array.of(1, 2, 3), root));
  add('chain-trailing-byte', 'check_chain_roles', 'A trailing byte after an issuer.', chain(leaf, cat(ca2, Uint8Array.of(0)), root));
  // validity
  const at = (s: string) => new Date(s);
  add('validity-utc', 'der_validity_ms', 'UTCTime bounds.', { cert: b64(cert([], { nb: at('2026-01-02T03:04:05Z'), na: at('2030-12-31T23:59:59Z') })) });
  add('validity-generalized', 'der_validity_ms', 'GeneralizedTime beyond 2049.', { cert: b64(cert([], { nb: at('2026-01-02T03:04:05Z'), na: at('2060-12-31T23:59:59Z') })) });
  add('validity-year-1999', 'der_validity_ms', 'UTCTime years 50-99 mean 19xx.', { cert: b64(cert([], { nb: at('1999-06-01T00:00:00Z'), na: at('2030-01-01T00:00:00Z') })) });
  add('validity-garbage', 'der_validity_ms', 'Not a certificate.', { cert: b64(Uint8Array.of(1, 2, 3)) });
  const timeCert = (nbTime: Uint8Array) => {
    const c = cert([]);
    const nbDer = derTime(FORGE_NB);
    const idx = Buffer.from(c).indexOf(Buffer.from(nbDer));
    return cat(c.subarray(0, idx), nbTime, c.subarray(idx + nbDer.length));
  };
  const rawTime = (tag: number, s: string) => tlv(tag, new TextEncoder().encode(s));
  add('validity-bad-month', 'der_validity_ms', 'notBefore with month 13 (certificate bytes edited in place: lengths stay consistent).', { cert: b64(timeCert(rawTime(0x17, '221301000000Z'))) });
  add('validity-feb-30', 'der_validity_ms', 'notBefore 30 February.', { cert: b64(timeCert(rawTime(0x17, '220230000000Z'))) });
  add('validity-second-60', 'der_validity_ms', 'notBefore second 60.', { cert: b64(timeCert(rawTime(0x17, '220101000060Z'))) });
  add('validity-no-z', 'der_validity_ms', 'notBefore without the Z suffix.', { cert: b64(timeCert(rawTime(0x17, '2201010000000'))) });
  const times: Array<[string, number, string]> = [
    ['utc-2022', 0x17, '220101000000Z'], ['utc-1950', 0x17, '500101000000Z'], ['utc-2049', 0x17, '491231235959Z'], ['gen-2050', 0x18, '20500101000000Z'], ['gen-1999', 0x18, '19990101000000Z'],
    ['leap-day', 0x17, '240229120000Z'], ['not-leap-day', 0x17, '230229120000Z'], ['month-0', 0x17, '220001000000Z'], ['day-0', 0x17, '220100000000Z'], ['hour-24', 0x17, '220101240000Z'],
    ['minute-60', 0x17, '220101006000Z'], ['second-60', 0x17, '220101000060Z'], ['utc-wrong-length', 0x17, '2201010000Z'], ['gen-wrong-length', 0x18, '220101000000Z'], ['non-digit', 0x17, '22010100000AZ'],
    ['fraction', 0x18, '20220101000000.5Z'], ['offset', 0x17, '220101000000+0100'], ['wrong-tag', 0x16, '220101000000Z'], ['april-31', 0x17, '220431000000Z'], ['dec-31', 0x17, '221231235959Z'],
  ];
  for (const [n, tag, text] of times) add(`time-${n}`, 'parse_der_time', `parseDerTime(${tag.toString(16)}, "${text}").`, { tag, text });
  return out;
}

/** Wrap a TBS back into a signed-looking certificate shell (signature bytes are not checked by the role reader). */
function tbsToCert(tbs: Uint8Array): Uint8Array {
  const alg = seq(oid('1.2.840.10045.4.3.3'));
  return seq(tbs, alg, bitString(new Uint8Array(96)));
}
export type { Json };
