/**
 * DER / X.509 differential tests. Our strict reader (`readCertRoleInfo`, `derValidityMs`) is compared against two
 * independent parsers on a corpus that includes malformed and non-minimal encodings:
 *   - OpenSSL (through node's X509Certificate), and
 *   - pkijs / asn1js (a pure-JS ASN.1 library).
 * Where we accept a certificate and another parser also parses it, they must agree on the CA flag, pathLen and validity.
 * Where we must reject (trailing bytes, non-minimal or indefinite lengths, truncation, duplicated extensions, wrong
 * types) the exact reason is pinned, even though OpenSSL itself is lenient about several of these.
 */
import { X509Certificate } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { readCertRoleInfo, unrecognisedCriticalExtension, type CertRoleInfo } from './x509-strict';
import { verifyIntelPckChainX509 } from './attest-intel-tdx';
import { derValidityMs, parseOpenSslTime } from './x509-validity';
import { boolean, ext, extension, forgeCert, forgeKey, integer, octets, seq, tlv, type Extension } from './test-support/forge-x509';

const K = forgeKey('diff/ca', 'P-256');
const cert = (exts: Extension[], nb = '2026-01-01T00:00:00Z', na = '2030-01-01T00:00:00Z'): Uint8Array =>
  forgeCert({ subject: [['CN', 'a']], issuer: [['CN', 'a']], subjectKey: K, signer: K, serial: 5n, notBefore: new Date(nb), notAfter: new Date(na), extensions: exts }).der;
const bc = (inner: Uint8Array): Extension => extension('2.5.29.19', true, inner);

const BASE: Array<[string, Uint8Array]> = [
  ['ca pathLen=0', cert([ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])])],
  ['ca pathLen=1', cert([ext.basicConstraints(true, 1), ext.keyUsage(['keyCertSign', 'cRLSign'])])],
  ['ca pathLen=127', cert([ext.basicConstraints(true, 127)])],
  ['ca pathLen=128 (needs a leading zero)', cert([ext.basicConstraints(true, 128)])],
  ['ca no pathLen', cert([ext.basicConstraints(true)])],
  ['end entity CA:FALSE (absent boolean)', cert([ext.basicConstraints(false), ext.keyUsage(['digitalSignature'])])],
  ['no extensions at all', cert([])],
  ['keyUsage only, no keyCertSign', cert([ext.keyUsage(['digitalSignature', 'nonRepudiation'])])],
  ['UTCTime window', cert([], '2026-01-01T00:00:00Z', '2049-12-31T23:59:59Z')],
  ['GeneralizedTime window (year 2050)', cert([], '2026-01-01T00:00:00Z', '2050-01-01T00:00:00Z')],
  ['GeneralizedTime window (year 2099)', cert([], '2049-12-31T23:59:59Z', '2099-06-30T12:00:00Z')],
];

// ── second parser ──────────────────────────────────────────────────────────────────────────────
interface PkiView { ca: boolean; pathLen: number | undefined; hasBc: boolean; from: number; to: number }
function viaPkijs(der: Uint8Array): PkiView | undefined {
  try {
    const ab = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer;
    const a = asn1js.fromBER(ab);
    if (a.offset === -1) return undefined;
    const c = new pkijs.Certificate({ schema: a.result });
    const e = c.extensions?.find((x) => x.extnID === '2.5.29.19');
    const v = e?.parsedValue as { cA?: boolean; pathLenConstraint?: number | { valueBlock?: { valueDec?: number } } } | undefined;
    const pl = typeof v?.pathLenConstraint === 'number' ? v.pathLenConstraint : v?.pathLenConstraint?.valueBlock?.valueDec;
    return { ca: v?.cA === true, pathLen: pl, hasBc: e !== undefined, from: c.notBefore.value.getTime(), to: c.notAfter.value.getTime() };
  } catch {
    return undefined;
  }
}
const viaNode = (der: Uint8Array): X509Certificate | undefined => {
  try { return new X509Certificate(Buffer.from(der)); } catch { return undefined; }
};
const ours = (der: Uint8Array): CertRoleInfo | string => {
  try { return readCertRoleInfo(der); } catch (e) { return (e as Error).message; }
};

/** What the chain verifiers run on every certificate: role read + full extension table + the critical-extension rule. */
const gate = (der: Uint8Array): string | undefined => {
  try {
    readCertRoleInfo(der);
    const c = unrecognisedCriticalExtension(der);
    return c ? `unrecognised critical extension ${c}` : undefined;
  } catch (e) {
    return (e as Error).message;
  }
};

describe('well-formed certificates: three parsers agree', () => {
  it.each(BASE)('%s', (_n, der) => {
    const o = ours(der);
    expect(typeof o).toBe('object');
    const info = o as CertRoleInfo;
    const n = viaNode(der)!;
    const p = viaPkijs(der)!;
    expect(n).toBeDefined();
    expect(p).toBeDefined();
    expect(info.ca).toBe(n.ca);
    expect(info.ca).toBe(p.ca);
    expect(info.hasBasicConstraints).toBe(p.hasBc);
    expect(info.pathLen).toBe(p.pathLen);
    const v = derValidityMs(der);
    expect(v.from).toBe(p.from);
    expect(v.to).toBe(p.to);
    expect(v.from).toBe(parseOpenSslTime(n.validFrom));
    expect(v.to).toBe(parseOpenSslTime(n.validTo));
  });
});

describe('malformed and non-minimal encodings: exact rejection', () => {
  const der = BASE[1]![1];
  const withLen = (newLenBytes: number[]): Uint8Array => Uint8Array.from([0x30, ...newLenBytes, ...der.subarray(4)]); // BASE certs use a 2-byte length (0x82 hh ll)
  const rows: Array<[string, Uint8Array, string]> = [
    ['one trailing zero byte', Uint8Array.from([...der, 0]), 'trailing bytes after the certificate'],
    ['four trailing bytes', Uint8Array.from([...der, 1, 2, 3, 4]), 'trailing bytes after the certificate'],
    ['a second certificate appended', Uint8Array.from([...der, ...der]), 'trailing bytes after the certificate'],
    ['outer length with a leading zero byte (0x83 00 hh ll)', withLen([0x83, 0x00, der[2]!, der[3]!]), 'DER: non-minimal length (leading zero)'],
    ['outer long form for a value below 128', Uint8Array.from([0x30, 0x81, 0x05, 1, 2, 3, 4, 5]), 'DER: non-minimal length (long form below 128)'],
    ['indefinite length', Uint8Array.from([0x30, 0x80, ...der.subarray(4), 0, 0]), 'DER: unsupported length form'],
    ['length form wider than 3 bytes', Uint8Array.from([0x30, 0x84, 0, 0, 1, 0, ...der.subarray(4)]), 'DER: unsupported length form'],
    ['truncated by 3 bytes', der.subarray(0, der.length - 3), 'DER: element overruns its parent'],
    ['truncated to the header', der.subarray(0, 2), 'DER: truncated length'],
    ['empty input', new Uint8Array(0), 'DER: truncated header'],
    ['not a SEQUENCE', Uint8Array.from([0x31, ...der.subarray(1)]), 'certificate is not a DER SEQUENCE'],
    ['multi-byte tag', Uint8Array.from([0x1f, 0x81, 0x00, 0x00]), 'DER: multi-byte tags are not supported'],
  ];
  it.each(rows)('%s', (_n, bytes, reason) => {
    expect(ours(bytes)).toBe(reason);
  });

  it('OpenSSL is lenient about trailing bytes and non-minimal lengths (the reason we reject them ourselves)', () => {
    expect(viaNode(Uint8Array.from([...der, 0]))?.ca).toBe(true);
    expect(viaNode(withLen([0x83, 0x00, der[2]!, der[3]!]))?.ca).toBe(true);
  });

  const extRows: Array<[string, Extension[], string]> = [
    ['duplicate BasicConstraints', [ext.basicConstraints(true), ext.basicConstraints(false)], 'duplicate BasicConstraints extension'],
    ['duplicate keyUsage', [ext.keyUsage(['keyCertSign']), ext.keyUsage(['keyCertSign'])], 'duplicate keyUsage extension'],
    ['BasicConstraints value is not a SEQUENCE', [bc(boolean(true))], 'BasicConstraints is not a SEQUENCE'],
    ['cA boolean longer than one byte', [bc(seq(tlv(0x01, Uint8Array.of(0xff, 0xff))))], 'BasicConstraints cA is not one byte'],
    ['negative pathLenConstraint', [bc(seq(boolean(true), tlv(0x02, Uint8Array.of(0xff))))], 'BasicConstraints pathLenConstraint malformed'],
    ['pathLenConstraint of three bytes', [bc(seq(boolean(true), tlv(0x02, Uint8Array.of(0x01, 0x00, 0x00))))], 'BasicConstraints pathLenConstraint malformed'],
    ['trailing data inside BasicConstraints', [bc(seq(boolean(true), integer(1), integer(2)))], 'BasicConstraints has trailing data'],
    ['keyUsage BIT STRING declares 10 unused bits', [extension('2.5.29.15', true, tlv(0x03, Uint8Array.of(0x0a, 0x04)))], 'keyUsage BIT STRING has more than 7 unused bits'],
    ['keyUsage is not a BIT STRING', [extension('2.5.29.15', true, octets(Uint8Array.of(0x04)))], 'keyUsage is not a BIT STRING'],
    ['extension value is not an OCTET STRING', [seq(tlv(0x06, Uint8Array.of(0x55, 0x1d, 0x13)), boolean(true), seq())], 'extension value is not an OCTET STRING'],
  ];
  it.each(extRows)('%s', (_n, exts, reason) => {
    expect(ours(cert(exts))).toBe(reason);
  });

  it('a BER-style cA (any non-zero byte) is read as TRUE by us, by OpenSSL and by pkijs alike: no parser disagrees on who is a CA', () => {
    for (const byte of [0x01, 0x7f, 0xff]) {
      const d = cert([bc(seq(tlv(0x01, Uint8Array.of(byte))))]);
      const o = ours(d) as CertRoleInfo;
      expect([byte, o.ca, viaNode(d)?.ca, viaPkijs(d)?.ca]).toEqual([byte, true, true, true]);
    }
    const explicitFalse = cert([bc(seq(tlv(0x01, Uint8Array.of(0x00))))]);
    expect([(ours(explicitFalse) as CertRoleInfo).ca, viaNode(explicitFalse)?.ca, viaPkijs(explicitFalse)?.ca]).toEqual([false, false, false]);
  });
});

describe('mutation corpus: where we parse and another parser parses, the role facts are identical', () => {
  // xorshift32: deterministic, no timing or platform dependence
  let state = 0x9e3779b9;
  const rnd = (n: number) => { state ^= state << 13; state >>>= 0; state ^= state >>> 17; state ^= state << 5; state >>>= 0; return state % n; };

  it('byte flips, deletions and insertions over every base certificate (several thousand inputs)', () => {
    let accepted = 0, bothParsed = 0, total = 0, gated = 0;
    const disagreements: string[] = [];
    for (const [name, base] of BASE) {
      for (let i = 0; i < 1000; i++) {
        const b = Uint8Array.from(base);
        const kind = rnd(3);
        const at = rnd(b.length);
        let m: Uint8Array;
        if (kind === 0) { b[at] = b[at]! ^ (1 << rnd(8)); m = b; }
        else if (kind === 1) m = Uint8Array.from([...b.subarray(0, at), ...b.subarray(at + 1 + rnd(3))]);
        else m = Uint8Array.from([...b.subarray(0, at), rnd(256), ...b.subarray(at)]);
        total++;
        const o = ours(m);
        if (typeof o === 'string') continue;
        accepted++;
        const n = viaNode(m);
        const p = viaPkijs(m);
        if (gate(m) !== undefined) { gated++; continue; } // rejected by the production gate: no disagreement can survive it
        if (n) { bothParsed++; if (o.ca !== n.ca) disagreements.push(`${name}#${i}: ca ours=${o.ca} openssl=${n.ca} base=${Buffer.from(base).toString("hex")} mut=${Buffer.from(m).toString("hex")}`); }
        if (p && p.hasBc === o.hasBasicConstraints) {
          if (o.ca !== p.ca) disagreements.push(`${name}#${i}: ca ours=${o.ca} pkijs=${p.ca}`);
          if (o.pathLen !== p.pathLen) disagreements.push(`${name}#${i}: pathLen ours=${o.pathLen} pkijs=${p.pathLen}`);
        }
      }
    }
    expect(total).toBe(BASE.length * 1000);
    expect(accepted).toBeGreaterThan(200); // the corpus does exercise the accept path
    expect(bothParsed).toBeGreaterThan(100);
    expect(disagreements).toEqual([]);
    expect(gated).toBeGreaterThan(0); // at least one mutation (a foreign critical extension) is stopped by the gate, not by the reader
  });

  it('a foreign critical extension makes OpenSSL and our reader disagree about CA, and the production gate rejects it', () => {
    const d = cert([ext.basicConstraints(true, 0), extension('2.5.29.31', true, octets(Uint8Array.of(0x03, 0x02, 0x02, 0x04)))]);
    expect((ours(d) as CertRoleInfo).ca).toBe(true);
    expect(viaNode(d)?.ca).toBe(false); // OpenSSL flags the malformed CRL distribution point and refuses the CA role
    expect(gate(d)).toBe('unrecognised critical extension 2.5.29.31');
  });
});

describe('Intel PCK chains reject an unrecognised critical extension (RFC 5280 4.2) like AMD chains do', () => {
  const chain = (caExts: Extension[]) => {
    const rk = forgeKey('crit/root', 'P-256'), ck = forgeKey('crit/ca', 'P-256'), lk = forgeKey('crit/leaf', 'P-256');
    const n = (c: string) => [['CN', c]] as const;
    const o = { notBefore: new Date('2020-01-01Z'), notAfter: new Date('2045-01-01Z') };
    const root = forgeCert({ subject: n('R'), issuer: n('R'), subjectKey: rk, signer: rk, serial: 1n, ...o, extensions: [ext.basicConstraints(true), ext.keyUsage(['keyCertSign'])] });
    const ca = forgeCert({ subject: n('C'), issuer: n('R'), subjectKey: ck, signer: rk, serial: 2n, ...o, extensions: caExts });
    const leaf = forgeCert({ subject: n('L'), issuer: n('C'), subjectKey: lk, signer: ck, serial: 3n, ...o, extensions: [ext.basicConstraints(false)] });
    return { pckChainPem: leaf.pem + ca.pem + root.pem, trustAnchorRootCaSpkiSha256: rk.spkiSha256, nowMs: Date.parse('2026-10-08Z') };
  };
  const GOOD = [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])];
  it('accepts the clean chain and a foreign NON-critical extension', async () => {
    expect((await verifyIntelPckChainX509(chain(GOOD))).ok).toBe(true);
    expect((await verifyIntelPckChainX509(chain([...GOOD, extension('1.2.3.4', false, octets(Uint8Array.of(1)))]))).ok).toBe(true);
  });
  it('rejects a foreign CRITICAL extension on the intermediate, naming its depth and OID', async () => {
    const r = await verifyIntelPckChainX509(chain([...GOOD, extension('1.2.3.4', true, octets(Uint8Array.of(1)))]));
    expect([r.ok, r.reason]).toEqual([false, 'PCK chain certificate at depth 1 has an unrecognised critical extension 1.2.3.4']);
  });
});
