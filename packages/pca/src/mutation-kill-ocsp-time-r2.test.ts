/**
 * Round-2 probe/kill for the OCSP time handling. The ledger claimed "pkijs rejects a malformed time while parsing the
 * response", making the verifier's own `Number.isFinite(thisUpdate/producedAt)` check unreachable. Here the response
 * TBS is re-encoded with malformed GeneralizedTime values and re-signed by the (trusted) issuer, so only the time
 * handling decides. Probed: asn1js does NOT reject them; it rolls the fields over into a different instant (a producedAt
 * with month 00 became the previous December and the response verified GOOD). Every malformed time must be refused.
 */
import { generateKeyPairSync, webcrypto, X509Certificate, sign as nodeSign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { describe, it, expect, beforeAll } from 'vitest';
import { buildNvidiaOcspRequest, verifyNvidiaOcspResponse } from './attest-nvidia-ocsp';

const { subtle } = webcrypto;
const NOW = Date.parse('2026-10-08T23:08:00Z');
pkijs.setEngine('node', new pkijs.CryptoEngine({ name: 'node', crypto: webcrypto as unknown as Crypto }));

interface Ident {
  name: string;
  priv: CryptoKey;
  pubSpki: Uint8Array;
  cert: X509Certificate;
}

function cn(name: string): pkijs.AttributeTypeAndValue {
  return new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value: name }) });
}

function ab(u: Uint8Array): ArrayBuffer {
  const o = new ArrayBuffer(u.length);
  new Uint8Array(o).set(u);
  return o;
}

let serialCounter = 100;
async function mkIdent(name: string, issuer: Ident | undefined, opts: { eku?: string[]; notBefore?: number; notAfter?: number; ca?: boolean } = {}): Promise<Ident> {
  const kp = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  KEYS.set(name, kp.privateKey as KeyObject);
  const priv = await subtle.importKey('pkcs8', (kp.privateKey as KeyObject).export({ format: 'der', type: 'pkcs8' }), { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
  const pubSpki = new Uint8Array((kp.publicKey as KeyObject).export({ format: 'der', type: 'spki' }));
  const c = new pkijs.Certificate();
  c.version = 2;
  c.serialNumber = new asn1js.Integer({ value: serialCounter++ });
  c.issuer.typesAndValues.push(cn(issuer?.name ?? name));
  c.subject.typesAndValues.push(cn(name));
  c.notBefore.value = new Date(opts.notBefore ?? NOW - 86400_000 * 30);
  c.notAfter.value = new Date(opts.notAfter ?? NOW + 86400_000 * 365);
  c.subjectPublicKeyInfo = new pkijs.PublicKeyInfo({ schema: asn1js.fromBER(ab(pubSpki)).result });
  c.extensions = [];
  if (opts.eku) {
    c.extensions.push(new pkijs.Extension({ extnID: '2.5.29.37', critical: false, extnValue: new pkijs.ExtKeyUsage({ keyPurposes: opts.eku }).toSchema().toBER(false) }));
  }
  if (opts.ca) {
    c.extensions.push(new pkijs.Extension({ extnID: '2.5.29.19', critical: true, extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(false) }));
  }
  await c.sign(issuer?.priv ?? priv, 'SHA-384');
  const cert = new X509Certificate(Buffer.from(c.toSchema(true).toBER(false)));
  return { name, priv, pubSpki, cert };
}

interface MkResp {
  cert: X509Certificate;
  issuer: X509Certificate;
  signer: Ident;
  embed?: X509Certificate[];
  by?: 'name' | 'key';
  status: 'good' | 'unknown' | 'revoked';
  thisUpdate?: number;
  nextUpdate?: number | null;
  nonce?: Uint8Array;
  reason?: number;
  hash?: 'sha1' | 'sha256' | 'sha384';
}
async function mkResponse(o: MkResp): Promise<Uint8Array> {
  const reqDer = await buildNvidiaOcspRequest(o.cert, o.issuer, { hash: o.hash ?? 'sha384' });
  const reqAsn = asn1js.fromBER(ab(reqDer));
  const req = new pkijs.OCSPRequest({ schema: reqAsn.result });
  const sr = new pkijs.SingleResponse({ certID: req.tbsRequest.requestList[0]!.reqCert });
  const tu = o.thisUpdate ?? NOW - 60_000;
  sr.thisUpdate = new Date(tu);
  if (o.nextUpdate !== null) sr.nextUpdate = new Date(o.nextUpdate ?? tu + 86400_000);
  if (o.status === 'good') sr.certStatus = new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 }, valueHex: new ArrayBuffer(0) });
  else if (o.status === 'unknown') sr.certStatus = new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 2 }, valueHex: new ArrayBuffer(0) });
  else {
    const parts: asn1js.BaseBlock[] = [new asn1js.GeneralizedTime({ valueDate: new Date(NOW - 3600_000) })];
    if (o.reason !== undefined) parts.push(new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [new asn1js.Enumerated({ value: o.reason })] }));
    sr.certStatus = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 1 }, value: parts });
  }
  const basic = new pkijs.BasicOCSPResponse();
  const spkiAsn = asn1js.fromBER(ab(o.signer.pubSpki));
  const spki = new pkijs.PublicKeyInfo({ schema: spkiAsn.result });
  if ((o.by ?? 'name') === 'key') {
    const h: ArrayBuffer = await subtle.digest('SHA-1', new Uint8Array(spki.subjectPublicKey.valueBlock.valueHexView));
    basic.tbsResponseData.responderID = new asn1js.OctetString({ valueHex: h });
  } else {
    const rdn = new pkijs.RelativeDistinguishedNames({ typesAndValues: [cn(o.signer.name)] });
    basic.tbsResponseData.responderID = rdn;
  }
  basic.tbsResponseData.producedAt = new Date(tu);
  basic.tbsResponseData.responses = [sr];
  if (o.nonce) {
    basic.tbsResponseData.responseExtensions = [new pkijs.Extension({ extnID: '1.3.6.1.5.5.7.48.1.2', critical: false, extnValue: new asn1js.OctetString({ valueHex: ab(o.nonce) }).toBER(false) })];
  }
  if (o.embed?.length) {
    basic.certs = o.embed.map((x) => new pkijs.Certificate({ schema: asn1js.fromBER(ab(x.raw)).result }));
  }
  await basic.sign(o.signer.priv, 'SHA-384');
  const resp = new pkijs.OCSPResponse({
    responseStatus: new asn1js.Enumerated({ value: 0 }),
    responseBytes: new pkijs.ResponseBytes({ responseType: '1.3.6.1.5.5.7.48.1.1', response: new asn1js.OctetString({ valueHex: basic.toSchema().toBER(false) }) }),
  });
  return new Uint8Array(resp.toSchema().toBER(false));
}


const KEYS = new Map<string, KeyObject>();
const MARK_TU = '20990101000000Z';
const MARK_PA = '20980101000000Z';

/** A GOOD response whose thisUpdate / producedAt GeneralizedTime strings are replaced by `tu` / `pa`, re-signed by `signer`. */
async function malformed(cert: X509Certificate, issuer: X509Certificate, signer: Ident, tu: string, pa: string): Promise<Uint8Array> {
  const reqDer = await buildNvidiaOcspRequest(cert, issuer, { hash: 'sha384' });
  const req = new pkijs.OCSPRequest({ schema: asn1js.fromBER(ab(reqDer)).result });
  const sr = new pkijs.SingleResponse({ certID: req.tbsRequest.requestList[0]!.reqCert });
  sr.thisUpdate = new Date(Date.UTC(2099, 0, 1));
  sr.certStatus = new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 }, valueHex: new ArrayBuffer(0) });
  const basic = new pkijs.BasicOCSPResponse();
  basic.tbsResponseData.responderID = new pkijs.RelativeDistinguishedNames({ typesAndValues: [cn(signer.name)] });
  basic.tbsResponseData.producedAt = new Date(Date.UTC(2098, 0, 1));
  basic.tbsResponseData.responses = [sr];
  await basic.sign(signer.priv, 'SHA-384');
  const swap = (buf: Buffer, from: string, to: string): Buffer => {
    if (to.length !== from.length) throw new Error('same-length replacement only');
    const i = buf.indexOf(Buffer.from(from, 'ascii'));
    if (i < 0) throw new Error('marker not found');
    const c = Buffer.from(buf);
    c.write(to, i, 'ascii');
    return c;
  };
  const full = swap(swap(Buffer.from(basic.toSchema().toBER(false)), MARK_TU, tu), MARK_PA, pa);
  const parsed = asn1js.fromBER(ab(new Uint8Array(full)));
  const parts = (parsed.result as asn1js.Sequence).valueBlock.value;
  const tbs = Buffer.from(parts[0]!.valueBeforeDecodeView);
  const algId = Buffer.from(parts[1]!.valueBeforeDecodeView);
  const sig = nodeSign('sha384', tbs, KEYS.get(signer.name)!); // DER ECDSA signature, as X.509/OCSP carry it
  const bitStr = Buffer.from(new asn1js.BitString({ valueHex: ab(new Uint8Array(sig)) }).toBER(false));
  const rest = parts.slice(3).map((p) => Buffer.from(p.valueBeforeDecodeView));
  const seqBody = Buffer.concat([tbs, algId, bitStr, ...rest]);
  const lenBytes = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
  const basicBytes = Buffer.concat([Buffer.from([0x30, ...lenBytes(seqBody.length)]), seqBody]);
  const resp = new pkijs.OCSPResponse({
    responseStatus: new asn1js.Enumerated({ value: 0 }),
    responseBytes: new pkijs.ResponseBytes({ responseType: '1.3.6.1.5.5.7.48.1.1', response: new asn1js.OctetString({ valueHex: ab(new Uint8Array(basicBytes)) }) }),
  });
  return new Uint8Array(resp.toSchema().toBER(false));
}

describe('r2: malformed OCSP times are refused', () => {
  let root: Ident, ica: Ident, leaf: Ident;
  let chain: X509Certificate[];
  beforeAll(async () => {
    root = await mkIdent('R2 Root', undefined, { ca: true });
    ica = await mkIdent('R2 ICA', root, { ca: true });
    leaf = await mkIdent('R2 Leaf', ica);
    chain = [leaf.cert, ica.cert, root.cert];
  });
  const ok = '20261008230000Z';
  it('control: a well-formed re-signed response verifies GOOD', async () => {
    const r = await verifyNvidiaOcspResponse(await malformed(leaf.cert, ica.cert, ica, ok, ok), { cert: leaf.cert, issuer: ica.cert, chain, nowMs: NOW });
    expect((r as { reason?: string }).reason).toBeUndefined();
    expect(r).toMatchObject({ ok: true, status: 'good' });
  });
  for (const [label, tu, pa] of [
    ['thisUpdate month 13', '20261308230000Z', ok],
    ['thisUpdate day 32', '20261032230000Z', ok],
    ['thisUpdate hour 24', '20261008240000Z', ok],
    ['producedAt month 00', ok, '20260008230000Z'],
  ] as const) {
    it(label, async () => {
      let r: unknown;
      try {
        r = await verifyNvidiaOcspResponse(await malformed(leaf.cert, ica.cert, ica, tu, pa), { cert: leaf.cert, issuer: ica.cert, chain, nowMs: NOW });
      } catch (e) {
        r = { thrown: (e as Error).message };
      }
      expect((r as { ok?: boolean }).ok).toBe(false);
      expect((r as { reason?: string }).reason).toMatch(/malformed \(out-of-range\) ASN\.1 time/);
    });
  }
});

// ---- delegated responder whose certificate validity is malformed / misread ---------------------------------------
const dlen = (n: number) => (n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]));
const dtlv = (t: number, c: Uint8Array) => Buffer.concat([Buffer.from([t]), dlen(c.length), Buffer.from(c)]);
const dseq = (...x: Uint8Array[]) => dtlv(0x30, Buffer.concat(x.map((y) => Buffer.from(y))));
const doid = (hex: string) => dtlv(0x06, Buffer.from(hex, 'hex'));
const dname = (cn: string) => dseq(dtlv(0x31, dseq(doid('550403'), dtlv(0x0c, Buffer.from(cn)))));
/** A delegated OCSP responder certificate (EKU id-kp-OCSPSigning) issued by `issuer`, with raw validity encodings. */
async function delegatedResponder(name: string, issuer: Ident, nb: Uint8Array, na: Uint8Array): Promise<Ident> {
  const kp = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  const pubSpki = new Uint8Array((kp.publicKey as KeyObject).export({ format: 'der', type: 'spki' }));
  const eku = dseq(doid('551d25'), dtlv(0x04, dseq(doid('2b06010505070309'))));
  const alg = dseq(doid('2a8648ce3d040303'));
  const tbs = dseq(dtlv(0xa0, dtlv(0x02, Buffer.from([2]))), dtlv(0x02, Buffer.from([0x55])), alg, dname(issuer.name), dseq(nb, na), dname(name), pubSpki, dtlv(0xa3, dseq(eku)));
  const der = dseq(tbs, alg, dtlv(0x03, Buffer.concat([Buffer.from([0]), nodeSign('sha384', tbs, KEYS.get(issuer.name)!)])));
  const priv = await subtle.importKey('pkcs8', (kp.privateKey as KeyObject).export({ format: 'der', type: 'pkcs8' }), { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
  return { name, priv, pubSpki, cert: new X509Certificate(der) };
}
const dutc = (s: string) => dtlv(0x17, Buffer.from(s, 'ascii'));
const dgen = (s: string) => dtlv(0x18, Buffer.from(s, 'ascii'));

describe('r2: a delegated OCSP responder certificate with unparseable / pre-1000 validity is refused', () => {
  let root: Ident, ica: Ident, leaf: Ident;
  let chain: X509Certificate[];
  beforeAll(async () => {
    root = await mkIdent('R2D Root', undefined, { ca: true });
    ica = await mkIdent('R2D ICA', root, { ca: true });
    leaf = await mkIdent('R2D Leaf', ica);
    chain = [leaf.cert, ica.cert, root.cert];
  });
  for (const [label, na] of [['notAfter second 60 ("Bad time value")', () => dutc('300101000060Z')], ['notAfter year 49 (Date.parse read 2049)', () => dgen('00490101000000Z')]] as const) {
    it(label, async () => {
      const ok = await delegatedResponder('R2D Responder OK', ica, dutc('250101000000Z'), dutc('300101000000Z'));
      const good = await verifyNvidiaOcspResponse(await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ok, embed: [ok.cert], status: 'good' }), { cert: leaf.cert, issuer: ica.cert, chain, nowMs: NOW });
      expect((good as { reason?: string }).reason).toBeUndefined();
      const bad = await delegatedResponder('R2D Responder BAD', ica, dutc('250101000000Z'), na());
      const r = await verifyNvidiaOcspResponse(await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: bad, embed: [bad.cert], status: 'good' }), { cert: leaf.cert, issuer: ica.cert, chain, nowMs: NOW });
      expect(r.ok).toBe(false);
      // second 60 is caught first by the strict ASN.1 time check over the whole response; year 49 by the validity window
      expect((r as { reason?: string }).reason).toMatch(/validity window|malformed \(out-of-range\) ASN\.1 time/);
    });
  }
});
