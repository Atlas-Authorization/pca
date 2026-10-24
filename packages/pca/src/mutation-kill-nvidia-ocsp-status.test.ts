/**
 * 0.4.2 mutation kills: OCSP certStatus / revokedInfo parsing and the time sanity checks, on a SYNTHETIC P-384 PKI (labelled: not
 * NVIDIA; the same builder as attest-nvidia-ocsp.test.ts) with hand-shaped certStatus encodings.
 */
import { generateKeyPairSync, webcrypto, X509Certificate } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { beforeAll, describe, expect, it } from 'vitest';
import { buildNvidiaOcspRequest, verifyNvidiaOcspResponse } from './attest-nvidia-ocsp';

const NOW = Date.parse('2026-10-08T23:08:00Z');

const subtle = webcrypto.subtle;
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
  rawStatus?: asn1js.BaseBlock;
  producedAt?: number;
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
  if (o.rawStatus) sr.certStatus = o.rawStatus;
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
  basic.tbsResponseData.producedAt = new Date(o.producedAt ?? tu);
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

describe('certStatus / revokedInfo parsing', () => {
  let root: Ident, ica: Ident, leaf: Ident;
  beforeAll(async () => {
    root = await mkIdent('SYN Root', undefined, { ca: true });
    ica = await mkIdent('SYN ICA', root, { ca: true });
    leaf = await mkIdent('SYN Leaf', ica);
  });
  const chain = () => [leaf.cert, ica.cert, root.cert];
  const run = async (o: Partial<MkResp>, extra: Record<string, unknown> = {}) => {
    const der = await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ica, status: 'good', ...o });
    return verifyNvidiaOcspResponse(der, { cert: leaf.cert, issuer: ica.cert, chain: chain(), nowMs: NOW, ...extra } as never);
  };
  const ctx = (tagNumber: number, tagClass: number, value: asn1js.BaseBlock[] = []) => new asn1js.Constructed({ idBlock: { tagClass, tagNumber }, value });
  const prim = (tagNumber: number, tagClass = 3) => new asn1js.Primitive({ idBlock: { tagClass, tagNumber }, valueHex: new ArrayBuffer(0) });
  const gt = (d: Date) => new asn1js.GeneralizedTime({ valueDate: d });
  const reason = (n: number) => new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [new asn1js.Enumerated({ value: n })] });
  const rej = (r: Awaited<ReturnType<typeof run>>) => (r.ok ? 'ok' : r.reason);

  const SCHEMA = /^OCSP response rejected: /;
  it('good / unknown / revoked are the accepted CHOICE alternatives; the pkijs schema itself refuses any other tag or class before our code sees it', async () => {
    expect(await run({ rawStatus: prim(0) })).toMatchObject({ ok: true, status: 'good' });
    expect(await run({ rawStatus: prim(2) })).toMatchObject({ ok: true, status: 'unknown' });
    for (const bad of [prim(3), prim(4), prim(0, 1), prim(1, 2), ctx(1, 3, []), ctx(1, 3, [new asn1js.Integer({ value: 5 })])]) {
      expect(rej(await run({ rawStatus: bad }))).toMatch(SCHEMA);
    }
  });
  it('revokedInfo: the time is a GeneralizedTime, the reason an optional [0] ENUMERATED', async () => {
    const t = new Date(NOW - 3_600_000);
    expect(await run({ rawStatus: ctx(1, 3, [gt(t), reason(4)]) })).toMatchObject({ ok: true, status: 'revoked', revokedAt: NOW - 3_600_000, revocationReason: 4 });
    expect(await run({ rawStatus: ctx(1, 3, [gt(t), reason(0)]) })).toMatchObject({ ok: true, status: 'revoked', revocationReason: 0 });
    const none = await run({ rawStatus: ctx(1, 3, [gt(t)]) });
    expect(none).toMatchObject({ ok: true, status: 'revoked', revokedAt: NOW - 3_600_000 });
    expect(Object.keys(none)).not.toContain('revocationReason');
  });
});

describe('response time sanity', () => {
  let root: Ident, ica: Ident, leaf: Ident;
  beforeAll(async () => {
    root = await mkIdent('SYN Root', undefined, { ca: true });
    ica = await mkIdent('SYN ICA', root, { ca: true });
    leaf = await mkIdent('SYN Leaf', ica);
  });
  const run = async (o: Partial<MkResp>, extra: Record<string, unknown> = {}) => {
    const der = await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ica, status: 'good', ...o });
    const r = await verifyNvidiaOcspResponse(der, { cert: leaf.cert, issuer: ica.cert, chain: [leaf.cert, ica.cert, root.cert], nowMs: NOW, ...extra } as never);
    return r.ok ? 'ok' : r.reason;
  };
  it('thisUpdate and producedAt in the future (beyond the skew) are refused; nextUpdate before thisUpdate is invalid; past nextUpdate is stale', async () => {
    expect(await run({ thisUpdate: NOW + 1000, producedAt: NOW - 1000 })).toBe('response thisUpdate is in the future');
    expect(await run({ thisUpdate: NOW + 1000, producedAt: NOW - 1000 }, { clockSkewMs: 1000 })).toBe('ok');
    expect(await run({ thisUpdate: NOW - 1000, producedAt: NOW + 1000 })).toBe('response producedAt is in the future');
    expect(await run({ thisUpdate: NOW - 1000, producedAt: NOW + 1000 }, { clockSkewMs: 1000 })).toBe('ok');
    expect(await run({ thisUpdate: NOW - 1000, nextUpdate: NOW - 2000 })).toBe('response nextUpdate is invalid');
    expect(await run({ thisUpdate: NOW - 1000, nextUpdate: NOW - 1000 }, { nowMs: NOW - 1000 })).toBe('ok');
    expect(await run({ thisUpdate: NOW - 2000, nextUpdate: NOW - 1 })).toBe('response is stale (past nextUpdate)');
    expect(await run({ thisUpdate: NOW - 2000, nextUpdate: NOW })).toBe('ok');
  });
});
