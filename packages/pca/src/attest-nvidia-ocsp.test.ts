/**
 * Tests for NVIDIA OCSP revocation: REAL request/response pairs captured from `ocsp.ndis.nvidia.com` on
 * 2026-10-08 (fixtures/real-nvidia-cc/ocsp) against the genuine H100 device chain. REVOKED / UNKNOWN / delegated
 * responder edge cases use a clearly-labelled SYNTHETIC P-384 PKI built with the vetted pkijs library (we hold no
 * NVIDIA CA keys).
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { generateKeyPairSync, webcrypto, X509Certificate } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { describe, it, expect, beforeAll } from 'vitest';
import { parsePemChain } from './attest-nvidia-spdm';
import {
  buildNvidiaOcspRequest,
  verifyNvidiaOcspResponse,
  checkNvidiaChainOcsp,
  nvidiaCertOcspUrls,
  fetchNvidiaOcsp,
} from './attest-nvidia-ocsp';

const FX = resolve(__dirname, '../fixtures/real-nvidia-cc');
const OC = resolve(FX, 'ocsp');
const chain = parsePemChain(readFileSync(resolve(FX, 'h100-device-cert-chain.pem'), 'utf8')) as X509Certificate[];
const rd = (n: string): Uint8Array => new Uint8Array(readFileSync(resolve(OC, n)));
const NONCE = Uint8Array.from(Buffer.from('0123456789abcdef0123456789abcdef', 'hex'));
/** Just after the capture (2026-10-08T23:07:30Z). */
const NOW = Date.parse('2026-10-08T23:08:00Z');
const NAMES = ['0-leaf-fmc', '1-brom', '2-provisioner-ica', '3-identity'];
const realResp = (i: number, v: 'nonce' | 'nononce' = 'nonce'): Uint8Array => rd(`${NAMES[i]}.${v}.resp.der`);
const base = (i: number) => ({ cert: chain[i]!, issuer: chain[i + 1]!, chain, nowMs: NOW });

describe('real NVIDIA OCSP responder (captured 2026-10-08)', () => {
  it('our requests are byte-identical to the fixtures and parse with OpenSSL-compatible CertIDs', async () => {
    for (let i = 0; i < 4; i++) {
      const req = await buildNvidiaOcspRequest(chain[i]!, chain[i + 1]!, { nonce: NONCE });
      expect(Buffer.from(req).equals(Buffer.from(rd(`${NAMES[i]}.nonce.req.der`)))).toBe(true);
      const nn = await buildNvidiaOcspRequest(chain[i]!, chain[i + 1]!);
      expect(Buffer.from(nn).equals(Buffer.from(rd(`${NAMES[i]}.nononce.req.der`)))).toBe(true);
    }
  });

  it('BROM, Provisioner ICA and Identity certs: GOOD, signed by NVIDIA delegated responders, nonce echoed', async () => {
    for (const i of [1, 2, 3]) {
      const r = await verifyNvidiaOcspResponse(realResp(i), { ...base(i), expectedNonce: NONCE });
      expect(r.ok, `cert ${i}: ${r.ok ? '' : r.reason}`).toBe(true);
      if (!r.ok) continue;
      expect(r.status).toBe('good');
      expect(r.responder).toBe('delegated');
      expect(r.producedAt).toBe(Date.parse('2026-10-08T23:07:30Z'));
      expect(r.nextUpdate! - r.thisUpdate).toBe(24 * 3600 * 1000);
    }
  });

  it('responses requested without a nonce verify when no nonce is expected', async () => {
    for (const i of [1, 2, 3]) expect((await verifyNvidiaOcspResponse(realResp(i, 'nononce'), base(i))).ok).toBe(true);
  });

  it('the per-device leaf is answered "unauthorized" (responseStatus 6): rejected, truthfully', async () => {
    expect(Buffer.from(realResp(0)).toString('hex')).toBe('3003' + '0a0106');
    const r = await verifyNvidiaOcspResponse(realResp(0), base(0));
    expect(r).toEqual({ ok: false, reason: 'OCSP responseStatus is 6 (not successful)' });
  });

  it('only the ICA and Identity certs advertise an OCSP URL in AIA', async () => {
    expect(await nvidiaCertOcspUrls(chain[0]!)).toEqual([]);
    expect(await nvidiaCertOcspUrls(chain[1]!)).toEqual([]);
    expect(await nvidiaCertOcspUrls(chain[2]!)).toEqual(['http://ocsp.ndis.nvidia.com']);
    expect(await nvidiaCertOcspUrls(chain[3]!)).toEqual(['http://ocsp.ndis.nvidia.com']);
    expect(await nvidiaCertOcspUrls(chain[4]!)).toEqual([]);
  });

  it('rejects a tampered signed field (producedAt digit flipped)', async () => {
    const t = Buffer.from(realResp(2));
    const at = t.indexOf(Buffer.from('20261008230730Z'));
    expect(at).toBeGreaterThan(0);
    t[at + 13] = t[at + 13]! ^ 1;
    const r = await verifyNvidiaOcspResponse(new Uint8Array(t), { ...base(2), expectedNonce: NONCE });
    expect(r.ok).toBe(false);
  });

  it('rejects a tampered signature value', async () => {
    const t = Buffer.from(realResp(1));
    const sigAlg = Buffer.from('300a06082a8648ce3d040303', 'hex');
    const at = t.indexOf(sigAlg);
    expect(at).toBeGreaterThan(0);
    t[at + sigAlg.length + 12] = t[at + sigAlg.length + 12]! ^ 0x80;
    const r = await verifyNvidiaOcspResponse(new Uint8Array(t), base(1));
    expect(r.ok).toBe(false);
  });

  it('rejects a flipped certStatus (good -> revoked would break the signature)', async () => {
    const t = Buffer.from(realResp(3));
    // certStatus good is the 2-byte primitive [0] "80 00"; turn it into unknown "82 00"
    const stamp = Buffer.from('20261008230730Z');
    const thisUpdateAt = t.indexOf(stamp, t.indexOf(stamp) + 1); // 2nd occurrence: producedAt, then thisUpdate
    const at = t.lastIndexOf(Buffer.from('8000', 'hex'), thisUpdateAt);
    expect(at).toBeGreaterThan(0);
    t[at] = 0x82;
    const r = await verifyNvidiaOcspResponse(new Uint8Array(t), base(3));
    expect(r.ok).toBe(false);
  });

  it('rejects a response for the wrong issuer', async () => {
    const r = await verifyNvidiaOcspResponse(realResp(1), { ...base(1), issuer: chain[3]! });
    expect(r.ok).toBe(false);
  });

  it('rejects a response for a different certificate (wrong serial)', async () => {
    const r = await verifyNvidiaOcspResponse(realResp(2), { ...base(3) });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/no SingleResponse matches/);
  });

  it('rejects a stale response (past nextUpdate) and a response from the future', async () => {
    const stale = await verifyNvidiaOcspResponse(realResp(2), { ...base(2), nowMs: NOW + 25 * 3600 * 1000 });
    expect(stale).toEqual({ ok: false, reason: 'response is stale (past nextUpdate)' });
    const early = await verifyNvidiaOcspResponse(realResp(2), { ...base(2), nowMs: NOW - 3600 * 1000 });
    expect(early.ok).toBe(false);
    const aged = await verifyNvidiaOcspResponse(realResp(2), { ...base(2), maxAgeMs: 10_000 });
    expect(aged).toEqual({ ok: false, reason: 'response is older than the maximum accepted age' });
  });

  it('nonce: mismatch and absence are rejected when a nonce is expected', async () => {
    const wrong = await verifyNvidiaOcspResponse(realResp(2), { ...base(2), expectedNonce: Uint8Array.from(Buffer.alloc(16, 7)) });
    expect(wrong).toEqual({ ok: false, reason: 'response nonce does not match the request nonce' });
    const none = await verifyNvidiaOcspResponse(realResp(2, 'nononce'), { ...base(2), expectedNonce: NONCE });
    expect(none).toEqual({ ok: false, reason: 'response does not echo the nonce' });
  });

  it('the issuer is always trusted to have signed its delegated responder (chain may be minimal)', async () => {
    const r = await verifyNvidiaOcspResponse(realResp(3), { ...base(3), chain: [chain[4]!] });
    expect(r).toMatchObject({ ok: true, status: 'good', responder: 'delegated' });
  });

  it('garbage / truncated / empty / trailing-byte DER is rejected without throwing', async () => {
    const good = realResp(2);
    for (const bad of [new Uint8Array(0), new Uint8Array([1, 2, 3]), good.subarray(0, 300), good.subarray(0, good.length - 1), Uint8Array.from([...good, 0]), new Uint8Array(1000).fill(0x30)]) {
      const r = await verifyNvidiaOcspResponse(bad, base(2));
      expect(r.ok).toBe(false);
    }
  });

  it('checkNvidiaChainOcsp: the real chain passes with the default (AIA) policy', async () => {
    const r = await checkNvidiaChainOcsp(chain, [realResp(1), realResp(2), realResp(3)], NOW, { expectedNonces: [undefined, NONCE, NONCE, NONCE] });
    expect(r).toEqual({ ok: true, verifiedCrls: 0, verifiedOcsp: 3, statuses: { 0: 'absent', 1: 'good', 2: 'good', 3: 'good' } });
  });

  it('checkNvidiaChainOcsp: missing a response for an AIA cert fails; policy "all" also needs the leaf', async () => {
    const miss = await checkNvidiaChainOcsp(chain, [realResp(2)], NOW);
    expect(miss.ok).toBe(false);
    const all = await checkNvidiaChainOcsp(chain, [realResp(1), realResp(2), realResp(3)], NOW, { requireGood: 'all' });
    expect(all.ok).toBe(false);
    if (!all.ok) expect(all.reason).toMatch(/GH100 A01 GSP FMC LF/);
    const explicit = await checkNvidiaChainOcsp(chain, [realResp(1), realResp(2), realResp(3)], NOW, { requireGood: [1, 2, 3] });
    expect(explicit.ok).toBe(true);
    const bad = await checkNvidiaChainOcsp(chain, [realResp(1)], NOW, { requireGood: [4] });
    expect(bad.ok).toBe(false);
  });

  it('checkNvidiaChainOcsp: fails closed on the unauthorized leaf response, garbage, duplicates, stale and wrong nonce', async () => {
    expect((await checkNvidiaChainOcsp(chain, [], NOW)).ok).toBe(false);
    expect((await checkNvidiaChainOcsp(chain, [realResp(0), realResp(2), realResp(3)], NOW)).ok).toBe(false);
    expect((await checkNvidiaChainOcsp(chain, [new Uint8Array([9, 9]), realResp(2), realResp(3)], NOW)).ok).toBe(false);
    expect((await checkNvidiaChainOcsp(chain, [realResp(2), realResp(2, 'nononce'), realResp(3)], NOW)).ok).toBe(false);
    expect((await checkNvidiaChainOcsp(chain, [realResp(2), realResp(3)], NOW + 48 * 3600 * 1000)).ok).toBe(false);
    expect((await checkNvidiaChainOcsp(chain, [realResp(2), realResp(3)], NOW, { expectedNonces: [undefined, undefined, Uint8Array.from(Buffer.alloc(16, 1))] })).ok).toBe(false);
    // a response matching no chain certificate at all (the root has no OCSP response)
    expect((await checkNvidiaChainOcsp(chain.slice(1), [realResp(1)], NOW)).ok).toBe(false);
  });

  it('fetchNvidiaOcsp POSTs the DER request via an injected fetch (never automatic)', async () => {
    const seen: { url: string; ct: string | null; len: number }[] = [];
    const fake = (async (url: string, init: { headers: Record<string, string>; body: Buffer }) => {
      seen.push({ url, ct: init.headers['content-type'] ?? null, len: init.body.length });
      return new Response(Buffer.from(realResp(2)), { status: 200 });
    }) as unknown as typeof fetch;
    const out = await fetchNvidiaOcsp(chain[2]!, chain[3]!, { fetch: fake, nonce: NONCE });
    expect(seen).toEqual([{ url: 'http://ocsp.ndis.nvidia.com/', ct: 'application/ocsp-request', len: out.request.length }]);
    expect((await verifyNvidiaOcspResponse(out.response, { ...base(2), expectedNonce: NONCE })).ok).toBe(true);
    const down = (async () => new Response('x', { status: 503 })) as unknown as typeof fetch;
    await expect(fetchNvidiaOcsp(chain[2]!, chain[3]!, { fetch: down })).rejects.toThrow(/HTTP 503/);
  });
});

// ── SYNTHETIC P-384 PKI (labelled: not NVIDIA) ────────────────────────────────────────────────

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

describe('synthetic P-384 PKI (labelled: not NVIDIA)', () => {
  let root: Ident, ica: Ident, leaf: Ident, delegated: Ident, noEku: Ident, rogueCa: Ident, rogueResp: Ident, expired: Ident;
  let synth: X509Certificate[];
  beforeAll(async () => {
    root = await mkIdent('SYN Root', undefined, { ca: true });
    ica = await mkIdent('SYN ICA', root, { ca: true });
    leaf = await mkIdent('SYN Leaf', ica);
    delegated = await mkIdent('SYN Responder', ica, { eku: ['1.3.6.1.5.5.7.3.9'] });
    noEku = await mkIdent('SYN NoEku', ica, { eku: ['1.3.6.1.5.5.7.3.1'] });
    rogueCa = await mkIdent('SYN Rogue CA', undefined, { ca: true });
    rogueResp = await mkIdent('SYN Rogue Responder', rogueCa, { eku: ['1.3.6.1.5.5.7.3.9'] });
    expired = await mkIdent('SYN Expired Responder', ica, { eku: ['1.3.6.1.5.5.7.3.9'], notBefore: NOW - 86400_000 * 100, notAfter: NOW - 86400_000 });
    synth = [leaf.cert, ica.cert, root.cert];
  });
  const v = (der: Uint8Array, extra: Partial<Parameters<typeof verifyNvidiaOcspResponse>[1]> = {}) =>
    verifyNvidiaOcspResponse(der, { cert: leaf.cert, issuer: ica.cert, chain: synth, nowMs: NOW, ...extra });

  it('direct response signed by the issuing CA key (byName and byKey), GOOD', async () => {
    for (const by of ['name', 'key'] as const) {
      const r = await v(await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ica, status: 'good', by }));
      expect(r, by).toMatchObject({ ok: true, status: 'good', responder: 'issuer' });
    }
  });

  it('REVOKED is reported with time and reason; chain check fails closed on it', async () => {
    const der = await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ica, status: 'revoked', reason: 1 });
    const r = await v(der);
    expect(r).toMatchObject({ ok: true, status: 'revoked', revocationReason: 1, revokedAt: NOW - 3600_000 });
    const c = await checkNvidiaChainOcsp(synth, [der], NOW, { requireGood: [] });
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.reason).toMatch(/SYN Leaf.*revoked/s);
    const noReason = await v(await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ica, status: 'revoked' }));
    expect(noReason).toMatchObject({ ok: true, status: 'revoked' });
  });

  it('UNKNOWN: verified as unknown; fails when required, tolerated when not required', async () => {
    const der = await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ica, status: 'unknown' });
    expect(await v(der)).toMatchObject({ ok: true, status: 'unknown' });
    const req = await checkNvidiaChainOcsp(synth, [der], NOW, { requireGood: [0] });
    expect(req.ok).toBe(false);
    const opt = await checkNvidiaChainOcsp(synth, [der], NOW, { requireGood: [] });
    expect(opt).toMatchObject({ ok: true, statuses: { 0: 'unknown', 1: 'absent' } });
  });

  it('delegated responder (EKU OCSPSigning, signed by the ICA) is accepted, byName and byKey', async () => {
    for (const by of ['name', 'key'] as const) {
      const r = await v(await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: delegated, embed: [delegated.cert], status: 'good', by }));
      expect(r, by).toMatchObject({ ok: true, status: 'good', responder: 'delegated' });
    }
  });

  it('delegated responder: missing EKU, foreign CA, expired cert, or not embedded are all rejected', async () => {
    const cases: [string, Ident, X509Certificate[] | undefined][] = [
      ['no OCSPSigning EKU', noEku, [noEku.cert]],
      ['signed by a CA outside the chain', rogueResp, [rogueResp.cert]],
      ['expired responder cert', expired, [expired.cert]],
      ['not embedded', delegated, undefined],
    ];
    for (const [label, signer, embed] of cases) {
      const r = await v(await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer, ...(embed ? { embed } : {}), status: 'good' }));
      expect(r.ok, label).toBe(false);
    }
  });

  it('a stranger key (not issuer, not delegated) cannot vouch; responderID naming the issuer with a foreign key fails', async () => {
    const stranger = await mkIdent('SYN ICA', undefined); // same name as the issuer, different key
    const r = await v(await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: stranger, status: 'good' }));
    expect(r.ok).toBe(false);
  });

  it('nonce echo (synthetic): match ok, mismatch / absent rejected', async () => {
    const n = Uint8Array.from(Buffer.alloc(20, 5));
    const der = await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ica, status: 'good', nonce: n });
    expect((await v(der, { expectedNonce: n })).ok).toBe(true);
    expect((await v(der, { expectedNonce: Uint8Array.from(Buffer.alloc(20, 6)) })).ok).toBe(false);
    const plain = await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ica, status: 'good' });
    expect((await v(plain, { expectedNonce: n })).ok).toBe(false);
  });

  it('nextUpdate absent: bounded by maxAge; CertID hash algorithms sha1/sha256 accepted', async () => {
    const der = await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ica, status: 'good', nextUpdate: null, thisUpdate: NOW - 3600_000 });
    expect((await v(der)).ok).toBe(true);
    expect((await v(der, { maxAgeMs: 1800_000 })).ok).toBe(false);
    expect((await v(der, { nowMs: NOW + 8 * 86400_000 })).ok).toBe(false);
    for (const hash of ['sha1', 'sha256'] as const) {
      expect((await v(await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: ica, status: 'good', hash }))).ok, hash).toBe(true);
    }
  });

  it('ICA-level response (issuer = root) and a full synthetic chain with two required certs', async () => {
    const a = await mkResponse({ cert: leaf.cert, issuer: ica.cert, signer: delegated, embed: [delegated.cert], status: 'good' });
    const rootResp = await mkIdent('SYN Root Responder', root, { eku: ['1.3.6.1.5.5.7.3.9'] });
    const b = await mkResponse({ cert: ica.cert, issuer: root.cert, signer: rootResp, embed: [rootResp.cert], status: 'good' });
    const c = await checkNvidiaChainOcsp(synth, [a, b], NOW, { requireGood: 'all' });
    expect(c).toEqual({ ok: true, verifiedCrls: 0, verifiedOcsp: 2, statuses: { 0: 'good', 1: 'good' } });
    // a revoked ICA fails even if the leaf is good and the ICA is not "required"
    const rb = await mkResponse({ cert: ica.cert, issuer: root.cert, signer: rootResp, embed: [rootResp.cert], status: 'revoked', reason: 5 });
    const d = await checkNvidiaChainOcsp(synth, [a, rb], NOW, { requireGood: [0] });
    expect(d.ok).toBe(false);
  });
});
