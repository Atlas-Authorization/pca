/**
 * Mutation-kill suite for attest-nvidia-ocsp.ts. OCSP responses come from a local builder that can vary every field the verifier
 * reads (signature algorithm, multiple SingleResponses, raw nonce, custom certStatus ...), over the synthetic NVIDIA device PKI.
 */
import { createSign, generateKeyPairSync, X509Certificate } from 'node:crypto';
import * as asn1 from 'asn1js';
import * as pkijs from 'pkijs';
import { describe, expect, it } from 'vitest';
// The module under test is loaded lazily from INSIDE the tests: Stryker attributes load-time (static) coverage to the test that triggers the
// import, so the very first test below exercises every module-level table.
type Ocsp = typeof import('./attest-nvidia-ocsp');
const mod = (): Promise<Ocsp> => import('./attest-nvidia-ocsp');
const buildNvidiaOcspRequest: Ocsp['buildNvidiaOcspRequest'] = async (...a) => (await mod()).buildNvidiaOcspRequest(...a);
const checkNvidiaChainOcsp: Ocsp['checkNvidiaChainOcsp'] = async (...a) => (await mod()).checkNvidiaChainOcsp(...a);
const fetchNvidiaOcsp: Ocsp['fetchNvidiaOcsp'] = async (...a) => (await mod()).fetchNvidiaOcsp(...a);
const nvidiaCertOcspUrls: Ocsp['nvidiaCertOcspUrls'] = async (...a) => (await mod()).nvidiaCertOcspUrls(...a);
const verifyNvidiaOcspResponse: Ocsp['verifyNvidiaOcspResponse'] = async (...a) => (await mod()).verifyNvidiaOcspResponse(...a);
import { parsePemChain } from './attest-nvidia-spdm';
import { forgeNvidiaScenario, forgeOcspResponderCert, forgeOcspResponse } from './test-support/forge-spdm';
import {
  cat,
  ctx,
  ctxPrim,
  digest,
  dn,
  ecdsaSign,
  ext,
  extension,
  forgeCert,
  forgeKey,
  generalizedTime,
  enumerated,
  integer,
  nul,
  octets,
  oid,
  seq,
  serialFor,
  tlv,
  bitString,
  hexToBytes,
  type ForgedCert,
  type ForgeKey,
} from './test-support/forge-x509';

const sc = forgeNvidiaScenario({ seed: 'ocsp-kill' });
const NOW = sc.nowMs;
const x = (c: ForgedCert) => new X509Certificate(Buffer.from(c.der));
const chain = parsePemChain(sc.device.chainPem);
const D = sc.device.certs; // leaf first, root last (index 4)
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const at = (ms: number) => new Date(ms);
const HASH_OID = { sha1: '1.3.14.3.2.26', sha256: '2.16.840.1.101.3.4.2.1', sha384: '2.16.840.1.101.3.4.2.2', sha512: '2.16.840.1.101.3.4.2.3' } as const;
const SIG_OID = { 'ec-sha256': '1.2.840.10045.4.3.2', 'ec-sha384': '1.2.840.10045.4.3.3', 'ec-sha512': '1.2.840.10045.4.3.4', 'rsa-sha256': '1.2.840.113549.1.1.11', 'rsa-sha384': '1.2.840.113549.1.1.12', 'rsa-sha512': '1.2.840.113549.1.1.13' } as const;

interface Single {
  cert: ForgedCert;
  issuer: ForgedCert;
  hash?: keyof typeof HASH_OID;
  hashOid?: string;
  serial?: Uint8Array;
  nameHash?: Uint8Array;
  keyHash?: Uint8Array;
  status?: 'good' | 'revoked' | 'unknown' | Uint8Array;
  revokedAt?: string;
  reason?: number;
  thisUpdate?: number;
  nextUpdate?: number | null;
}
interface Resp {
  singles: Single[];
  producedAt?: number;
  responder?: { cert: ForgedCert; key: { sign(tbs: Uint8Array, sigKind: keyof typeof SIG_OID): Uint8Array } };
  rid?: 'name' | 'key';
  sigOid?: string;
  sigKind?: keyof typeof SIG_OID;
  embed?: ForgedCert[] | 'responder' | 'none';
  extensions?: Uint8Array[];
  signWith?: ForgeKey;
}
const ecKeyOf = (k: ForgeKey) => ({ sign: (tbs: Uint8Array, kind: keyof typeof SIG_OID) => ecdsaSign(k, kind.endsWith('512') ? ('sha512' as never) : kind.endsWith('256') ? 'sha256' : 'sha384', tbs).der });

function build(r: Resp): Uint8Array {
  const t0 = NOW - HOUR;
  const singles = r.singles.map((s) => {
    const h = s.hash ?? 'sha384';
    const nameHash = s.nameHash ?? digest(h as never, dn(s.issuer.subject));
    const keyHash = s.keyHash ?? digest(h as never, s.issuer.key.pub);
    const serialEl = s.serial ? tlv(0x02, s.serial) : integer(hexToBytes(s.cert.serialHex.length % 2 ? `0${s.cert.serialHex}` : s.cert.serialHex));
    const certId = seq(seq(oid(s.hashOid ?? HASH_OID[h]), nul()), octets(nameHash), octets(keyHash), serialEl);
    const st = s.status ?? 'good';
    const certStatus =
      st instanceof Uint8Array
        ? st
        : st === 'good'
          ? Uint8Array.of(0x80, 0x00)
          : st === 'unknown'
            ? Uint8Array.of(0x82, 0x00)
            : tlv(0xa1, tlv(0x18, new TextEncoder().encode(s.revokedAt ?? '20261019120000Z')), ...(s.reason !== undefined ? [ctx(0, enumerated(s.reason))] : []));
    const next = s.nextUpdate === undefined ? NOW + 30 * DAY : s.nextUpdate;
    return seq(certId, certStatus, generalizedTime(at(s.thisUpdate ?? t0)), ...(next === null ? [] : [ctx(0, generalizedTime(at(next)))]));
  });
  const rc = r.responder?.cert ?? r.singles[0]!.issuer;
  const ridKind = r.rid ?? (r.responder ? 'key' : 'name');
  const rid = ridKind === 'key' ? ctx(2, octets(digest('sha1', rc.key.pub))) : ctx(1, dn(rc.subject));
  const tbs = seq(rid, generalizedTime(at(r.producedAt ?? t0)), seq(...singles), ...(r.extensions && r.extensions.length > 0 ? [ctx(1, seq(...r.extensions))] : []));
  const kind = r.sigKind ?? 'ec-sha384';
  const sigOid = r.sigOid ?? SIG_OID[kind];
  const signer = r.responder ? r.responder.key : ecKeyOf(r.signWith ?? r.singles[0]!.issuer.key);
  const sig = signer.sign(tbs, kind);
  const embedList = r.embed === 'none' ? [] : Array.isArray(r.embed) ? r.embed : r.responder ? [r.responder.cert] : [];
  const embed = embedList.length > 0 ? [ctx(0, seq(...embedList.map((c) => c.der)))] : [];
  const basic = seq(tbs, seq(oid(sigOid)), bitString(sig), ...embed);
  return seq(enumerated(0), tlv(0xa0, seq(oid('1.3.6.1.5.5.7.48.1.1'), octets(basic))));
}
const nonceExt = (raw: Uint8Array) => extension('1.3.6.1.5.5.7.48.1.2', false, raw);
const verify = (der: Uint8Array, i = 0, o: Record<string, unknown> = {}) => verifyNvidiaOcspResponse(der, { cert: chain[i]!, issuer: chain[i + 1]!, chain, nowMs: NOW, ...o });
const single = (i = 0, o: Partial<Single> = {}): Single => ({ cert: D[i]!, issuer: D[i + 1]!, ...o });
const good = (o: Partial<Resp> = {}, s: Partial<Single> = {}, i = 0) => build({ singles: [single(i, s)], ...o });
const reason = async (der: Uint8Array, i = 0, o: Record<string, unknown> = {}) => {
  const r = await verify(der, i, o);
  return r.ok ? 'OK' : r.reason;
};
const delegated = (over: Parameters<typeof forgeOcspResponderCert>[2] = {}, signerIdx = 1) => {
  const cert = forgeOcspResponderCert(D[signerIdx]!, D[signerIdx]!.key, { seed: 'delegate', ...over });
  return { cert, key: ecKeyOf(cert.key) };
};


const rsaFixture = (() => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spki = Uint8Array.from(rsa.publicKey.export({ type: 'spki', format: 'der' }));
  const cert = forgeCert({
    subject: [['CN', 'RSA Responder'], ['O', 'NVIDIA Corporation']],
    issuer: D[1]!.subject,
    subjectKey: { ...forgeKey('rsa-resp', 'P-384'), spki, pub: new Uint8Array(65).fill(4) },
    signer: D[1]!.key,
    serial: serialFor('rsa-resp'),
    notBefore: at(NOW - 400 * DAY),
    notAfter: at(NOW + 400 * DAY),
    sigDigest: 'sha384',
    extensions: [ext.extKeyUsage(['1.3.6.1.5.5.7.3.9'], true)],
  });
  const signer = (hash: string) => ({ sign: (tbs: Uint8Array) => Uint8Array.from(createSign(hash).update(tbs).sign(rsa.privateKey)) });
  return { cert, signer };
})();
const tables = {
  async requestHashes() {
    for (const [h, oidStr] of Object.entries(HASH_OID)) {
      const der = await buildNvidiaOcspRequest(chain[0]!, chain[1]!, h === 'sha384' ? {} : { hash: h as never });
      const req = new pkijs.OCSPRequest({ schema: asn1.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer).result });
      const id = req.tbsRequest.requestList[0]!.reqCert;
      expect(id.hashAlgorithm.algorithmId).toBe(oidStr);
      expect(Buffer.from(id.issuerNameHash.valueBlock.valueHexView).toString('hex')).toBe(Buffer.from(digest(h as never, dn(D[1]!.subject))).toString('hex'));
    }
  },
  async certIdHashes() {
    for (const h of ['sha1', 'sha256', 'sha384', 'sha512'] as const) expect(await reason(build({ singles: [single(0, { hash: h })] })), h).toBe('OK');
    expect(await reason(build({ singles: [single(0, { hashOid: '1.2.3.4' })] }))).toBe('no SingleResponse matches the certificate (serial / issuer hashes differ)');
  },
  async ecSignatureAlgorithms() {
    for (const kind of ['ec-sha256', 'ec-sha384', 'ec-sha512'] as const) {
      const signer = { sign: (tbs: Uint8Array) => ecdsaSign(D[1]!.key, kind === 'ec-sha512' ? ('sha512' as never) : kind === 'ec-sha256' ? 'sha256' : 'sha384', tbs).der };
      expect(await reason(build({ singles: [single()], responder: { cert: D[1]!, key: signer }, rid: 'name', embed: 'none', sigKind: kind })), kind).toBe('OK');
      // an algorithm identifier that disagrees with the real digest fails
      const wrong = { sign: (tbs: Uint8Array) => ecdsaSign(D[1]!.key, kind === 'ec-sha256' ? 'sha384' : 'sha256', tbs).der };
      expect(await reason(build({ singles: [single()], responder: { cert: D[1]!, key: wrong }, rid: 'name', embed: 'none', sigKind: kind })), `${kind} wrong digest`).toBe('OCSP response signature does not verify under the issuer key');
    }
    // an RSA algorithm identifier on an EC-signed response is refused
    expect(await reason(build({ singles: [single()], sigKind: 'ec-sha384', sigOid: SIG_OID['rsa-sha384'] }))).toBe('OCSP response signature does not verify under the issuer key');
    expect(await reason(build({ singles: [single()], sigKind: 'ec-sha384', sigOid: SIG_OID['rsa-sha256'] }))).toBe('OCSP response signature does not verify under the issuer key');
    expect(await reason(build({ singles: [single()], sigKind: 'ec-sha384', sigOid: SIG_OID['rsa-sha512'] }))).toBe('OCSP response signature does not verify under the issuer key');
  },
  async rsaSignatureAlgorithms() {
    for (const [kind, hash] of [['rsa-sha256', 'sha256'], ['rsa-sha384', 'sha384'], ['rsa-sha512', 'sha512']] as const) {
      expect(await reason(build({ singles: [single()], responder: { cert: rsaFixture.cert, key: rsaFixture.signer(hash) }, rid: 'name', sigKind: kind })), kind).toBe('OK');
      const other = hash === 'sha256' ? 'sha384' : 'sha256';
      expect(await reason(build({ singles: [single()], responder: { cert: rsaFixture.cert, key: rsaFixture.signer(other) }, rid: 'name', sigKind: kind })), `${kind} wrong hash`).toMatch(/does not verify/);
    }
    // an EC algorithm identifier on an RSA-signed response is refused (key family mismatch)
    for (const ecKind of ['ec-sha256', 'ec-sha384', 'ec-sha512'] as const) {
      expect(await reason(build({ singles: [single()], responder: { cert: rsaFixture.cert, key: rsaFixture.signer('sha384') }, rid: 'name', sigKind: ecKind })), ecKind).toBe('OCSP response signature does not verify under the delegated responder key');
    }
  },
  async oids() {
    expect(await nvidiaCertOcspUrls(chain[2]!)).toEqual(['http://ocsp.ndis.nvidia.com']); // AIA + id-ad-ocsp
    const nonce = Uint8Array.of(1, 2, 3, 4);
    const req = await buildNvidiaOcspRequest(chain[0]!, chain[1]!, { nonce });
    const parsed = new pkijs.OCSPRequest({ schema: asn1.fromBER(req.buffer.slice(req.byteOffset, req.byteOffset + req.byteLength) as ArrayBuffer).result });
    expect(parsed.tbsRequest.requestExtensions![0]!.extnID).toBe('1.3.6.1.5.5.7.48.1.2');
    const d = delegated();
    expect(await reason(build({ singles: [single()], responder: d, extensions: [nonceExt(octets(nonce))] }), 0, { expectedNonce: nonce })).toBe('OK'); // basic-response type, nonce OID, OCSPSigning EKU
    const { cert: noEkuCert, key } = delegated({ seed: 'oid-no-eku', eku: ['1.3.6.1.5.5.7.3.1'] });
    expect(await reason(build({ singles: [single()], responder: { cert: noEkuCert, key } }))).toBe('delegated responder certificate lacks the id-kp-OCSPSigning EKU');
    expect(await reason(build({ singles: [single()], responder: d, extensions: [extension('1.3.6.1.5.5.7.48.1.3', false, octets(nonce))] }), 0, { expectedNonce: nonce })).toBe('response does not echo the nonce');
  },
};

describe('constants and module-level tables (first test: owns the load-time coverage)', () => {
  it('values, and every table entry exercised end to end', async () => {
    const m = await mod();
    expect(m.NVIDIA_OCSP_URL).toBe('http://ocsp.ndis.nvidia.com/');
    expect(m.NVIDIA_OCSP_DEFAULT_MAX_AGE_MS).toBe(604_800_000);
    await tables.requestHashes();
    await tables.certIdHashes();
    await tables.ecSignatureAlgorithms();
    await tables.rsaSignatureAlgorithms();
    await tables.oids();
  });
});

describe('buildNvidiaOcspRequest', () => {
  const parse = (der: Uint8Array) => {
    const a = asn1.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer);
    expect(a.offset).toBe(der.length);
    return new pkijs.OCSPRequest({ schema: a.result });
  };
  it('CertID: hash OID per algorithm (default SHA-384), name/key hashes, serial', async () => {
    for (const [h, oidStr] of Object.entries(HASH_OID)) {
      const req = parse(await buildNvidiaOcspRequest(chain[0]!, chain[1]!, h === 'sha384' ? {} : { hash: h as never }));
      const id = req.tbsRequest.requestList[0]!.reqCert;
      expect(id.hashAlgorithm.algorithmId).toBe(oidStr);
      expect(Buffer.from(id.issuerNameHash.valueBlock.valueHexView).toString('hex')).toBe(Buffer.from(digest(h as never, dn(D[1]!.subject))).toString('hex'));
      expect(Buffer.from(id.issuerKeyHash.valueBlock.valueHexView).toString('hex')).toBe(Buffer.from(digest(h as never, D[1]!.key.pub)).toString('hex'));
      expect(Buffer.from(id.serialNumber.valueBlock.valueHexView).toString('hex').replace(/^00/, '')).toBe(D[0]!.serialHex.padStart(2, '0'));
    }
    expect(parse(await buildNvidiaOcspRequest(chain[0]!, chain[1]!)).tbsRequest.requestExtensions).toBeUndefined();
  });
  it('nonce: 1..32 bytes, carried in a non-critical id-pkix-ocsp-nonce extension as an OCTET STRING', async () => {
    const e = new RangeError('nonce must be 1..32 bytes');
    await expect(buildNvidiaOcspRequest(chain[0]!, chain[1]!, { nonce: new Uint8Array(0) })).rejects.toThrow(e);
    await expect(buildNvidiaOcspRequest(chain[0]!, chain[1]!, { nonce: new Uint8Array(33) })).rejects.toThrow(e);
    for (const n of [1, 2, 31, 32]) {
      const nonce = Uint8Array.from({ length: n }, (_, i) => i + 1);
      const req = parse(await buildNvidiaOcspRequest(chain[0]!, chain[1]!, { nonce }));
      const ex = req.tbsRequest.requestExtensions!;
      expect(ex.length).toBe(1);
      expect(ex[0]!.extnID).toBe('1.3.6.1.5.5.7.48.1.2');
      expect(ex[0]!.critical ?? false).toBe(false);
      const inner = asn1.fromBER(ex[0]!.extnValue.valueBlock.valueHexView.slice().buffer);
      expect(Array.from(new Uint8Array((inner.result as asn1.OctetString).valueBlock.valueHexView))).toEqual(Array.from(nonce));
    }
  });
});

describe('verifyNvidiaOcspResponse: result shape', () => {
  it('good / unknown / revoked, with and without nextUpdate', async () => {
    const t = NOW - HOUR;
    const n = NOW + 30 * DAY;
    const sec = (ms: number) => Math.floor(ms / 1000) * 1000;
    expect(await verify(good())).toStrictEqual({ ok: true, status: 'good', thisUpdate: sec(t), nextUpdate: sec(n), producedAt: sec(t), responder: 'issuer' });
    expect(await verify(good({}, { nextUpdate: null }))).toStrictEqual({ ok: true, status: 'good', thisUpdate: sec(t), producedAt: sec(t), responder: 'issuer' });
    expect(await verify(good({}, { status: 'unknown' }))).toStrictEqual({ ok: true, status: 'unknown', thisUpdate: sec(t), nextUpdate: sec(n), producedAt: sec(t), responder: 'issuer' });
    expect(await verify(good({}, { status: 'unknown', nextUpdate: null }))).toStrictEqual({ ok: true, status: 'unknown', thisUpdate: sec(t), producedAt: sec(t), responder: 'issuer' });
    const rv = await verify(good({}, { status: 'revoked', reason: 4, revokedAt: '20261019123456Z' }));
    expect(rv).toStrictEqual({ ok: true, status: 'revoked', thisUpdate: sec(t), nextUpdate: sec(n), producedAt: sec(t), revokedAt: Date.UTC(2026, 9, 19, 12, 34, 56), revocationReason: 4, responder: 'issuer' });
    const rv0 = await verify(good({}, { status: 'revoked', reason: 0, nextUpdate: null }));
    expect(rv0).toMatchObject({ ok: true, status: 'revoked', revocationReason: 0 });
    expect('nextUpdate' in rv0).toBe(false);
    const rvNoReason = await verify(good({}, { status: 'revoked' }));
    expect(rvNoReason.ok && 'revocationReason' in rvNoReason).toBe(false);
    expect(rvNoReason.ok && (rvNoReason as { revokedAt: number }).revokedAt).toBe(Date.UTC(2026, 9, 19, 12, 0, 0));
  });
  it('malformed certStatus variants', async () => {
    const schema = "OCSP response rejected: Object's schema was not verified against input data for BasicOCSPResponse";
    // the ASN.1 schema refuses non-context certStatus choices before the verifier's own check is reached
    expect(await reason(good({}, { status: Uint8Array.of(0x05, 0x00) }))).toBe(schema);
    expect(await reason(good({}, { status: Uint8Array.of(0x83, 0x00) }))).toBe(schema);
    expect(await reason(good({}, { status: tlv(0xa1) }))).toBe(schema);
    // a RevokedInfo time that is not plain YYYYMMDDHHMMSSZ is refused by the verifier
    expect(await reason(good({}, { status: 'revoked', revokedAt: '20261019123456.5Z' }))).toBe('malformed revoked certStatus');
    expect(await reason(good({}, { status: 'revoked', revokedAt: '2026101912345Z' }))).toBe('OCSP response rejected: Wrong input string for conversion');
  });
});

describe('verifyNvidiaOcspResponse: envelope', () => {
  const wrap = (status: number, body?: Uint8Array) => seq(enumerated(status), ...(body ? [body] : []));
  it('DER, trailing bytes, responseStatus, responseBytes, responseType', async () => {
    expect(await reason(new Uint8Array([0xff, 0x00]))).toBe('response is not valid DER');
    expect(await reason(new Uint8Array([0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]))).toBe('response is not valid DER');
    expect(await reason(cat(good(), new Uint8Array([0])))).toBe('trailing bytes after OCSPResponse');
    expect(await reason(forgeOcspResponse({ cert: D[0]!, issuer: D[1]!, thisUpdate: at(NOW - HOUR), responseStatus: 1 }))).toBe('OCSP responseStatus is 1 (not successful)');
    expect(await reason(forgeOcspResponse({ cert: D[0]!, issuer: D[1]!, thisUpdate: at(NOW - HOUR), responseStatus: 6 }))).toBe('OCSP responseStatus is 6 (not successful)');
    expect(await reason(wrap(0))).toBe('successful response carries no responseBytes');
    expect(await reason(forgeOcspResponse({ cert: D[0]!, issuer: D[1]!, thisUpdate: at(NOW - HOUR), responseType: '1.3.6.1.5.5.7.48.1.2' }))).toBe('responseType is not id-pkix-ocsp-basic');
    expect(await reason(wrap(0, tlv(0xa0, seq(oid('1.3.6.1.5.5.7.48.1.1'), octets(new Uint8Array([0xff, 0x00]))))))).toBe('BasicOCSPResponse is not valid DER');
    expect(await reason(good({ sigOid: '1.2.3.4' }))).toBe('unsupported OCSP signature algorithm 1.2.3.4');
  });
  it('the forger\'s own response is accepted (sanity for the builder)', async () => {
    expect(await reason(forgeOcspResponse({ cert: D[0]!, issuer: D[1]!, thisUpdate: at(NOW - HOUR), nextUpdate: at(NOW + DAY) }))).toBe('OK');
  });
});

describe('verifyNvidiaOcspResponse: CertID matching', () => {
  const none = 'no SingleResponse matches the certificate (serial / issuer hashes differ)';
  it('every CertID hash algorithm is supported; unknown ones never match', async () => {
    for (const h of ['sha1', 'sha256', 'sha384', 'sha512'] as const) expect(await reason(good({}, { hash: h })), h).toBe('OK');
    expect(await reason(good({}, { hashOid: '1.2.3.4' }))).toBe(none);
  });
  it('serial, issuer name hash and issuer key hash must each match', async () => {
    expect(await reason(good({}, { serial: Uint8Array.of(9, 9, 9) }))).toBe(none);
    expect(await reason(good({}, { nameHash: new Uint8Array(48).fill(1) }))).toBe(none);
    expect(await reason(good({}, { keyHash: new Uint8Array(48).fill(1) }))).toBe(none);
    expect(await reason(good({}, { nameHash: new Uint8Array(47) }))).toBe(none); // wrong length
    expect(await reason(build({ singles: [single(0), single(1)] }))).toBe('OK'); // the right one among several
    expect(await reason(build({ singles: [single(0), single(0)] }))).toBe('ambiguous: multiple SingleResponses match the certificate');
    expect(await reason(good(), 1)).toBe(none); // a response for the leaf does not speak for the issuer
  });
  it('serial comparison ignores leading zero padding (including a zero serial)', async () => {
    const key = forgeKey('small-serial', 'P-384');
    const mk = (serial: bigint) => forgeCert({ subject: [['CN', 'leaf-small']], issuer: D[1]!.subject, subjectKey: key, signer: D[1]!.key, serial, notBefore: at(NOW - 400 * DAY), notAfter: at(NOW + 400 * DAY), sigDigest: 'sha384', extensions: [ext.basicConstraints(false)] });
    for (const [serial, wire] of [[5n, [0, 0, 5]], [0x85n, [0, 0, 0x85]], [0n, [0, 0]], [0n, [0]], [0x100n, [0, 1, 0]]] as const) {
      const cert = mk(serial);
      const der = build({ singles: [{ cert, issuer: D[1]!, serial: Uint8Array.from(wire) }] });
      expect(await verifyNvidiaOcspResponse(der, { cert: x(cert), issuer: chain[1]!, chain, nowMs: NOW }).then((r) => (r.ok ? 'OK' : r.reason)), `${serial} ${wire}`).toBe('OK');
    }
    const cert = mk(5n);
    const wrongSerial = build({ singles: [{ cert, issuer: D[1]!, serial: Uint8Array.from([0, 0, 6]) }] });
    expect(await verifyNvidiaOcspResponse(wrongSerial, { cert: x(cert), issuer: chain[1]!, chain, nowMs: NOW }).then((r) => (r.ok ? 'OK' : r.reason))).toBe(none);
    const zeroVsOne = build({ singles: [{ cert: mk(0n), issuer: D[1]!, serial: Uint8Array.from([1]) }] });
    expect(await verifyNvidiaOcspResponse(zeroVsOne, { cert: x(mk(0n)), issuer: chain[1]!, chain, nowMs: NOW }).then((r) => (r.ok ? 'OK' : r.reason))).toBe(none);
  });
});

describe('verifyNvidiaOcspResponse: serial numbers are compared byte-for-byte after stripping only LEADING zero octets', () => {
  it('serials that differ in significant octets never match', async () => {
    const key = forgeKey('trail-serial', 'P-384');
    const mk = (serial: bigint) => forgeCert({ subject: [['CN', 'leaf-trail']], issuer: D[1]!.subject, subjectKey: key, signer: D[1]!.key, serial, notBefore: at(NOW - 400 * DAY), notAfter: at(NOW + 400 * DAY), sigDigest: 'sha384', extensions: [ext.basicConstraints(false)] });
    const cert = mk(0x050000n);
    const ask = (wire: number[]) => verifyNvidiaOcspResponse(build({ singles: [{ cert, issuer: D[1]!, serial: Uint8Array.from(wire) }] }), { cert: x(cert), issuer: chain[1]!, chain, nowMs: NOW }).then((r) => (r.ok ? 'OK' : r.reason));
    expect(await ask([5, 0, 0])).toBe('OK');
    expect(await ask([0, 5, 0, 0])).toBe('OK');
    const none = 'no SingleResponse matches the certificate (serial / issuer hashes differ)';
    expect(await ask([4, 0, 0])).toBe(none);
    expect(await ask([5, 0])).toBe(none);
    expect(await ask([5])).toBe(none);
    expect(await ask([0])).toBe(none);
  });
});

describe('verifyNvidiaOcspResponse: signature algorithms', () => {
  it('ECDSA with SHA-256 / SHA-384 / SHA-512 under an EC issuer or responder', async () => {
    for (const kind of ['ec-sha256', 'ec-sha384', 'ec-sha512'] as const) {
      const signer = { sign: (tbs: Uint8Array) => ecdsaSign(D[1]!.key, kind === 'ec-sha512' ? ('sha512' as never) : kind === 'ec-sha256' ? 'sha256' : 'sha384', tbs).der };
      const r = await reason(build({ singles: [single()], responder: { cert: D[1]!, key: signer }, rid: 'name', embed: 'none', sigKind: kind }));
      expect(r, kind).toBe('OK');
    }
  });
  it('RSA with SHA-256 / 384 / 512 under an RSA delegated responder (and not under an EC key)', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const spki = Uint8Array.from(rsa.publicKey.export({ type: 'spki', format: 'der' }));
    const rcert = forgeCert({
      subject: [['CN', 'RSA Responder'], ['O', 'NVIDIA Corporation']],
      issuer: D[1]!.subject,
      subjectKey: { ...forgeKey('rsa-resp', 'P-384'), spki, pub: new Uint8Array(65).fill(4) },
      signer: D[1]!.key,
      serial: serialFor('rsa-resp'),
      notBefore: at(NOW - 400 * DAY),
      notAfter: at(NOW + 400 * DAY),
      sigDigest: 'sha384',
      extensions: [ext.extKeyUsage(['1.3.6.1.5.5.7.3.9'], true)],
    });
    const rsaSigner = (hash: string) => ({ sign: (tbs: Uint8Array) => Uint8Array.from(createSign(hash).update(tbs).sign(rsa.privateKey)) });
    for (const [kind, hash] of [['rsa-sha256', 'sha256'], ['rsa-sha384', 'sha384'], ['rsa-sha512', 'sha512']] as const) {
      const der = build({ singles: [single()], responder: { cert: rcert, key: rsaSigner(hash) }, rid: 'name', sigKind: kind });
      expect(await reason(der), kind).toBe('OK');
      // an RSA signature algorithm paired with the wrong hash fails verification
      const wrongHash = build({ singles: [single()], responder: { cert: rcert, key: rsaSigner(hash === 'sha256' ? 'sha384' : 'sha256') }, rid: 'name', sigKind: kind });
      expect(await reason(wrongHash), `${kind} wrong hash`).toMatch(/does not verify/);
    }
    // an RSA algorithm identifier on a response signed with an EC key is refused, as is an EC identifier with an RSA key
    const ecWithRsaOid = build({ singles: [single()], sigKind: 'ec-sha384', sigOid: SIG_OID['rsa-sha384'] });
    expect(await reason(ecWithRsaOid)).toBe('OCSP response signature does not verify under the issuer key');
    const rsaWithEcOid = build({ singles: [single()], responder: { cert: rcert, key: rsaSigner('sha384') }, rid: 'name', sigKind: 'ec-sha384' });
    expect(await reason(rsaWithEcOid)).toBe('OCSP response signature does not verify under the delegated responder key');
    // wrong hash for an EC algorithm id
    const ecWrongHash = build({ singles: [single()], signWith: D[1]!.key, sigKind: 'ec-sha384', sigOid: SIG_OID['ec-sha256'] });
    expect(await reason(ecWrongHash)).toBe('OCSP response signature does not verify under the issuer key');
    const ecWrongHash512 = build({ singles: [single()], sigKind: 'ec-sha384', sigOid: SIG_OID['ec-sha512'] });
    expect(await reason(ecWrongHash512)).toBe('OCSP response signature does not verify under the issuer key');
  });
});

describe('verifyNvidiaOcspResponse: responder authentication', () => {
  it('issuer identified by name or by key hash; wrong signature; unknown responder', async () => {
    expect(await verify(good({ rid: 'name' }))).toMatchObject({ ok: true, responder: 'issuer' });
    expect(await verify(good({ rid: 'key' }))).toMatchObject({ ok: true, responder: 'issuer' });
    expect(await reason(good({ signWith: forgeKey('stranger', 'P-384') }))).toBe('OCSP response signature does not verify under the issuer key');
    expect(await reason(good({ rid: 'key', signWith: forgeKey('stranger', 'P-384') }))).toBe('OCSP response signature does not verify under the issuer key');
    // responder named by someone else and signed by someone else, with nothing embedded
    const other = delegated({ seed: 'other-resp' });
    expect(await reason(build({ singles: [single()], responder: other, embed: 'none' }))).toBe('no embedded responder certificate verifies the response');
  });
  it('delegated responder: accepted when signed by the issuer or a chain cert above it', async () => {
    const d1 = delegated({}, 1);
    expect(await verify(build({ singles: [single()], responder: d1 }))).toMatchObject({ ok: true, responder: 'delegated' });
    expect(await verify(build({ singles: [single()], responder: d1, rid: 'name' }))).toMatchObject({ ok: true, responder: 'delegated' });
    const d2 = delegated({ seed: 'above' }, 2); // signed by the cert above the issuer
    expect(await verify(build({ singles: [single()], responder: d2 }))).toMatchObject({ ok: true, responder: 'delegated' });
    const d0 = delegated({ seed: 'below' }, 0); // signed by the leaf, which is BELOW the issuer
    expect(await reason(build({ singles: [single()], responder: d0 }))).toBe('delegated responder certificate is not signed by the supplied NVIDIA chain');
    const stranger = forgeOcspResponderCert(D[1]!, forgeKey('not-nvidia', 'P-384'), { seed: 'stranger-signed' });
    expect(await reason(build({ singles: [single()], responder: { cert: stranger, key: ecKeyOf(stranger.key) } }))).toBe('delegated responder certificate is not signed by the supplied NVIDIA chain');
  });
  it('the issuer need not appear in the supplied chain (then only the issuer itself may sign the responder)', async () => {
    const d1 = delegated({}, 1);
    const der = build({ singles: [single()], responder: d1 });
    expect(await reason(der, 0, { chain: [] })).toBe('OK');
    expect(await reason(der, 0, { chain: [chain[3]!, chain[4]!] })).toBe('OK');
    const dRoot = delegated({ seed: 'root-signed' }, 4);
    expect(await reason(build({ singles: [single()], responder: dRoot }), 0, { chain: [] })).toBe('delegated responder certificate is not signed by the supplied NVIDIA chain');
  });
  it('an issuer found at index 0 of the chain admits the whole chain as signers', async () => {
    // certificate under test = the leaf's own CertID but with the leaf as "issuer" (issuer index 0)
    const d3 = delegated({ seed: 'idx0-above' }, 3);
    const s: Single = { cert: D[0]!, issuer: D[0]! };
    const der = build({ singles: [s], responder: d3 });
    const r = await verifyNvidiaOcspResponse(der, { cert: chain[0]!, issuer: chain[0]!, chain, nowMs: NOW });
    expect(r.ok).toBe(true);
  });
  it('delegated responder failure reasons', async () => {
    const d1 = delegated({}, 1);
    const other = delegated({ seed: 'someone' }, 1);
    expect(await reason(build({ singles: [single()], responder: d1, embed: [other.cert] }))).toBe('embedded certificates do not match the responderID');
    expect(await reason(build({ singles: [single()], responder: d1, embed: [other.cert, d1.cert] }))).toBe('OK');
    expect(await reason(build({ singles: [single()], responder: d1, embed: [d1.cert, other.cert] }))).toBe('OK');
    const noEku = delegated({ seed: 'no-eku', eku: null }, 1);
    expect(await reason(build({ singles: [single()], responder: noEku }))).toBe('delegated responder certificate lacks the id-kp-OCSPSigning EKU');
    const wrongEku = delegated({ seed: 'wrong-eku', eku: ['1.3.6.1.5.5.7.3.1'] }, 1);
    expect(await reason(build({ singles: [single()], responder: wrongEku }))).toBe('delegated responder certificate lacks the id-kp-OCSPSigning EKU');
    const multiEku = delegated({ seed: 'multi-eku', eku: ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.9'] }, 1);
    expect(await reason(build({ singles: [single()], responder: multiEku }))).toBe('OK');
    // key matches the responderID but signed by a different key
    expect(await reason(build({ singles: [single()], responder: { cert: d1.cert, key: ecKeyOf(forgeKey('impostor', 'P-384')) } }))).toBe('OCSP response signature does not verify under the delegated responder key');
    // reasons describe the LAST failing candidate, but a later good one still wins
    expect(await reason(build({ singles: [single()], responder: d1, embed: [noEku.cert, d1.cert] }))).toBe('OK');
  });
  it('responder validity window to the second, with skew', async () => {
    const nb = Math.floor(NOW / 1000) * 1000 - 10 * DAY;
    const na = nb + 20 * DAY;
    const d = delegated({ seed: 'window', notBefore: at(nb), notAfter: at(na) }, 1);
    const der = build({ singles: [single()], responder: d, producedAt: nb, });
    const at_ = (now: number, o: Record<string, unknown> = {}) => reason(build({ singles: [single(0, { thisUpdate: now - 1000, nextUpdate: now + DAY })], responder: d, producedAt: now - 1000 }), 0, { nowMs: now, ...o });
    expect(await at_(nb)).toBe('OK');
    expect(await at_(nb - 1)).toMatch(/outside its validity window/);
    expect(await at_(nb - 1, { clockSkewMs: 1 })).toBe('OK');
    expect(await at_(nb - 2, { clockSkewMs: 1 })).toMatch(/outside its validity window/);
    expect(await at_(na)).toBe('OK');
    expect(await at_(na + 1)).toMatch(/outside its validity window/);
    expect(await at_(na + 1, { clockSkewMs: 5000 })).toMatch(/outside its validity window/); // skew does not extend the end
    expect(der.length).toBeGreaterThan(10);
  });
});

describe('verifyNvidiaOcspResponse: delegated responder certificate details', () => {
  it('a responder signed by a CA BELOW the issuer is refused (only the issuer and above may sign it)', async () => {
    const below = delegated({ seed: 'below-ca' }, 1); // signed by chain[1], a CA
    const der = build({ singles: [single(2)], responder: below });
    expect(await reason(der, 2)).toBe('delegated responder certificate is not signed by the supplied NVIDIA chain');
    const at = delegated({ seed: 'at-issuer' }, 3); // signed by the issuer itself
    expect(await reason(build({ singles: [single(2)], responder: at }), 2)).toBe('OK');
    const above = delegated({ seed: 'above-issuer' }, 4);
    expect(await reason(build({ singles: [single(2)], responder: above }), 2)).toBe('OK');
  });
  it('a responder certificate without extensions, or with an unparseable EKU, lacks the OCSPSigning purpose', async () => {
    const key = forgeKey('bare-resp', 'P-384');
    const mkResp = (extensions: Uint8Array[]) =>
      forgeCert({ subject: [['CN', 'Bare Responder']], issuer: D[1]!.subject, subjectKey: key, signer: D[1]!.key, serial: serialFor('bare-resp'), notBefore: at(NOW - 400 * DAY), notAfter: at(NOW + 400 * DAY), sigDigest: 'sha384', extensions });
    const lacks = 'delegated responder certificate lacks the id-kp-OCSPSigning EKU';
    const bare = mkResp([]);
    expect(await reason(build({ singles: [single()], responder: { cert: bare, key: ecKeyOf(key) } }))).toBe(lacks);
    const garbage = mkResp([extension('2.5.29.37', false, Uint8Array.of(1, 2, 3))]);
    expect(await reason(build({ singles: [single()], responder: { cert: garbage, key: ecKeyOf(key) } }))).toBe(lacks);
  });
  it('RevokedInfo time must be exactly YYYYMMDDHHMMSSZ', async () => {
    const m = 'malformed revoked certStatus';
    expect(await reason(good({}, { status: 'revoked', revokedAt: '20261019123456.5Z' }))).toBe(m);
    expect(await verify(good({}, { status: 'revoked', revokedAt: '20261019123456Z' }))).toMatchObject({ ok: true, revokedAt: Date.UTC(2026, 9, 19, 12, 34, 56) });
  });
});

describe('verifyNvidiaOcspResponse: nonce', () => {
  const nonce = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  it('echoed nonce (DER OCTET STRING or raw) must match; other extensions are ignored', async () => {
    const wrapped = nonceExt(octets(nonce));
    expect(await reason(good({ extensions: [wrapped] }), 0, { expectedNonce: nonce })).toBe('OK');
    expect(await reason(good({ extensions: [wrapped] }), 0, { expectedNonce: Uint8Array.from(nonce).reverse() })).toBe('response nonce does not match the request nonce');
    expect(await reason(good(), 0, { expectedNonce: nonce })).toBe('response does not echo the nonce');
    expect(await reason(good({ extensions: [extension('1.2.3.4', false, octets(nonce))] }), 0, { expectedNonce: nonce })).toBe('response does not echo the nonce');
    // an unrelated extension first, then the nonce
    expect(await reason(good({ extensions: [extension('1.2.3.4', false, octets(new Uint8Array(16).fill(9))), wrapped] }), 0, { expectedNonce: nonce })).toBe('OK');
    // not wrapped: the raw extension value is the nonce
    const rawNonce = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
    expect(await reason(good({ extensions: [nonceExt(rawNonce)] }), 0, { expectedNonce: rawNonce })).toBe('OK');
    expect(await reason(good({ extensions: [nonceExt(rawNonce)] }), 0, { expectedNonce: nonce })).toBe('response nonce does not match the request nonce');
    // looks like an OCTET STRING but with trailing garbage: compared raw
    const trailing = cat(octets(nonce), Uint8Array.of(0xff));
    expect(await reason(good({ extensions: [nonceExt(trailing)] }), 0, { expectedNonce: trailing })).toBe('OK');
    expect(await reason(good({ extensions: [nonceExt(trailing)] }), 0, { expectedNonce: nonce })).toBe('response nonce does not match the request nonce');
    // a nonce that is not required is not checked
    expect(await reason(good({ extensions: [wrapped] }))).toBe('OK');
  });
});

describe('verifyNvidiaOcspResponse: freshness', () => {
  const s = Math.floor(NOW / 1000) * 1000;
  const run = (single: Partial<Single>, resp: Partial<Resp> = {}, o: Record<string, unknown> = {}) => reason(good(resp, single), 0, o);
  it('thisUpdate / producedAt in the future, with skew', async () => {
    expect(await run({ thisUpdate: s })).toBe('OK');
    expect(await run({ thisUpdate: s + 1000 })).toBe('response thisUpdate is in the future');
    expect(await run({ thisUpdate: s + 5000 }, {}, { clockSkewMs: 5000 })).toBe('OK');
    expect(await run({ thisUpdate: s + 6000 }, {}, { clockSkewMs: 5000 })).toBe('response thisUpdate is in the future');
    expect(await run({ thisUpdate: s - HOUR }, { producedAt: s })).toBe('OK');
    expect(await run({ thisUpdate: s - HOUR }, { producedAt: s + 1000 })).toBe('response producedAt is in the future');
    expect(await run({ thisUpdate: s - HOUR }, { producedAt: s + 5000 }, { clockSkewMs: 5000 })).toBe('OK');
    expect(await run({ thisUpdate: s - HOUR }, { producedAt: s + 6000 }, { clockSkewMs: 5000 })).toBe('response producedAt is in the future');
    // skew only ever widens, never shifts into the past
    expect(await run({ thisUpdate: s - HOUR }, { producedAt: s - 5000 }, { clockSkewMs: 5000 })).toBe('OK');
  });
  it('nextUpdate sanity and staleness', async () => {
    expect(await run({ thisUpdate: s - 10 * 1000, nextUpdate: s })).toBe('OK'); // now == nextUpdate
    expect(await run({ thisUpdate: s - 10 * 1000, nextUpdate: s - 1000 })).toBe('response is stale (past nextUpdate)');
    expect(await run({ thisUpdate: s - 1000, nextUpdate: s - 1000 })).toBe('response is stale (past nextUpdate)'); // nextUpdate == thisUpdate is valid, but stale
    expect(await run({ thisUpdate: s - 1000, nextUpdate: s + 1000 })).toBe('OK');
    expect(await run({ thisUpdate: s - 1000, nextUpdate: s - 2000 })).toBe('response nextUpdate is invalid');
    expect(await run({ thisUpdate: s - 1000, nextUpdate: s - 1000 + 0 }, {}, { nowMs: s - 1000 })).toBe('OK'); // nextUpdate == thisUpdate and fresh
  });
  it('maximum age (default 7 days, custom) applies with or without nextUpdate', async () => {
    expect(await run({ thisUpdate: s - 7 * DAY, nextUpdate: null })).toBe('OK');
    expect(await run({ thisUpdate: s - 7 * DAY - 1000, nextUpdate: null })).toBe('response is older than the maximum accepted age');
    expect(await run({ thisUpdate: s - 7 * DAY - 1000, nextUpdate: s + DAY })).toBe('response is older than the maximum accepted age');
    expect(await run({ thisUpdate: s - 2 * HOUR, nextUpdate: null }, {}, { maxAgeMs: 2 * HOUR })).toBe('OK');
    expect(await run({ thisUpdate: s - 2 * HOUR - 1000, nextUpdate: null }, {}, { maxAgeMs: 2 * HOUR })).toBe('response is older than the maximum accepted age');
    expect(await run({ thisUpdate: s - 8 * DAY, nextUpdate: null }, {}, { maxAgeMs: 9 * DAY })).toBe('OK');
  });
});

// ------------------------------------------------------------------------------------------------ AIA
describe('nvidiaCertOcspUrls', () => {
  it('lists the OCSP access locations of a certificate, none for a certificate without AIA', async () => {
    expect(await nvidiaCertOcspUrls(chain[0]!)).toEqual([]);
    expect(await nvidiaCertOcspUrls(chain[2]!)).toEqual(['http://ocsp.ndis.nvidia.com']);
    expect(await nvidiaCertOcspUrls(chain[3]!)).toEqual(['http://ocsp.ndis.nvidia.com']);
  });
  it('only ocsp access methods with a URI location count; a certificate with no extensions at all yields none', async () => {
    const key = forgeKey('aia-key', 'P-384');
    const url = (s: string) => new TextEncoder().encode(s);
    const aia = extension('1.3.6.1.5.5.7.1.1', false, seq(seq(oid('1.3.6.1.5.5.7.48.2'), ctxPrim(6, url('http://issuer.example/ca.cer'))), seq(oid('1.3.6.1.5.5.7.48.1'), ctxPrim(2, url('ocsp.example'))), seq(oid('1.3.6.1.5.5.7.48.1'), ctxPrim(6, url('http://a.example'))), seq(oid('1.3.6.1.5.5.7.48.1'), ctxPrim(6, url('http://b.example')))));
    const mk = (extensions: Uint8Array[]) => forgeCert({ subject: [['CN', 'aia']], issuer: [['CN', 'aia']], subjectKey: key, signer: key, serial: serialFor('aia'), notBefore: at(NOW - DAY), notAfter: at(NOW + DAY), sigDigest: 'sha384', extensions });
    expect(await nvidiaCertOcspUrls(x(mk([aia])))).toEqual(['http://a.example', 'http://b.example']);
    expect(await nvidiaCertOcspUrls(x(mk([])))).toEqual([]);
  });
});

// ------------------------------------------------------------------------------------------------ chain
describe('checkNvidiaChainOcsp', () => {
  const resp = (i: number, o: Partial<Single> = {}, r: Partial<Resp> = {}) => build({ singles: [single(i, o)], ...r });
  const all = () => [resp(0), resp(1), resp(2), resp(3)];
  it('guards', async () => {
    expect(await checkNvidiaChainOcsp([chain[0]!], [resp(0)], NOW)).toEqual({ ok: false, reason: 'chain too short for OCSP' });
    expect(await checkNvidiaChainOcsp([], [resp(0)], NOW)).toEqual({ ok: false, reason: 'chain too short for OCSP' });
    expect(await checkNvidiaChainOcsp(chain, [], NOW)).toEqual({ ok: false, reason: 'no OCSP responses supplied' });
    expect(await checkNvidiaChainOcsp(chain.slice(0, 2), [resp(0)], NOW)).toMatchObject({ ok: true }); // two certificates is enough
  });
  it('default policy requires GOOD for every non-root certificate that advertises OCSP', async () => {
    const r = await checkNvidiaChainOcsp(chain, [resp(2), resp(3)], NOW);
    expect(r).toEqual({ ok: true, verifiedCrls: 0, verifiedOcsp: 2, statuses: { 0: 'absent', 1: 'absent', 2: 'good', 3: 'good' } });
    const missing = await checkNvidiaChainOcsp(chain, [resp(2)], NOW);
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.reason).toBe(`no GOOD OCSP response for required certificate '${chain[3]!.subject.replace(/\n/g, ', ')}' (status: absent)`);
      expect(missing.statuses).toEqual({ 0: 'absent', 1: 'absent', 2: 'good', 3: 'absent' });
    }
    const unknown = await checkNvidiaChainOcsp(chain, [resp(2), resp(3, { status: 'unknown' })], NOW);
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) expect(unknown.reason).toContain('(status: unknown)');
    expect((await checkNvidiaChainOcsp(chain, [resp(2), resp(3), resp(0), resp(1)], NOW, { requireGood: 'aia' })).ok).toBe(true);
  });
  it('requireGood "all" and explicit indices', async () => {
    const some = await checkNvidiaChainOcsp(chain, [resp(2), resp(3)], NOW, { requireGood: 'all' });
    expect(some.ok).toBe(false);
    if (!some.ok) expect(some.reason).toContain(`'${chain[0]!.subject.replace(/\n/g, ', ')}'`);
    expect(await checkNvidiaChainOcsp(chain, all(), NOW, { requireGood: 'all' })).toMatchObject({ ok: true, verifiedOcsp: 4 });
    expect(await checkNvidiaChainOcsp(chain, [resp(0)], NOW, { requireGood: [0] })).toMatchObject({ ok: true, verifiedOcsp: 1 });
    expect(await checkNvidiaChainOcsp(chain, [resp(0)], NOW, { requireGood: [] })).toMatchObject({ ok: true });
    for (const bad of [-1, 4, 5, 1.5, NaN]) {
      expect(await checkNvidiaChainOcsp(chain, [resp(0)], NOW, { requireGood: [bad] })).toEqual({ ok: false, reason: `requireGood index ${bad} is not a non-root chain certificate` });
    }
    expect((await checkNvidiaChainOcsp(chain, [resp(3)], NOW, { requireGood: [3] })).ok).toBe(true);
  });
  it('revoked, duplicate and unmatched responses', async () => {
    const subj = (i: number) => chain[i]!.subject.replace(/\n/g, ', ');
    const rv = await checkNvidiaChainOcsp(chain, [resp(2, { status: 'revoked' })], NOW, { requireGood: [] });
    expect(rv).toEqual({ ok: false, reason: `chain certificate '${subj(2)}' is revoked (OCSP)`, statuses: { 0: 'absent', 1: 'absent', 2: 'revoked', 3: 'absent' } });
    const dup = await checkNvidiaChainOcsp(chain, [resp(1), resp(1)], NOW, { requireGood: [] });
    expect(dup).toMatchObject({ ok: false, reason: 'duplicate OCSP responses for chain certificate #1' });
    if (!dup.ok) expect(dup.statuses).toEqual({ 0: 'absent', 1: 'good', 2: 'absent', 3: 'absent' });
    const stranger = build({ singles: [{ cert: D[0]!, issuer: D[2]! }], signWith: D[2]!.key });
    expect(await checkNvidiaChainOcsp(chain, [stranger], NOW, { requireGood: [] })).toMatchObject({ ok: false, reason: 'OCSP response #0 rejected: no SingleResponse matches the certificate (serial / issuer hashes differ)' });
    const second = await checkNvidiaChainOcsp(chain, [resp(2), stranger], NOW, { requireGood: [] });
    expect(second).toMatchObject({ ok: false, reason: expect.stringMatching(/^OCSP response #1 rejected: /) });
  });
  it('a defective response that speaks for a certificate fails closed, naming it', async () => {
    const stale = resp(1, { thisUpdate: NOW - 30 * DAY, nextUpdate: null });
    const r = await checkNvidiaChainOcsp(chain, [resp(0), stale], NOW, { requireGood: [] });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe(`OCSP response #1 for '${chain[1]!.subject.replace(/\n/g, ', ')}' rejected: response is older than the maximum accepted age`);
      expect(r.statuses).toEqual({ 0: 'good', 1: 'absent', 2: 'absent', 3: 'absent' });
    }
  });
  it('one response may not vouch for two certificates', async () => {
    const d2 = delegated({ seed: 'shared-responder' }, 2);
    const both = build({ singles: [single(0), single(1)], responder: d2, rid: 'key' });
    // issuer of cert 0 is chain[1], issuer of cert 1 is chain[2]; the delegated responder is signed by chain[2], above both
    const r = await checkNvidiaChainOcsp(chain, [both], NOW, { requireGood: [] });
    expect(r).toMatchObject({ ok: false, reason: 'OCSP response #0 matches more than one chain certificate' });
  });
  it('maxAgeMs, clockSkewMs and per-index nonces are passed through to every response check', async () => {
    const old = resp(2, { thisUpdate: NOW - 2 * DAY, nextUpdate: null });
    expect((await checkNvidiaChainOcsp(chain, [old], NOW, { requireGood: [] })).ok).toBe(true);
    const tooOld = await checkNvidiaChainOcsp(chain, [old], NOW, { requireGood: [], maxAgeMs: DAY });
    expect(tooOld.ok).toBe(false);
    if (!tooOld.ok) expect(tooOld.reason).toContain('older than the maximum accepted age');
    const future = resp(2, { thisUpdate: NOW + 4000, nextUpdate: null }, { producedAt: NOW });
    expect((await checkNvidiaChainOcsp(chain, [future], NOW, { requireGood: [] })).ok).toBe(false);
    expect((await checkNvidiaChainOcsp(chain, [future], NOW, { requireGood: [], clockSkewMs: 5000 })).ok).toBe(true);
    const n = Uint8Array.of(1, 2, 3, 4);
    const withNonce = resp(2, {}, { extensions: [nonceExt(octets(n))] });
    expect((await checkNvidiaChainOcsp(chain, [withNonce], NOW, { requireGood: [], expectedNonces: [undefined, undefined, n] })).ok).toBe(true);
    const bad = await checkNvidiaChainOcsp(chain, [withNonce], NOW, { requireGood: [], expectedNonces: [undefined, undefined, Uint8Array.of(9)] });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.reason).toContain('response nonce does not match the request nonce');
    // a nonce expected for ANOTHER index does not constrain this response
    expect((await checkNvidiaChainOcsp(chain, [withNonce], NOW, { requireGood: [], expectedNonces: [Uint8Array.of(7)] })).ok).toBe(true);
  });
});

// ------------------------------------------------------------------------------------------------ fetch
describe('fetchNvidiaOcsp', () => {
  const okRes = (bytes: Uint8Array) => ({ ok: true, status: 200, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) }) as unknown as Response;
  it('POSTs the request to the default responder and returns request and response bytes', async () => {
    const calls: { url: unknown; init: RequestInit }[] = [];
    const f = (async (url: string, init: RequestInit) => (calls.push({ url, init }), okRes(Uint8Array.of(1, 2, 3)))) as unknown as typeof fetch;
    const r = await fetchNvidiaOcsp(chain[0]!, chain[1]!, { fetch: f });
    expect(Array.from(r.response)).toEqual([1, 2, 3]);
    expect(Array.from(r.request)).toEqual(Array.from(await buildNvidiaOcspRequest(chain[0]!, chain[1]!)));
    expect(calls.length).toBe(1);
    expect(calls[0]!.url).toBe('http://ocsp.ndis.nvidia.com/');
    expect(calls[0]!.init.method).toBe('POST');
    expect(calls[0]!.init.headers).toEqual({ 'content-type': 'application/ocsp-request' });
    expect(Array.from(calls[0]!.init.body as Buffer)).toEqual(Array.from(r.request));
  });
  it('custom URL and nonce; HTTP errors; missing fetch', async () => {
    const urls: unknown[] = [];
    const f = (async (u: string) => (urls.push(u), okRes(new Uint8Array(0)))) as unknown as typeof fetch;
    const nonce = Uint8Array.of(5, 6, 7);
    const r = await fetchNvidiaOcsp(chain[0]!, chain[1]!, { fetch: f, url: 'http://example.test/ocsp', nonce });
    expect(urls).toEqual(['http://example.test/ocsp']);
    expect(Array.from(r.request)).toEqual(Array.from(await buildNvidiaOcspRequest(chain[0]!, chain[1]!, { nonce })));
    expect(Array.from(r.request)).not.toEqual(Array.from(await buildNvidiaOcspRequest(chain[0]!, chain[1]!)));
    const bad = (async () => ({ ok: false, status: 503 }) as unknown as Response) as unknown as typeof fetch;
    await expect(fetchNvidiaOcsp(chain[0]!, chain[1]!, { fetch: bad })).rejects.toThrow(new Error('OCSP fetch failed: HTTP 503'));
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'fetch')!;
    Object.defineProperty(globalThis, 'fetch', { value: undefined, configurable: true, writable: true });
    try {
      await expect(fetchNvidiaOcsp(chain[0]!, chain[1]!)).rejects.toThrow(new Error('fetchNvidiaOcsp: no fetch implementation available'));
    } finally {
      Object.defineProperty(globalThis, 'fetch', saved);
    }
  });
});
