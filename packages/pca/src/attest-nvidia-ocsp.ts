/**
 * NVIDIA GPU-CC DEVICE-CHAIN REVOCATION VIA OCSP (RFC 6960).
 *
 * NVIDIA's own local verifier checks the device chain against its OCSP responder (`ocsp.ndis.nvidia.com`):
 * for each non-root certificate it POSTs an OCSPRequest (CertID over the issuer name/key hashes + serial, nonce
 * extension), verifies the response signature, the responder's chain, the nonce, and requires status GOOD.
 * This module is the offline-verifiable equivalent: it builds the same requests, and verifies the responses a
 * caller (or `fetchNvidiaOcsp`) obtained. Fetching is never automatic.
 *
 * ASN.1 is handled by the vetted `pkijs` / `asn1js` libraries (optional dependencies, loaded lazily); there is NO
 * hand-rolled DER parsing here. Signature verification and hashing use `node:crypto`.
 *
 * Verified per response (fail closed on anything else): responseStatus SUCCESSFUL with id-pkix-ocsp-basic;
 * the CertID matches the cert under test (serial + issuerNameHash + issuerKeyHash for the issuer supplied);
 * the BasicOCSPResponse signature (ECDSA P-256/384/521 with SHA-256/384/512, or RSA PKCS#1 v1.5) verifies under
 * EITHER the issuing CA's key itself OR a delegated responder certificate embedded in the response which is
 * signed by a certificate of the supplied NVIDIA chain (at or above the issuer), is within validity, and carries
 * the id-kp-OCSPSigning EKU; nonce echo when requested; thisUpdate <= now <= nextUpdate (and a maximum age).
 */
import { createHash, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

type Pkijs = typeof import('pkijs');
type Asn1 = typeof import('asn1js');

const OID_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';
const OID_OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2';
const OID_AIA = '1.3.6.1.5.5.7.1.1';
const OID_AD_OCSP = '1.3.6.1.5.5.7.48.1';
const OID_EKU_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';
const OID_EKU = '2.5.29.37';

const HASHES: Readonly<Record<string, string>> = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};
const OID_BY_HASH: Readonly<Record<string, string>> = { sha1: '1.3.14.3.2.26', sha256: '2.16.840.1.101.3.4.2.1', sha384: '2.16.840.1.101.3.4.2.2', sha512: '2.16.840.1.101.3.4.2.3' };

/** Signature algorithm OID -> node hash name + family. */
const SIG_ALGS: Readonly<Record<string, { hash: string; kind: 'ec' | 'rsa' }>> = {
  '1.2.840.10045.4.3.2': { hash: 'sha256', kind: 'ec' },
  '1.2.840.10045.4.3.3': { hash: 'sha384', kind: 'ec' },
  '1.2.840.10045.4.3.4': { hash: 'sha512', kind: 'ec' },
  '1.2.840.113549.1.1.11': { hash: 'sha256', kind: 'rsa' },
  '1.2.840.113549.1.1.12': { hash: 'sha384', kind: 'rsa' },
  '1.2.840.113549.1.1.13': { hash: 'sha512', kind: 'rsa' },
};

/** NVIDIA's public OCSP responder (the default used by NVIDIA's local verifier). */
export const NVIDIA_OCSP_URL = 'http://ocsp.ndis.nvidia.com/';
/** Default maximum accepted age of a response (thisUpdate -> now), when no nextUpdate bound applies. */
export const NVIDIA_OCSP_DEFAULT_MAX_AGE_MS = 7 * 24 * 3600 * 1000;

export type NvidiaOcspStatus = 'good' | 'revoked' | 'unknown';

export type NvidiaOcspResult =
  | { ok: true; status: NvidiaOcspStatus; thisUpdate: number; nextUpdate?: number; producedAt: number; revokedAt?: number; revocationReason?: number; responder: 'issuer' | 'delegated' }
  | { ok: false; reason: string };

export interface VerifyNvidiaOcspOptions {
  /** The certificate whose status the response must speak for. */
  cert: X509Certificate;
  /** Its issuer (the CertID is computed over this certificate's subject + key). */
  issuer: X509Certificate;
  /** The trusted NVIDIA chain; a delegated responder certificate must be signed by one of these (at/above the issuer). */
  chain: X509Certificate[];
  nowMs: number;
  /** Maximum age of thisUpdate (default: 7 days; also applied when nextUpdate is absent). */
  maxAgeMs?: number;
  /** When set, the response MUST echo exactly this nonce. */
  expectedNonce?: Uint8Array;
  /** Tolerated clock skew for "not yet valid" checks (default 0). */
  clockSkewMs?: number;
}

async function loadLibs(): Promise<{ pkijs: Pkijs; asn1: Asn1 }> {
  try {
    const [pkijs, asn1] = await Promise.all([import('pkijs'), import('asn1js')]);
    return { pkijs, asn1 };
  } catch {
    throw new Error('NVIDIA OCSP requires the optional dependencies "pkijs" and "asn1js" (npm i pkijs asn1js)');
  }
}

const view = (b: ArrayBuffer | ArrayBufferView): Uint8Array => (ArrayBuffer.isView(b) ? new Uint8Array(b.buffer, b.byteOffset, b.byteLength) : new Uint8Array(b));
const eq = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
function stripLeadingZeros(a: Uint8Array): Uint8Array {
  let i = 0;
  while (i < a.length - 1 && a[i] === 0) i++;
  return a.subarray(i);
}
function toAb(u: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(u.length);
  new Uint8Array(out).set(u);
  return out;
}

interface CertParts {
  cert: InstanceType<Pkijs['Certificate']>;
  subjectDer: Uint8Array;
  keyBits: Uint8Array;
  serial: Uint8Array;
}
function parseCert(l: { pkijs: Pkijs; asn1: Asn1 }, x: X509Certificate): CertParts {
  const asn = l.asn1.fromBER(toAb(x.raw));
  if (asn.offset === -1) throw new Error('certificate is not valid DER');
  const cert = new l.pkijs.Certificate({ schema: asn.result });
  return {
    cert,
    subjectDer: view(cert.subject.toSchema().toBER(false)),
    keyBits: view(cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView),
    serial: stripLeadingZeros(view(cert.serialNumber.valueBlock.valueHexView)),
  };
}

function certIdHashes(issuer: CertParts, hash: string): { name: Uint8Array; key: Uint8Array } {
  return { name: createHash(hash).update(issuer.subjectDer).digest(), key: createHash(hash).update(issuer.keyBits).digest() };
}

// ── request ─────────────────────────────────────────────────────────────────────────────────────

/** Build a DER OCSPRequest for `cert` (issued by `issuer`), SHA-384 CertID (as NVIDIA's verifier does) plus an optional nonce. */
export async function buildNvidiaOcspRequest(cert: X509Certificate, issuer: X509Certificate, opts: { nonce?: Uint8Array; hash?: 'sha1' | 'sha256' | 'sha384' | 'sha512' } = {}): Promise<Uint8Array> {
  const l = await loadLibs();
  const hash = opts.hash ?? 'sha384';
  const c = parseCert(l, cert);
  const i = parseCert(l, issuer);
  const h = certIdHashes(i, hash);
  const certId = new l.pkijs.CertID({
    hashAlgorithm: new l.pkijs.AlgorithmIdentifier({ algorithmId: OID_BY_HASH[hash]!, algorithmParams: new l.asn1.Null() }),
    issuerNameHash: new l.asn1.OctetString({ valueHex: toAb(h.name) }),
    issuerKeyHash: new l.asn1.OctetString({ valueHex: toAb(h.key) }),
    serialNumber: c.cert.serialNumber,
  });
  const req = new l.pkijs.OCSPRequest();
  req.tbsRequest.requestList = [new l.pkijs.Request({ reqCert: certId })];
  if (opts.nonce) {
    if (opts.nonce.length < 1 || opts.nonce.length > 32) throw new RangeError('nonce must be 1..32 bytes');
    const inner = new l.asn1.OctetString({ valueHex: toAb(opts.nonce) }).toBER(false);
    req.tbsRequest.requestExtensions = [new l.pkijs.Extension({ extnID: OID_OCSP_NONCE, critical: false, extnValue: inner })];
  }
  return view(req.toSchema(true).toBER(false));
}

// ── response ────────────────────────────────────────────────────────────────────────────────────

function fail(reason: string): { ok: false; reason: string } {
  return { ok: false, reason };
}

function ekuOf(l: { pkijs: Pkijs }, c: CertParts): string[] | undefined {
  const ext = c.cert.extensions?.find((e) => e.extnID === OID_EKU);
  if (!ext) return undefined;
  const parsed = ext.parsedValue as InstanceType<Pkijs['ExtKeyUsage']> | undefined;
  return parsed?.keyPurposes;
}

function verifySig(alg: string, tbs: Uint8Array, sig: Uint8Array, key: KeyObject): boolean {
  const a = SIG_ALGS[alg];
  if (!a) return false;
  const t = key.asymmetricKeyType;
  if ((a.kind === 'ec') !== (t === 'ec')) return false;
  if (a.kind === 'rsa' && t !== 'rsa') return false;
  try {
    return cryptoVerify(a.hash, tbs, key, sig);
  } catch {
    return false;
  }
}

/** Verify one DER OCSPResponse for `opts.cert`. Never throws; any malformation is `{ok:false}`. */
export async function verifyNvidiaOcspResponse(responseDer: Uint8Array, opts: VerifyNvidiaOcspOptions): Promise<NvidiaOcspResult> {
  try {
    return await verifyInner(responseDer, opts);
  } catch (e) {
    return fail(`OCSP response rejected: ${e instanceof Error ? e.message : 'malformed'}`);
  }
}

async function verifyInner(responseDer: Uint8Array, opts: VerifyNvidiaOcspOptions): Promise<NvidiaOcspResult> {
  const l = await loadLibs();
  const { pkijs, asn1 } = l;
  const skew = opts.clockSkewMs ?? 0;
  const maxAge = opts.maxAgeMs ?? NVIDIA_OCSP_DEFAULT_MAX_AGE_MS;

  const top = asn1.fromBER(toAb(responseDer));
  if (top.offset === -1) return fail('response is not valid DER');
  if (top.offset !== responseDer.length) return fail('trailing bytes after OCSPResponse');
  const resp = new pkijs.OCSPResponse({ schema: top.result });
  const status = resp.responseStatus.valueBlock.valueDec;
  if (status !== 0) return fail(`OCSP responseStatus is ${status} (not successful)`);
  if (!resp.responseBytes) return fail('successful response carries no responseBytes');
  if (resp.responseBytes.responseType !== OID_OCSP_BASIC) return fail('responseType is not id-pkix-ocsp-basic');
  const basicAsn = asn1.fromBER(toAb(view(resp.responseBytes.response.valueBlock.valueHexView)));
  if (basicAsn.offset === -1) return fail('BasicOCSPResponse is not valid DER');
  const basic = new pkijs.BasicOCSPResponse({ schema: basicAsn.result });
  const tbs = basic.tbsResponseData;
  if (!tbs.tbsView || tbs.tbsView.length === 0) return fail('missing tbsResponseData');
  const tbsBytes = view(tbs.tbsView);
  const sigAlg = basic.signatureAlgorithm.algorithmId;
  if (!SIG_ALGS[sigAlg]) return fail(`unsupported OCSP signature algorithm ${sigAlg}`);
  const sig = view(basic.signature.valueBlock.valueHexView);

  const subject = parseCert(l, opts.cert);
  const issuer = parseCert(l, opts.issuer);

  // CertID match (exactly one single response must speak for our cert)
  const matches = tbs.responses.filter((r) => {
    const hn = HASHES[r.certID.hashAlgorithm.algorithmId];
    if (!hn) return false;
    const want = certIdHashes(issuer, hn);
    return (
      eq(stripLeadingZeros(view(r.certID.serialNumber.valueBlock.valueHexView)), subject.serial) &&
      eq(view(r.certID.issuerNameHash.valueBlock.valueHexView), want.name) &&
      eq(view(r.certID.issuerKeyHash.valueBlock.valueHexView), want.key)
    );
  });
  if (matches.length === 0) return fail('no SingleResponse matches the certificate (serial / issuer hashes differ)');
  if (matches.length > 1) return fail('ambiguous: multiple SingleResponses match the certificate');
  const single = matches[0]!;

  // responder authentication
  const issuerPub = opts.issuer.publicKey;
  let responder: 'issuer' | 'delegated' = 'issuer';
  const rid = tbs.responderID;
  const isIssuerId =
    rid instanceof pkijs.RelativeDistinguishedNames
      ? eq(view(rid.toSchema().toBER(false)), issuer.subjectDer)
      : rid instanceof asn1.OctetString
        ? eq(view(rid.valueBlock.valueHexView), createHash('sha1').update(issuer.keyBits).digest())
        : false;
  const issuerOk = isIssuerId && verifySig(sigAlg, tbsBytes, sig, issuerPub);
  if (!issuerOk) {
    // delegated responder
    const embedded = (basic.certs ?? []).map((c) => new X509Certificate(Buffer.from(c.toSchema().toBER(false))));
    let found: X509Certificate | undefined;
    let why = 'no embedded responder certificate verifies the response';
    for (const cand of embedded) {
      const cp = parseCert(l, cand);
      const idOk =
        rid instanceof pkijs.RelativeDistinguishedNames
          ? eq(view(rid.toSchema().toBER(false)), cp.subjectDer)
          : rid instanceof asn1.OctetString
            ? eq(view(rid.valueBlock.valueHexView), createHash('sha1').update(cp.keyBits).digest())
            : false;
      if (!idOk) {
        why = 'embedded certificates do not match the responderID';
        continue;
      }
      const eku = ekuOf(l, cp);
      if (!eku || !eku.includes(OID_EKU_OCSP_SIGNING)) {
        why = 'delegated responder certificate lacks the id-kp-OCSPSigning EKU';
        continue;
      }
      const nb = Date.parse(cand.validFrom);
      const na = Date.parse(cand.validTo);
      if (!(nb - skew <= opts.nowMs && opts.nowMs <= na)) {
        why = 'delegated responder certificate is outside its validity window';
        continue;
      }
      // must be signed by a NVIDIA chain cert at or above the issuer
      const issuerIdx = opts.chain.findIndex((c) => c.raw.equals(opts.issuer.raw));
      const signers = issuerIdx >= 0 ? opts.chain.slice(issuerIdx) : [opts.issuer];
      if (!signers.some((s) => cand.checkIssued(s) && cand.verify(s.publicKey))) {
        why = 'delegated responder certificate is not signed by the supplied NVIDIA chain';
        continue;
      }
      if (!verifySig(sigAlg, tbsBytes, sig, cand.publicKey)) {
        why = 'OCSP response signature does not verify under the delegated responder key';
        continue;
      }
      found = cand;
      break;
    }
    if (!found) return fail(isIssuerId ? 'OCSP response signature does not verify under the issuer key' : why);
    responder = 'delegated';
  }

  // nonce
  if (opts.expectedNonce) {
    const ext = tbs.responseExtensions?.find((e) => e.extnID === OID_OCSP_NONCE);
    if (!ext) return fail('response does not echo the nonce');
    const raw = view(ext.extnValue.valueBlock.valueHexView);
    let echoed: Uint8Array = raw;
    const inner = asn1.fromBER(toAb(raw));
    if (inner.offset === raw.length && inner.result instanceof asn1.OctetString) echoed = view(inner.result.valueBlock.valueHexView);
    if (!eq(echoed, opts.expectedNonce)) return fail('response nonce does not match the request nonce');
  }

  // freshness
  const thisUpdate = single.thisUpdate.getTime();
  const producedAt = tbs.producedAt.getTime();
  const nextUpdate = single.nextUpdate?.getTime();
  if (!Number.isFinite(thisUpdate) || !Number.isFinite(producedAt)) return fail('response times are not parseable');
  if (thisUpdate > opts.nowMs + skew) return fail('response thisUpdate is in the future');
  if (producedAt > opts.nowMs + skew) return fail('response producedAt is in the future');
  if (nextUpdate !== undefined) {
    if (!Number.isFinite(nextUpdate) || nextUpdate < thisUpdate) return fail('response nextUpdate is invalid');
    if (opts.nowMs > nextUpdate) return fail('response is stale (past nextUpdate)');
  }
  if (opts.nowMs - thisUpdate > maxAge) return fail('response is older than the maximum accepted age');

  // status: CHOICE [0] good, [1] revoked, [2] unknown
  const tag = single.certStatus.idBlock.tagNumber;
  if (single.certStatus.idBlock.tagClass !== 3) return fail('malformed certStatus');
  if (tag === 0) return { ok: true, status: 'good', thisUpdate, ...(nextUpdate !== undefined ? { nextUpdate } : {}), producedAt, responder };
  if (tag === 2) return { ok: true, status: 'unknown', thisUpdate, ...(nextUpdate !== undefined ? { nextUpdate } : {}), producedAt, responder };
  if (tag === 1) {
    const info = revokedInfo(single.certStatus);
    if (!info) return fail('malformed revoked certStatus');
    return {
      ok: true,
      status: 'revoked',
      thisUpdate,
      ...(nextUpdate !== undefined ? { nextUpdate } : {}),
      producedAt,
      revokedAt: info.at,
      ...(info.reason !== undefined ? { revocationReason: info.reason } : {}),
      responder,
    };
  }
  return fail('unrecognised certStatus');
}

/** Read RevokedInfo (IMPLICIT [1]: GeneralizedTime, [0] EXPLICIT CRLReason OPTIONAL) via asn1js, never by hand. */
function revokedInfo(status: { valueBlock: { value?: unknown[]; valueHexView: Uint8Array } }): { at: number; reason?: number } | undefined {
  const items = status.valueBlock.value;
  if (!Array.isArray(items) || items.length < 1) return undefined;
  const first = items[0] as { valueBlock: { valueHexView: Uint8Array } };
  const txt = Buffer.from(view(first.valueBlock.valueHexView)).toString('latin1');
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(txt);
  if (!m) return undefined;
  const at = Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!);
  let reason: number | undefined;
  const second = items[1] as { valueBlock?: { value?: { valueBlock: { valueDec?: number } }[] } } | undefined;
  const enumv = second?.valueBlock?.value?.[0];
  if (enumv && typeof enumv.valueBlock.valueDec === 'number') reason = enumv.valueBlock.valueDec;
  return { at, ...(reason !== undefined ? { reason } : {}) };
}

// ── chain policy ────────────────────────────────────────────────────────────────────────────────

/** Does `cert` advertise an OCSP responder URL in its Authority Information Access extension? */
export async function nvidiaCertOcspUrls(cert: X509Certificate): Promise<string[]> {
  const l = await loadLibs();
  const c = parseCert(l, cert);
  const ext = c.cert.extensions?.find((e) => e.extnID === OID_AIA);
  const aia = ext?.parsedValue as InstanceType<Pkijs['InfoAccess']> | undefined;
  if (!aia) return [];
  return aia.accessDescriptions
    .filter((d) => d.accessMethod === OID_AD_OCSP && d.accessLocation.type === 6)
    .map((d) => String(d.accessLocation.value));
}

export interface NvidiaChainOcspOptions {
  /**
   * Which chain certificates MUST have a verified GOOD response: 'aia' (default: every non-root cert that advertises
   * an OCSP URL), 'all' (every non-root cert), or explicit chain indices (0 = leaf).
   */
  requireGood?: 'aia' | 'all' | number[];
  maxAgeMs?: number;
  clockSkewMs?: number;
  /** Nonce expected per chain index (undefined = none required for that cert). */
  expectedNonces?: (Uint8Array | undefined)[];
}

export type NvidiaChainOcspResult =
  | { ok: true; verifiedCrls: number; verifiedOcsp: number; statuses: Record<number, NvidiaOcspStatus | 'absent'> }
  | { ok: false; reason: string; statuses?: Record<number, NvidiaOcspStatus | 'absent'> };

/**
 * Check the device chain with OCSP responses. Same `{ok, ...}` shape as `checkNvidiaChainRevocation` (`verifiedCrls`
 * is 0 here; use `verifiedOcsp`) plus per-cert statuses. Every supplied response must verify for exactly one chain
 * certificate (fail closed otherwise); any REVOKED status fails; required certs must have a GOOD response (UNKNOWN or
 * missing fails). Non-required certs with UNKNOWN/absent responses are reported but tolerated.
 */
export async function checkNvidiaChainOcsp(chain: X509Certificate[], responses: Uint8Array[], nowMs: number, opts: NvidiaChainOcspOptions = {}): Promise<NvidiaChainOcspResult> {
  if (chain.length < 2) return { ok: false, reason: 'chain too short for OCSP' };
  if (responses.length === 0) return { ok: false, reason: 'no OCSP responses supplied' };
  const last = chain.length - 1;
  const required = new Set<number>();
  const policy = opts.requireGood ?? 'aia';
  if (Array.isArray(policy)) {
    for (const i of policy) {
      if (!Number.isInteger(i) || i < 0 || i >= last) return { ok: false, reason: `requireGood index ${i} is not a non-root chain certificate` };
      required.add(i);
    }
  } else {
    for (let i = 0; i < last; i++) if (policy === 'all' || (await nvidiaCertOcspUrls(chain[i]!)).length > 0) required.add(i);
  }
  const statuses: Record<number, NvidiaOcspStatus | 'absent'> = {};
  for (let i = 0; i < last; i++) statuses[i] = 'absent';
  let verified = 0;
  for (const [ri, der] of responses.entries()) {
    let matched = false;
    let lastReason = 'matches no chain certificate';
    for (let i = 0; i < last; i++) {
      const r = await verifyNvidiaOcspResponse(der, {
        cert: chain[i]!,
        issuer: chain[i + 1]!,
        chain,
        nowMs,
        ...(opts.maxAgeMs !== undefined ? { maxAgeMs: opts.maxAgeMs } : {}),
        ...(opts.clockSkewMs !== undefined ? { clockSkewMs: opts.clockSkewMs } : {}),
        ...(opts.expectedNonces?.[i] ? { expectedNonce: opts.expectedNonces[i]! } : {}),
      });
      if (!r.ok) {
        if (!r.reason.startsWith('no SingleResponse matches')) {
          // it speaks for this cert but is defective: fail closed
          return { ok: false, reason: `OCSP response #${ri} for '${chain[i]!.subject.replace(/\n/g, ', ')}' rejected: ${r.reason}`, statuses };
        }
        lastReason = r.reason;
        continue;
      }
      if (matched) return { ok: false, reason: `OCSP response #${ri} matches more than one chain certificate`, statuses };
      matched = true;
      if (statuses[i] !== 'absent') return { ok: false, reason: `duplicate OCSP responses for chain certificate #${i}`, statuses };
      statuses[i] = r.status;
      verified++;
      if (r.status === 'revoked') return { ok: false, reason: `chain certificate '${chain[i]!.subject.replace(/\n/g, ', ')}' is revoked (OCSP)`, statuses };
    }
    if (!matched) return { ok: false, reason: `OCSP response #${ri} rejected: ${lastReason}`, statuses };
  }
  for (const i of required) {
    if (statuses[i] !== 'good') return { ok: false, reason: `no GOOD OCSP response for required certificate '${chain[i]!.subject.replace(/\n/g, ', ')}' (status: ${statuses[i]})`, statuses };
  }
  return { ok: true, verifiedCrls: 0, verifiedOcsp: verified, statuses };
}

// ── guarded network helper (never called automatically) ─────────────────────────────────────────

/** POST an OCSPRequest for `cert` to NVIDIA's responder and return `{request, response}` DER. Explicit use only. */
export async function fetchNvidiaOcsp(
  cert: X509Certificate,
  issuer: X509Certificate,
  opts: { fetch?: typeof fetch; url?: string; nonce?: Uint8Array } = {},
): Promise<{ request: Uint8Array; response: Uint8Array }> {
  const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
  if (!f) throw new Error('fetchNvidiaOcsp: no fetch implementation available');
  const request = await buildNvidiaOcspRequest(cert, issuer, opts.nonce ? { nonce: opts.nonce } : {});
  const res = await f(opts.url ?? NVIDIA_OCSP_URL, { method: 'POST', headers: { 'content-type': 'application/ocsp-request' }, body: Buffer.from(request) });
  if (!res.ok) throw new Error(`OCSP fetch failed: HTTP ${res.status}`);
  return { request, response: new Uint8Array(await res.arrayBuffer()) };
}
