/**
 * @atlasauth/pca-scitt — SCITT transparency receipts for Proof-Carrying Authority.
 *
 * RFC 9943 (SCITT architecture) + RFC 9942 (COSE Receipts). Each verified PCActn (a PCA decision
 * record) is registered as a COSE **Signed Statement** (a COSE_Sign1 over the PCActn/verdict), appended
 * to PCA's append-only transparency ledger (RFC 6962 Merkle, reused from `@atlasauth/pca`), and handed
 * back a COSE **Receipt** — a COSE_Sign1 signed by the Transparency Service carrying an RFC 9162 inclusion
 * proof against the ledger root. The receipt turns PCA's decision record into standards-shaped,
 * externally-verifiable, append-only audit evidence that a third party can check with nothing but the
 * signed statement, the receipt and the (pinned) tree root.
 *
 * Self-contained: a deterministic (RFC 8949 §4.2.1 core-deterministic) CBOR codec sufficient for COSE_Sign1,
 * and `node:crypto` for all signing/verification. The log is an RFC 9162 SHA-256 Merkle tree whose leaf
 * entries are the raw Signed Statement bytes (see `./rfc9162`), so an independent RFC 9162 verifier can check
 * a receipt's inclusion proof given the statement bytes.
 */
import { type InclusionProof, type ProofStep, canonicalBytes, decodeB64uStrict, b64u, utf8 } from '@atlasauth/pca';
import { consistencyPath, inclusionPath, leafHash, rootFromInclusionPath, treeHash, verifyConsistencyPath } from './rfc9162';
import { type KeyObject, sign as nodeSign, verify as nodeVerify } from 'node:crypto';

// ========================================================================================
// Deterministic CBOR (RFC 8949 §4.2.1 "core deterministic encoding"), minimal profile
// sufficient for COSE_Sign1: unsigned int, negative int, byte string, text string, array,
// map (keys sorted by their encoded bytes, no duplicates), tag, and the booleans / null.
// Floats and indefinite-length items are intentionally unsupported (never used by COSE_Sign1
// here) and are rejected on decode — a forged receipt that uses them fails closed.
// ========================================================================================

/** A CBOR map key: an integer (COSE header label) or a text string. */
export type CborKey = number | string;

/** A CBOR value in this minimal model. */
export type CborValue = number | string | Uint8Array | boolean | null | CborValue[] | Map<CborKey, CborValue> | CborTag;

/** A CBOR tagged value (major type 6) — used here for the COSE_Sign1 tag (18). */
export class CborTag {
  constructor(
    readonly tag: number,
    readonly value: CborValue,
  ) {}
}

/** True when `s` has no lone UTF-16 surrogate (it would be silently replaced by U+FFFD when encoded). */
function isWellFormed(s: string): boolean {
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

function isInt(n: number): boolean {
  return Number.isInteger(n) && Number.isSafeInteger(n);
}

/** Head bytes for (major, argument). Argument must be a non-negative safe integer. */
function head(major: number, arg: number): number[] {
  const mt = major << 5;
  if (arg < 24) return [mt | arg];
  if (arg < 0x100) return [mt | 24, arg];
  if (arg < 0x10000) return [mt | 25, (arg >>> 8) & 0xff, arg & 0xff];
  if (arg < 0x100000000) return [mt | 26, (arg >>> 24) & 0xff, (arg >>> 16) & 0xff, (arg >>> 8) & 0xff, arg & 0xff];
  const hi = Math.floor(arg / 0x100000000);
  const lo = arg % 0x100000000;
  return [
    mt | 27,
    (hi >>> 24) & 0xff,
    (hi >>> 16) & 0xff,
    (hi >>> 8) & 0xff,
    hi & 0xff,
    (lo >>> 24) & 0xff,
    (lo >>> 16) & 0xff,
    (lo >>> 8) & 0xff,
    lo & 0xff,
  ];
}

function concat(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

function cmpBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a[i]! - b[i]!;
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/** Deterministically encode a CBOR value to bytes. Throws on anything outside the supported profile. */
export function encode(v: CborValue): Uint8Array {
  if (v === null) return new Uint8Array([0xf6]);
  if (v === false) return new Uint8Array([0xf4]);
  if (v === true) return new Uint8Array([0xf5]);
  if (typeof v === 'number') {
    if (!isInt(v)) throw new TypeError('cbor: only safe-integer numbers are supported');
    return v >= 0 ? new Uint8Array(head(0, v)) : new Uint8Array(head(1, -1 - v));
  }
  if (typeof v === 'string') {
    if (!isWellFormed(v)) throw new TypeError('cbor: text string contains a lone surrogate');
    const bytes = utf8(v);
    return concat([new Uint8Array(head(3, bytes.length)), bytes]);
  }
  if (v instanceof Uint8Array) {
    return concat([new Uint8Array(head(2, v.length)), v]);
  }
  if (Array.isArray(v)) {
    const items = v.map(encode);
    return concat([new Uint8Array(head(4, v.length)), ...items]);
  }
  if (v instanceof Map) {
    const entries: { k: Uint8Array; val: Uint8Array }[] = [];
    for (const [key, val] of v) entries.push({ k: encodeKey(key), val: encode(val) });
    entries.sort((x, y) => cmpBytes(x.k, y.k));
    for (let i = 1; i < entries.length; i++) {
      if (cmpBytes(entries[i - 1]!.k, entries[i]!.k) === 0) throw new TypeError('cbor: duplicate map key');
    }
    return concat([new Uint8Array(head(5, v.size)), ...entries.flatMap((e) => [e.k, e.val])]);
  }
  if (v instanceof CborTag) {
    if (!isInt(v.tag) || v.tag < 0) throw new TypeError('cbor: bad tag');
    return concat([new Uint8Array(head(6, v.tag)), encode(v.value)]);
  }
  throw new TypeError('cbor: unsupported value');
}

function encodeKey(k: CborKey): Uint8Array {
  if (typeof k === 'number') {
    if (!isInt(k)) throw new TypeError('cbor: bad integer map key');
    return k >= 0 ? new Uint8Array(head(0, k)) : new Uint8Array(head(1, -1 - k));
  }
  if (!isWellFormed(k)) throw new TypeError('cbor: text string contains a lone surrogate');
  const bytes = utf8(k);
  return concat([new Uint8Array(head(3, bytes.length)), bytes]);
}

// ignoreBOM: a leading U+FEFF is data, not an encoding marker; dropping it would make two encodings decode alike.
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

class Reader {
  pos = 0;
  constructor(readonly buf: Uint8Array) {}

  private byte(): number {
    if (this.pos >= this.buf.length) throw new RangeError('cbor: unexpected end of input');
    const b = this.buf[this.pos]!;
    this.pos++;
    return b;
  }

  private bytes(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new RangeError('cbor: unexpected end of input');
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  private readUint(n: number): number {
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + this.byte();
    if (!Number.isSafeInteger(v)) throw new RangeError('cbor: integer out of safe range');
    return v;
  }

  /** Read (major, argument). Enforces minimal-length (canonical) argument encoding. */
  private readHead(): { major: number; arg: number } {
    const ib = this.byte();
    const major = ib >> 5;
    const info = ib & 0x1f;
    if (major === 7 && info >= 24) throw new RangeError('cbor: unsupported simple/float value'); // floats and 1-byte simple values
    if (info < 24) return { major, arg: info };
    if (info === 24) {
      const arg = this.readUint(1);
      if (arg < 24) throw new RangeError('cbor: non-minimal integer');
      return { major, arg };
    }
    if (info === 25) {
      const arg = this.readUint(2);
      if (arg < 0x100) throw new RangeError('cbor: non-minimal integer');
      return { major, arg };
    }
    if (info === 26) {
      const arg = this.readUint(4);
      if (arg < 0x10000) throw new RangeError('cbor: non-minimal integer');
      return { major, arg };
    }
    if (info === 27) {
      const arg = this.readUint(8);
      if (arg < 0x100000000) throw new RangeError('cbor: non-minimal integer');
      return { major, arg };
    }
    throw new RangeError('cbor: unsupported additional information (indefinite/reserved)');
  }

  value(): CborValue {
    const { major, arg } = this.readHead();
    switch (major) {
      case 0:
        return arg;
      case 1:
        if (!Number.isSafeInteger(-1 - arg)) throw new RangeError('cbor: integer out of safe range');
        return -1 - arg;
      case 2:
        return this.bytes(arg);
      case 3:
        return TEXT_DECODER.decode(this.bytes(arg));
      case 4: {
        const out: CborValue[] = [];
        for (let i = 0; i < arg; i++) out.push(this.value());
        return out;
      }
      case 5: {
        const map = new Map<CborKey, CborValue>();
        let prevKeyBytes: Uint8Array | null = null;
        for (let i = 0; i < arg; i++) {
          const keyStart = this.pos;
          const key = this.value();
          if (typeof key !== 'number' && typeof key !== 'string') throw new TypeError('cbor: map key must be int or text');
          const keyBytes = this.buf.slice(keyStart, this.pos);
          if (prevKeyBytes && cmpBytes(prevKeyBytes, keyBytes) >= 0) throw new RangeError('cbor: map keys not canonically ordered / duplicate');
          prevKeyBytes = keyBytes;
          map.set(key, this.value());
        }
        return map;
      }
      case 6:
        return new CborTag(arg, this.value());
      case 7:
        if (arg === 20) return false;
        if (arg === 21) return true;
        if (arg === 22) return null;
        throw new RangeError('cbor: unsupported simple/float value');
      default:
        throw new RangeError('cbor: unsupported major type');
    }
  }
}

/** Strictly decode a single canonical CBOR value, requiring the whole buffer to be consumed. */
export function decode(bytes: Uint8Array): CborValue {
  const r = new Reader(bytes);
  const v = r.value();
  if (r.pos !== bytes.length) throw new RangeError('cbor: trailing bytes');
  return v;
}

// ========================================================================================
// COSE + SCITT constants
// ========================================================================================

/** COSE_Sign1 CBOR tag (RFC 9052 §4.2). */
export const COSE_SIGN1_TAG = 18;
/** COSE header parameter labels (RFC 9052 / RFC 9597). */
export const HDR_ALG = 1;
export const HDR_CONTENT_TYPE = 3;
export const HDR_CWT_CLAIMS = 15; // RFC 9597 "CWT Claims" COSE header parameter
/** CWT claim keys (RFC 8392). */
export const CWT_ISS = 1;
export const CWT_SUB = 2;
/** RFC 9942 COSE Receipts header parameters. */
export const HDR_VDS = 395; // verifiable-data-structure (protected)
export const HDR_VDS_PROOFS = 396; // verifiable-data-structure-proofs (unprotected)
/** RFC 9942 verifiable data structure identifier: RFC9162_SHA256 (Certificate-Transparency Merkle). */
export const VDS_RFC9162_SHA256 = 1;
/** RFC 9942 proof type within the proofs map for RFC9162_SHA256: inclusion. */
export const PROOF_TYPE_INCLUSION = -1;

/** Default content type stamped on a Signed Statement whose payload is a canonical PCActn/verdict. */
export const DEFAULT_CONTENT_TYPE = 'application/pca+json';

// ========================================================================================
// Signature suites (node:crypto) — EdDSA (Ed25519) and ES256 (ECDSA P-256, IEEE-P1363 raw).
// ========================================================================================

export type CoseAlg = 'EdDSA' | 'ES256';

const ALG_LABEL: Record<CoseAlg, number> = { EdDSA: -8, ES256: -7 };

function algForLabel(label: number): CoseAlg | null {
  if (label === -8) return 'EdDSA';
  if (label === -7) return 'ES256';
  return null;
}

function signBytes(alg: CoseAlg, key: KeyObject, msg: Uint8Array): Uint8Array {
  if (alg === 'EdDSA') return new Uint8Array(nodeSign(null, msg, key));
  return new Uint8Array(nodeSign('sha256', msg, { key, dsaEncoding: 'ieee-p1363' }));
}

function verifyBytes(alg: CoseAlg, key: KeyObject, msg: Uint8Array, sig: Uint8Array): boolean {
  if (alg === 'EdDSA') return nodeVerify(null, msg, key, sig);
  return nodeVerify('sha256', msg, { key, dsaEncoding: 'ieee-p1363' }, sig);
}

/** The COSE_Sign1 `Sig_structure` to-be-signed bytes (RFC 9052 §4.4), external_aad empty. */
function sigStructure(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  return encode(['Signature1', protectedBytes, new Uint8Array(0), payload]);
}

// ========================================================================================
// Signed Statements (RFC 9943 §4): a COSE_Sign1 over a PCActn / verdict.
// ========================================================================================

export interface SignStatementOpts {
  alg: CoseAlg;
  /** The issuer's PRIVATE key (node:crypto KeyObject). */
  key: KeyObject;
  /** Issuer / feed identifier, carried in the CWT Claims header (iss). */
  issuer: string;
  /** Optional subject (CWT sub) — e.g. the grant_ref or principal the statement is about. */
  subject?: string;
  /** Payload content type (defaults to {@link DEFAULT_CONTENT_TYPE}). */
  contentType?: string;
}

/**
 * Sign a PCActn / verdict as a COSE Signed Statement (COSE_Sign1). The protected header carries the
 * signature algorithm, the payload content type and the CWT Claims (issuer, optional subject); the
 * payload is the strict-canonical serialization of `payload` (byte-reproducible by any verifier).
 */
export function signStatement(payload: unknown, opts: SignStatementOpts): Uint8Array {
  const prot = new Map<CborKey, CborValue>();
  prot.set(HDR_ALG, ALG_LABEL[opts.alg]);
  prot.set(HDR_CONTENT_TYPE, opts.contentType ?? DEFAULT_CONTENT_TYPE);
  const claims = new Map<CborKey, CborValue>();
  claims.set(CWT_ISS, opts.issuer);
  if (opts.subject !== undefined) claims.set(CWT_SUB, opts.subject);
  prot.set(HDR_CWT_CLAIMS, claims);

  const protectedBytes = encode(prot);
  const payloadBytes = canonicalBytes(payload);
  const sig = signBytes(opts.alg, opts.key, sigStructure(protectedBytes, payloadBytes));
  return encode(new CborTag(COSE_SIGN1_TAG, [protectedBytes, new Map<CborKey, CborValue>(), payloadBytes, sig]));
}

interface CoseSign1 {
  protectedBytes: Uint8Array;
  protectedMap: Map<CborKey, CborValue>;
  unprotected: Map<CborKey, CborValue>;
  /** The embedded payload, or null when detached (`nil`). */
  payload: Uint8Array | null;
  signature: Uint8Array;
}

/** Decode and structurally validate a COSE_Sign1 (tag 18). Throws on any deviation. */
function decodeCoseSign1(bytes: Uint8Array): CoseSign1 {
  const top = decode(bytes);
  if (!(top instanceof CborTag) || top.tag !== COSE_SIGN1_TAG) throw new TypeError('cose: not a COSE_Sign1 (tag 18)');
  const arr = top.value;
  if (!Array.isArray(arr) || arr.length !== 4) throw new TypeError('cose: malformed COSE_Sign1 array');
  const [protectedBytes, unprotected, payload, signature] = arr;
  if (!(protectedBytes instanceof Uint8Array)) throw new TypeError('cose: protected must be a bstr');
  if (!(unprotected instanceof Map)) throw new TypeError('cose: unprotected must be a map');
  if (!(payload instanceof Uint8Array) && payload !== null) throw new TypeError('cose: payload must be a bstr or nil');
  if (!(signature instanceof Uint8Array)) throw new TypeError('cose: signature must be a bstr');
  const protectedMap = protectedBytes.length === 0 ? new Map<CborKey, CborValue>() : decodeMap(decode(protectedBytes));
  return { protectedBytes, protectedMap, unprotected, payload, signature };
}

function decodeMap(v: CborValue): Map<CborKey, CborValue> {
  if (!(v instanceof Map)) throw new TypeError('cbor: expected a map');
  return v;
}

function algOf(protectedMap: Map<CborKey, CborValue>): CoseAlg {
  const label = protectedMap.get(HDR_ALG);
  if (label === undefined) throw new TypeError('cose: missing alg header');
  const alg = typeof label === 'number' ? algForLabel(label) : null;
  if (alg === null) throw new TypeError('cose: unsupported alg');
  return alg;
}

/** Outcome of {@link checkStatement}: success, or the specific reason verification failed. */
export type StatementCheck = { ok: true } | { ok: false; reason: string };

/**
 * Verify a Signed Statement and say WHY it failed. Reasons: `malformed: <detail>` (not a canonical tag-18
 * COSE_Sign1), `unsupported alg` / `missing alg header` (the algorithm must be a protected header and one
 * of EdDSA / ES256), `detached payload` (statements must carry their payload), or `bad signature`.
 * Never throws. The COSE `external_aad` is always empty.
 */
export function checkStatement(statement: Uint8Array, publicKey: KeyObject): StatementCheck {
  let s: CoseSign1;
  try {
    s = decodeCoseSign1(statement);
  } catch (e) {
    return { ok: false, reason: `malformed: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (s.payload === null) return { ok: false, reason: 'detached payload' };
  let alg: CoseAlg;
  try {
    alg = algOf(s.protectedMap);
  } catch (e) {
    return { ok: false, reason: e instanceof Error && e.message.includes('missing') ? 'missing alg header' : 'unsupported alg' };
  }
  try {
    return verifyBytes(alg, publicKey, sigStructure(s.protectedBytes, s.payload), s.signature) ? { ok: true } : { ok: false, reason: 'bad signature' };
  } catch {
    return { ok: false, reason: 'bad signature' };
  }
}

/** Verify a Signed Statement's COSE_Sign1 signature against the issuer public key. Never throws. */
export function verifyStatement(statement: Uint8Array, publicKey: KeyObject): boolean {
  return checkStatement(statement, publicKey).ok;
}

/** The raw canonical payload bytes carried by a Signed Statement. Throws on a malformed statement. */
export function statementPayload(statement: Uint8Array): Uint8Array {
  const { payload } = decodeCoseSign1(statement);
  if (payload === null) throw new TypeError('cose: statement payload is detached');
  return payload;
}

/** The b64u leaf a statement occupies in the transparency log (the Merkle leaf is bound to these bytes). */
export function statementLeaf(statement: Uint8Array): string {
  return b64u(statement);
}

// ========================================================================================
// RFC 9162 inclusion proof codec. The proof is [tree_size, leaf_index, inclusion_path], where
// inclusion_path is the bottom-up list of sibling hashes (bstr). Sibling SIDES are implicit —
// fully determined by (index, size) under the RFC 6962 split — so they are not transmitted and
// are re-derived on verification (matching `@atlasauth/pca`'s merkle path shape).
// ========================================================================================

function splitN(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Sibling sides (leaf -> root) for `index` in a tree of `size` leaves (RFC 6962 split). */
function siblingSides(index: number, size: number): ('L' | 'R')[] {
  const out: ('L' | 'R')[] = [];
  let idx = index;
  let n = size;
  while (n > 1) {
    const k = splitN(n);
    if (idx < k) {
      out.push('R');
      n = k;
    } else {
      out.push('L');
      idx -= k;
      n -= k;
    }
  }
  return out.reverse();
}

/** Encode a core-Merkle {@link InclusionProof} as an RFC 9162 inclusion proof (CBOR bstr content). */
export function encodeInclusionProof(proof: InclusionProof): Uint8Array {
  const sibs: CborValue[] = proof.path.map((step) => {
    const h = decodeB64uStrict(step.hash, 32);
    if (!h) throw new TypeError('scitt: proof step hash is not a 32-byte b64u hash');
    return h;
  });
  return encode([proof.size, proof.index, sibs]);
}

/** Decode an RFC 9162 inclusion proof back into a core-Merkle {@link InclusionProof} (sides re-derived). */
export function decodeInclusionProof(bytes: Uint8Array): InclusionProof {
  const v = decode(bytes);
  if (!Array.isArray(v) || v.length !== 3) throw new TypeError('scitt: malformed inclusion proof');
  const [size, index, sibs] = v;
  if (typeof size !== 'number' || typeof index !== 'number') throw new TypeError('scitt: proof size/index must be integers');
  if (!Number.isSafeInteger(size) || !Number.isSafeInteger(index) || size < 1 || index < 0 || index >= size) {
    throw new RangeError('scitt: proof size/index out of range');
  }
  if (!Array.isArray(sibs)) throw new TypeError('scitt: inclusion path must be an array');
  const sides = siblingSides(index, size);
  if (sibs.length !== sides.length) throw new RangeError('scitt: inclusion path length does not match (index,size)');
  const path: ProofStep[] = sibs.map((h, i) => {
    if (!(h instanceof Uint8Array) || h.length !== 32) throw new TypeError('scitt: inclusion path entry must be a 32-byte bstr');
    return { side: sides[i]!, hash: b64u(h) };
  });
  return { index, size, path };
}

// ========================================================================================
// COSE Receipts (RFC 9942): a COSE_Sign1 signed by the Transparency Service whose payload is the
// Merkle tree root and whose unprotected header carries the RFC 9162 inclusion proof.
// ========================================================================================

export interface ReceiptSignerOpts {
  alg: CoseAlg;
  /** The Transparency Service PRIVATE key. */
  key: KeyObject;
  /** Optional TS issuer id (CWT iss in the receipt's protected header). */
  issuer?: string;
}

/**
 * Build a signed COSE Receipt for `proof` against ledger root `root` (b64u, 32-byte SHA-256). The receipt's
 * payload is detached (`nil`); the signature covers the root a verifier recomputes from the inclusion proof.
 */
export function buildReceipt(root: string, proof: InclusionProof, signer: ReceiptSignerOpts): Uint8Array {
  const rootBytes = decodeB64uStrict(root, 32);
  if (!rootBytes) throw new TypeError('scitt: tree root is not a 32-byte b64u hash');

  const prot = new Map<CborKey, CborValue>();
  prot.set(HDR_ALG, ALG_LABEL[signer.alg]);
  prot.set(HDR_VDS, VDS_RFC9162_SHA256);
  if (signer.issuer !== undefined) {
    const claims = new Map<CborKey, CborValue>();
    claims.set(CWT_ISS, signer.issuer);
    prot.set(HDR_CWT_CLAIMS, claims);
  }
  const protectedBytes = encode(prot);

  const proofs = new Map<CborKey, CborValue>();
  proofs.set(PROOF_TYPE_INCLUSION, [encodeInclusionProof(proof)]);
  const unprotected = new Map<CborKey, CborValue>();
  unprotected.set(HDR_VDS_PROOFS, proofs);

  // RFC 9942 section 4.4: the payload SHOULD be detached, so a verifier must recompute the root from the proof.
  const sig = signBytes(signer.alg, signer.key, sigStructure(protectedBytes, rootBytes));
  return encode(new CborTag(COSE_SIGN1_TAG, [protectedBytes, unprotected, null, sig]));
}

/** The pieces a decoded receipt exposes for verification. */
interface DecodedReceipt {
  cose: CoseSign1;
  proof: InclusionProof;
}

function decodeReceipt(receipt: Uint8Array): DecodedReceipt {
  const cose = decodeCoseSign1(receipt);
  const vds = cose.protectedMap.get(HDR_VDS);
  if (vds !== VDS_RFC9162_SHA256) throw new TypeError('scitt: receipt is not RFC9162_SHA256');
  if (cose.payload !== null && cose.payload.length !== 32) throw new TypeError('scitt: receipt payload (root) must be 32 bytes');
  const proofsRaw = cose.unprotected.get(HDR_VDS_PROOFS);
  if (!(proofsRaw instanceof Map)) throw new TypeError('scitt: missing verifiable-data-structure-proofs');
  const inclusion = proofsRaw.get(PROOF_TYPE_INCLUSION);
  if (!Array.isArray(inclusion) || inclusion.length < 1) throw new TypeError('scitt: missing inclusion proof');
  const first = inclusion[0];
  if (!(first instanceof Uint8Array)) throw new TypeError('scitt: inclusion proof must be a bstr');
  return { cose, proof: decodeInclusionProof(first) };
}

/** The sibling hashes of a core proof as raw bytes (leaf -> root order). */
function proofHashes(proof: InclusionProof): Uint8Array[] {
  return proof.path.map((step) => {
    const h = decodeB64uStrict(step.hash, 32);
    if (!h) throw new TypeError('scitt: proof step hash is not a 32-byte b64u hash');
    return h;
  });
}

export interface VerifyReceiptOpts {
  /**
   * The expected (pinned, out-of-band) tree root (b64u). When given, the receipt's own root MUST equal it
   * and the inclusion proof is checked against it.
   */
  treeRoot?: string;
  /**
   * The Transparency Service PUBLIC key. When given, the receipt's COSE signature over the root is verified
   * and the (now-trusted) signed root is used as the inclusion anchor.
   */
  verificationKey?: KeyObject;
  /** The issuer PUBLIC key of the Signed Statement. When given, the statement's own signature is verified. */
  statementKey?: KeyObject;
}

/**
 * Verify a COSE Receipt for a Signed Statement. FAIL-CLOSED (returns a boolean, never throws). All of the
 * following must hold:
 *   1. at least one anchor is supplied (`treeRoot` and/or `verificationKey`);
 *   2. when `verificationKey` is given, the receipt's TS signature over the root verifies;
 *   3. when `treeRoot` is given, it equals the receipt's root;
 *   4. the RFC 9162 inclusion proof binds the EXACT statement bytes (leaf = SHA-256(0x00 || statement)) to that root;
 *   5. when `statementKey` is given, the Signed Statement's own COSE signature verifies.
 * A tampered statement breaks (4) (and (5)); a forged receipt breaks (2) or (4); a wrong root breaks (3)/(4).
 */
export function verifyReceipt(receipt: Uint8Array, statement: Uint8Array, opts: VerifyReceiptOpts): boolean {
  try {
    if (opts.treeRoot === undefined && opts.verificationKey === undefined) return false; // no anchor
    const dec = decodeReceipt(receipt);

    // Apply the inclusion proof to the exact statement bytes; the result is the root the receipt commits to.
    const root = rootFromInclusionPath(leafHash(statement), dec.proof.index, dec.proof.size, proofHashes(dec.proof));
    if (root === null) return false;
    // An embedded payload must be that same root; a detached one is simply replaced by it (RFC 9942 section 5.2.1).
    if (dec.cose.payload !== null && b64u(dec.cose.payload) !== b64u(root)) return false;

    if (opts.verificationKey) {
      const alg = algOf(dec.cose.protectedMap);
      if (!verifyBytes(alg, opts.verificationKey, sigStructure(dec.cose.protectedBytes, root), dec.cose.signature)) {
        return false;
      }
    }
    if (opts.treeRoot !== undefined && opts.treeRoot !== b64u(root)) return false;

    if (opts.statementKey && !verifyStatement(statement, opts.statementKey)) return false;
    return true;
  } catch {
    return false;
  }
}

// ========================================================================================
// Transparency Service (RFC 9943 §2/§4): an append-only log of Signed Statements whose Merkle
// backend is reused from `@atlasauth/pca` (`TransparencyLedger` over the statement leaves). Each
// registration returns a signed COSE Receipt proving inclusion against the current ledger root.
// ========================================================================================

export interface TransparencyServiceOpts {
  /** Receipt-signing algorithm. */
  alg: CoseAlg;
  /** The Transparency Service PRIVATE signing key. */
  key: KeyObject;
  /** Optional TS issuer id, stamped into every receipt's CWT Claims header. */
  issuer?: string;
}

export interface RegistrationResult {
  index: number;
  receipt: Uint8Array;
  root: string;
}

export interface AppendResult extends RegistrationResult {
  statement: Uint8Array;
}

export class TransparencyService {
  private readonly statements: Uint8Array[] = []; // the registered Signed Statements (the log entries)
  private readonly leafHashes: Uint8Array[] = []; // SHA-256(0x00 || statement), RFC 9162 section 2.1.1
  private readonly signer: ReceiptSignerOpts;

  constructor(opts: TransparencyServiceOpts) {
    this.signer = { alg: opts.alg, key: opts.key, ...(opts.issuer !== undefined ? { issuer: opts.issuer } : {}) };
  }

  /** Current number of registered statements. */
  get size(): number {
    return this.statements.length;
  }

  /** The current Merkle tree root (b64u); the empty-log root (SHA-256 of nothing) for an empty service. */
  get root(): string {
    return b64u(treeHash(this.leafHashes));
  }

  /** The statement leaves (b64u of each Signed Statement) currently in the log, in order. */
  snapshot(): string[] {
    return this.statements.map((st) => b64u(st));
  }

  private receiptFor(index: number): RegistrationResult {
    const root = treeHash(this.leafHashes);
    const sides = siblingSides(index, this.leafHashes.length);
    const path = inclusionPath(this.leafHashes, index).map((h, i): ProofStep => ({ side: sides[i]!, hash: b64u(h) }));
    const proof: InclusionProof = { index, size: this.leafHashes.length, path };
    return { index, receipt: buildReceipt(b64u(root), proof, this.signer), root: b64u(root) };
  }

  /** Register an already-signed Signed Statement; append it and return a signed inclusion Receipt. */
  register(statement: Uint8Array): RegistrationResult {
    // Structurally validate the statement before it enters the log (fail closed on garbage).
    const cose = decodeCoseSign1(statement);
    if (cose.payload === null) throw new TypeError('scitt: cannot register a statement with a detached payload');
    const index = this.statements.length;
    this.statements.push(new Uint8Array(statement));
    this.leafHashes.push(leafHash(statement));
    return this.receiptFor(index);
  }

  /** Sign `payload` as a Signed Statement, register it, and return the statement plus its Receipt. */
  appendAndReceipt(payload: unknown, stmt: SignStatementOpts): AppendResult {
    const statement = signStatement(payload, stmt);
    return { statement, ...this.register(statement) };
  }

  /** Re-issue a Receipt for an already-registered statement, against the CURRENT ledger root. */
  getReceipt(index: number): RegistrationResult {
    if (!Number.isInteger(index) || index < 0 || index >= this.statements.length) throw new RangeError('getReceipt: index out of range');
    return this.receiptFor(index);
  }

  /**
   * An RFC 9162 consistency proof that the log at `oldSize` entries is a prefix of the current log. The
   * result carries both roots and the proof in the RFC 9942 `consistency-proof-content` CBOR encoding.
   */
  consistencyProof(oldSize: number): ConsistencyProofResult {
    if (!Number.isInteger(oldSize) || oldSize < 1 || oldSize > this.statements.length) throw new RangeError('consistencyProof: size out of range');
    const path = consistencyPath(this.leafHashes, oldSize);
    return {
      oldSize,
      newSize: this.statements.length,
      oldRoot: b64u(treeHash(this.leafHashes.slice(0, oldSize))),
      newRoot: this.root,
      proof: encode([oldSize, this.statements.length, path]),
    };
  }
}

export interface ConsistencyProofResult {
  oldSize: number;
  newSize: number;
  /** Root (b64u) of the log at `oldSize`. */
  oldRoot: string;
  /** Root (b64u) of the log at `newSize`. */
  newRoot: string;
  /** CBOR `[tree-size-1, tree-size-2, [+ bstr]]` (RFC 9942 section 5.3). */
  proof: Uint8Array;
}

/**
 * Verify an RFC 9942 / RFC 9162 consistency proof between two pinned roots (b64u). FAIL-CLOSED boolean:
 * the encoded sizes must match `oldSize` / `newSize` implied by the proof itself, and the RFC 9162
 * section 2.1.4.2 algorithm must reproduce both roots.
 */
export function verifyConsistencyProof(proof: Uint8Array, oldRoot: string, newRoot: string): boolean {
  try {
    const v = decode(proof);
    if (!Array.isArray(v) || v.length !== 3) return false;
    const [oldSize, newSize, path] = v;
    if (typeof oldSize !== 'number' || typeof newSize !== 'number' || !Array.isArray(path)) return false;
    if (!path.every((h): h is Uint8Array => h instanceof Uint8Array)) return false;
    const r1 = decodeB64uStrict(oldRoot, 32);
    const r2 = decodeB64uStrict(newRoot, 32);
    if (!r1 || !r2) return false;
    return verifyConsistencyPath(oldSize, newSize, r1, r2, path);
  } catch {
    return false;
  }
}

/** Register a Signed Statement into a Transparency Service (RFC 9943 register-signed-statement). */
export function registerStatement(statement: Uint8Array, service: TransparencyService): RegistrationResult {
  return service.register(statement);
}
