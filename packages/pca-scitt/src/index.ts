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
 * Self-contained: a hand-rolled, deterministic (RFC 8949 §4.2.1 core-deterministic) CBOR codec — no CBOR
 * library — sufficient for COSE_Sign1, and `node:crypto` for all signing/verification. The Merkle tree and
 * append-only ledger are the ones in `@atlasauth/pca` (the `TransparencyLedger` / `merkle` core).
 */
import {
  type InclusionProof,
  type ProofStep,
  TransparencyLedger,
  canonicalBytes,
  decodeB64uStrict,
  b64u,
  utf8,
  verifyInclusion,
} from '@atlasauth/pca';
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
  const bytes = utf8(k);
  return concat([new Uint8Array(head(3, bytes.length)), bytes]);
}

const TEXT_DECODER = new TextDecoder('utf-8', { fatal: true });

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
  payload: Uint8Array;
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
  if (!(payload instanceof Uint8Array)) throw new TypeError('cose: payload must be a bstr');
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
  if (typeof label !== 'number') throw new TypeError('cose: missing alg header');
  const alg = algForLabel(label);
  if (alg === null) throw new TypeError('cose: unsupported alg');
  return alg;
}

/** Verify a Signed Statement's COSE_Sign1 signature against the issuer public key. Never throws. */
export function verifyStatement(statement: Uint8Array, publicKey: KeyObject): boolean {
  try {
    const s = decodeCoseSign1(statement);
    const alg = algOf(s.protectedMap);
    return verifyBytes(alg, publicKey, sigStructure(s.protectedBytes, s.payload), s.signature);
  } catch {
    return false;
  }
}

/** The raw canonical payload bytes carried by a Signed Statement. Throws on a malformed statement. */
export function statementPayload(statement: Uint8Array): Uint8Array {
  return decodeCoseSign1(statement).payload;
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

/** Build a signed COSE Receipt for `proof` against ledger root `root` (b64u, 32-byte SHA-256). */
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

  const sig = signBytes(signer.alg, signer.key, sigStructure(protectedBytes, rootBytes));
  return encode(new CborTag(COSE_SIGN1_TAG, [protectedBytes, unprotected, rootBytes, sig]));
}

/** The pieces a decoded receipt exposes for verification. */
interface DecodedReceipt {
  cose: CoseSign1;
  rootB64: string;
  proof: InclusionProof;
}

function decodeReceipt(receipt: Uint8Array): DecodedReceipt {
  const cose = decodeCoseSign1(receipt);
  const vds = cose.protectedMap.get(HDR_VDS);
  if (vds !== VDS_RFC9162_SHA256) throw new TypeError('scitt: receipt is not RFC9162_SHA256');
  if (cose.payload.length !== 32) throw new TypeError('scitt: receipt payload (root) must be 32 bytes');
  const proofsRaw = cose.unprotected.get(HDR_VDS_PROOFS);
  if (!(proofsRaw instanceof Map)) throw new TypeError('scitt: missing verifiable-data-structure-proofs');
  const inclusion = proofsRaw.get(PROOF_TYPE_INCLUSION);
  if (!Array.isArray(inclusion) || inclusion.length < 1) throw new TypeError('scitt: missing inclusion proof');
  const first = inclusion[0];
  if (!(first instanceof Uint8Array)) throw new TypeError('scitt: inclusion proof must be a bstr');
  return { cose, rootB64: b64u(cose.payload), proof: decodeInclusionProof(first) };
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
 *   4. the RFC 9162 inclusion proof binds the EXACT statement bytes (leaf = b64u(statement)) to that root;
 *   5. when `statementKey` is given, the Signed Statement's own COSE signature verifies.
 * A tampered statement breaks (4) (and (5)); a forged receipt breaks (2) or (4); a wrong root breaks (3)/(4).
 */
export function verifyReceipt(receipt: Uint8Array, statement: Uint8Array, opts: VerifyReceiptOpts): boolean {
  try {
    if (opts.treeRoot === undefined && opts.verificationKey === undefined) return false; // no anchor
    const dec = decodeReceipt(receipt);

    if (opts.verificationKey) {
      const alg = algOf(dec.cose.protectedMap);
      if (!verifyBytes(alg, opts.verificationKey, sigStructure(dec.cose.protectedBytes, dec.cose.payload), dec.cose.signature)) {
        return false;
      }
    }
    if (opts.treeRoot !== undefined && opts.treeRoot !== dec.rootB64) return false;

    const leaf = b64u(statement);
    if (!verifyInclusion(dec.rootB64, dec.proof, leaf)) return false;

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
  private readonly leaves: string[] = []; // b64u(statement) — the ledger commits
  private readonly signer: ReceiptSignerOpts;

  constructor(opts: TransparencyServiceOpts) {
    this.signer = { alg: opts.alg, key: opts.key, ...(opts.issuer !== undefined ? { issuer: opts.issuer } : {}) };
  }

  /** Current number of registered statements. */
  get size(): number {
    return this.leaves.length;
  }

  /** Rebuild the backing `TransparencyLedger` (RFC 6962 Merkle) from the statement leaves. */
  private buildLedger(): TransparencyLedger {
    return TransparencyLedger.fromEntries(this.leaves.map((commit) => ({ commit })));
  }

  /** The current ledger (Merkle) root (b64u); the empty-log root for an empty service. */
  get root(): string {
    return this.buildLedger().head().root;
  }

  /** The statement leaves (b64u) currently in the log, in order. */
  snapshot(): string[] {
    return [...this.leaves];
  }

  /** Register an already-signed Signed Statement; append it and return a signed inclusion Receipt. */
  register(statement: Uint8Array): RegistrationResult {
    // Structurally validate the statement before it enters the log (fail closed on garbage).
    decodeCoseSign1(statement);
    const index = this.leaves.length;
    this.leaves.push(b64u(statement));
    const ledger = this.buildLedger();
    const root = ledger.head().root;
    const proof = ledger.inclusionProof(index);
    return { index, receipt: buildReceipt(root, proof, this.signer), root };
  }

  /** Sign `payload` as a Signed Statement, register it, and return the statement plus its Receipt. */
  appendAndReceipt(payload: unknown, stmt: SignStatementOpts): AppendResult {
    const statement = signStatement(payload, stmt);
    return { statement, ...this.register(statement) };
  }

  /** Re-issue a Receipt for an already-registered statement, against the CURRENT ledger root. */
  getReceipt(index: number): RegistrationResult {
    if (!Number.isInteger(index) || index < 0 || index >= this.leaves.length) throw new RangeError('getReceipt: index out of range');
    const ledger = this.buildLedger();
    const root = ledger.head().root;
    const proof = ledger.inclusionProof(index);
    return { index, receipt: buildReceipt(root, proof, this.signer), root };
  }
}

/** Register a Signed Statement into a Transparency Service (RFC 9943 register-signed-statement). */
export function registerStatement(statement: Uint8Array, service: TransparencyService): RegistrationResult {
  return service.register(statement);
}
