/**
 * SD-JWT primitives for AP2 mandates (RFC 9901): strict compact parsing, disclosure processing, the
 * `sd_hash` / `issuer_jwt_hash` binding digests, and ES256 (P-256) signing and verification.
 *
 * Nothing here implements a cryptographic primitive: SHA-2 and ECDSA come from `node:crypto`. The
 * code is the SD-JWT *format* (what is hashed, in which order, which shapes are accepted) and it
 * fails closed on every ambiguity (duplicate digests, unreferenced disclosures, malformed base64url,
 * duplicate JSON keys, unknown `_sd_alg`, non-ES256 algorithms).
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from 'node:crypto';

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
export type JsonObject = { [k: string]: Json };

/** Every failure raised while parsing or verifying carries a human-readable reason. */
export class Ap2Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Ap2Error';
  }
}

// ---------------------------------------------------------------------------------------------
// base64url + JSON helpers
// ---------------------------------------------------------------------------------------------

export function b64uEncode(data: Uint8Array | string): string {
  return Buffer.from(typeof data === 'string' ? Buffer.from(data, 'utf8') : data).toString('base64url');
}

/** Strict base64url decode: canonical alphabet, no padding, and the encoding must round-trip. */
export function b64uDecode(s: string, what: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Ap2Error(`${what}: not base64url`);
  const buf = Buffer.from(s, 'base64url');
  if (buf.toString('base64url') !== s) throw new Ap2Error(`${what}: non-canonical base64url`);
  return buf;
}

export function isObject(v: unknown): v is JsonObject {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Reject an object that repeats a key. `JSON.parse` silently keeps the last duplicate, which would let
 * two parties read different claims out of the same signed bytes. Run on text that already parsed, so
 * only string/brace structure needs tracking.
 */
function assertNoDuplicateKeys(text: string, what: string): void {
  const stack: (Set<string> | null)[] = [];
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (expectKey && top) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.has(key)) throw new Ap2Error(`${what}: duplicate key ${JSON.stringify(key)}`);
        top.add(key);
        expectKey = false;
      }
      i = j;
    } else if (c === '{') {
      stack.push(new Set());
      expectKey = true;
    } else if (c === '[') {
      stack.push(null);
      expectKey = false;
    } else if (c === '}' || c === ']') {
      stack.pop();
      expectKey = false;
    } else if (c === ',') {
      expectKey = stack[stack.length - 1] instanceof Set;
    }
  }
}

/**
 * JSON parse that rejects duplicate keys. Numbers are parsed as written (`1000.0` is accepted: the
 * official Python SDK serialises float fields that way).
 */
export function parseJson(text: string, what: string): unknown {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch (e) {
    throw new Ap2Error(`${what}: invalid JSON (${(e as Error).message})`);
  }
  assertNoDuplicateKeys(text, what);
  return v;
}

/**
 * UTF-8 text of decoded bytes, FATAL on any invalid sequence. `Buffer#toString('utf8')` silently substitutes U+FFFD, so
 * distinct byte strings would read as the same claims (a parser differential against strict decoders). The BOM is kept,
 * so `JSON.parse` refuses it.
 */
function utf8Text(bytes: Uint8Array, what: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Ap2Error(`${what}: not valid UTF-8`);
  }
}

/**
 * Set `out[k] = v` as an OWN data property. Plain assignment of the key `__proto__` would instead replace the object's
 * prototype: the claim would vanish from the own keys (and from any re-serialisation) while its members became readable
 * as inherited claims.
 */
function setClaim(out: JsonObject, k: string, v: Json): void {
  Object.defineProperty(out, k, { value: v, enumerable: true, writable: true, configurable: true });
}

function decodeJsonSegment(segment: string, what: string): JsonObject {
  const v = parseJson(utf8Text(b64uDecode(segment, what), what), what);
  if (!isObject(v)) throw new Ap2Error(`${what}: must be a JSON object`);
  return v;
}

// ---------------------------------------------------------------------------------------------
// hashing
// ---------------------------------------------------------------------------------------------

/** The `_sd_alg` values the AP2 reference SDK accepts. */
export type SdAlg = 'sha-256' | 'sha-384' | 'sha-512';
const NODE_HASH: Record<SdAlg, string> = { 'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512' };

export function isSdAlg(v: unknown): v is SdAlg {
  return v === 'sha-256' || v === 'sha-384' || v === 'sha-512';
}

/** base64url(hash(ascii(value))): the digest used for disclosures, `sd_hash` and `checkout_hash`. */
export function sdDigest(value: string, alg: SdAlg = 'sha-256'): string {
  if (!/^[\x20-\x7e]*$/.test(value)) throw new Ap2Error('digest input must be ASCII');
  return createHash(NODE_HASH[alg]).update(value, 'ascii').digest('base64url');
}

// ---------------------------------------------------------------------------------------------
// ES256 keys (P-256)
// ---------------------------------------------------------------------------------------------

/** An EC P-256 public key in JWK form (the shape of `types/jwk.json`). */
export interface P256Jwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  alg?: 'ES256';
  use?: 'sig' | 'enc';
  kid?: string;
  [k: string]: unknown;
}

export interface Ap2KeyPair {
  /** Public JWK (never contains `d`). */
  publicJwk: P256Jwk;
  privateKey: KeyObject;
}

const B64U_43 = /^[A-Za-z0-9_-]{43}$/;

/** Validate a public JWK against `types/jwk.json` and prove the point is on the curve. */
export function assertP256Jwk(jwk: unknown, what: string): P256Jwk {
  if (!isObject(jwk)) throw new Ap2Error(`${what}: JWK must be an object`);
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new Ap2Error(`${what}: JWK must be EC P-256`);
  if (typeof jwk.x !== 'string' || !B64U_43.test(jwk.x)) throw new Ap2Error(`${what}: bad JWK x`);
  if (typeof jwk.y !== 'string' || !B64U_43.test(jwk.y)) throw new Ap2Error(`${what}: bad JWK y`);
  if ('d' in jwk) throw new Ap2Error(`${what}: JWK carries private material`);
  if (jwk.alg !== undefined && jwk.alg !== 'ES256') throw new Ap2Error(`${what}: JWK alg must be ES256`);
  try {
    createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
  } catch {
    throw new Ap2Error(`${what}: JWK is not a valid P-256 point`);
  }
  return jwk as unknown as P256Jwk;
}

function publicKeyObject(jwk: P256Jwk): KeyObject {
  return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
}

export function generateAp2KeyPair(kid?: string): Ap2KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pub = publicKey.export({ format: 'jwk' });
  const publicJwk: P256Jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: String(pub.x),
    y: String(pub.y),
    ...(kid !== undefined ? { kid } : {}),
  };
  return { publicJwk, privateKey };
}

/** Rebuild a key pair from a private JWK (`d` present), e.g. for fixtures. */
export function ap2KeyPairFromPrivateJwk(jwk: Record<string, unknown>): Ap2KeyPair {
  const privateKey = createPrivateKey({ key: jwk as never, format: 'jwk' });
  const pub = createPublicKey(privateKey).export({ format: 'jwk' });
  const kid = typeof jwk.kid === 'string' ? jwk.kid : undefined;
  return {
    privateKey,
    publicJwk: { kty: 'EC', crv: 'P-256', x: String(pub.x), y: String(pub.y), ...(kid !== undefined ? { kid } : {}) },
  };
}

/** RFC 7638 JWK thumbprint (SHA-256) of an EC P-256 key. */
export function jwkThumbprint(jwk: P256Jwk): string {
  const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

/** ES256 over `signingInput`; returns the 64-byte `r || s` JWS signature as base64url. */
function es256Sign(privateKey: KeyObject, signingInput: string): string {
  return nodeSign('sha256', Buffer.from(signingInput, 'ascii'), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
}

function es256Verify(jwk: P256Jwk, signingInput: string, signature: Buffer): boolean {
  if (signature.length !== 64) return false;
  return nodeVerify('sha256', Buffer.from(signingInput, 'ascii'), { key: publicKeyObject(jwk), dsaEncoding: 'ieee-p1363' }, signature);
}

// ---------------------------------------------------------------------------------------------
// compact JWT / SD-JWT parsing
// ---------------------------------------------------------------------------------------------

export interface JwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
  x5c?: string[];
  [k: string]: unknown;
}

/** One SD-JWT: an issuer-signed JWT plus its disclosures (no trailing KB-JWT; AP2 binds with chain hops). */
export interface SdJwtHop {
  /** Canonical serialisation `<jwt>~<d1>~...~<dn>~`. */
  raw: string;
  jwt: string;
  header: JwtHeader;
  /** The signed payload exactly as issued (digest placeholders still in place). */
  payload: JsonObject;
  disclosures: string[];
  sdAlg: SdAlg;
  signingInput: string;
  signature: Buffer;
}

/** The hop's `~`-joined serialisation: what `sd_hash` is computed over. */
export function hopSdJwt(hop: Pick<SdJwtHop, 'jwt' | 'disclosures'>): string {
  return `${hop.jwt}~${hop.disclosures.map((d) => `${d}~`).join('')}`;
}

/** Parse one SD-JWT (`jwt~d1~...~dn~`). The serialisation must end with `~`. */
export function parseSdJwtHop(token: string): SdJwtHop {
  if (typeof token !== 'string' || token.length === 0) throw new Ap2Error('SD-JWT: empty');
  if (token.startsWith('~')) throw new Ap2Error('SD-JWT: empty issuer JWT');
  if (!token.endsWith('~')) throw new Ap2Error('SD-JWT: must end with "~" (a trailing KB-JWT is not an AP2 form)');
  const parts = token.slice(0, -1).split('~');
  const jwt = parts[0] ?? '';
  const disclosures = parts.slice(1);
  if (disclosures.some((d) => d.length === 0)) throw new Ap2Error('SD-JWT: empty disclosure segment');
  const seg = jwt.split('.');
  if (seg.length !== 3 || seg.some((s) => s.length === 0)) throw new Ap2Error('SD-JWT: issuer JWT must be header.payload.signature');
  const [h, p, s] = seg as [string, string, string];
  const header = decodeJsonSegment(h, 'JWT header') as JwtHeader;
  const payload = decodeJsonSegment(p, 'JWT payload');
  const signature = b64uDecode(s, 'JWT signature');
  const rawAlg = payload._sd_alg;
  if (rawAlg !== undefined && !isSdAlg(rawAlg)) throw new Ap2Error(`SD-JWT: unsupported _sd_alg ${JSON.stringify(rawAlg)}`);
  return {
    raw: token,
    jwt,
    header,
    payload,
    disclosures,
    sdAlg: isSdAlg(rawAlg) ? rawAlg : 'sha-256',
    signingInput: `${h}.${p}`,
    signature,
  };
}

/** `sd_hash` of a hop: the digest of `<jwt>~<d1>~...~` (the on-wire form of the preceding hop). */
export function sdHashOf(hop: SdJwtHop, alg: SdAlg = hop.sdAlg): string {
  return sdDigest(hopSdJwt(hop), alg);
}

/** `issuer_jwt_hash` of a hop: the digest of the issuer-signed JWT alone. */
export function issuerJwtHashOf(hop: SdJwtHop, alg: SdAlg = hop.sdAlg): string {
  return sdDigest(hop.jwt, alg);
}

/** Verify the issuer JWT's ES256 signature. Anything other than `alg: ES256` is rejected. */
export function verifyHopSignature(hop: SdJwtHop, key: P256Jwk): boolean {
  if (hop.header.alg !== 'ES256') return false;
  return es256Verify(assertP256Jwk(key, 'verification key'), hop.signingInput, hop.signature);
}

// ---------------------------------------------------------------------------------------------
// disclosure processing (RFC 9901 section 7)
// ---------------------------------------------------------------------------------------------

type Disclosure =
  | { kind: 'property'; name: string; value: Json; raw: string }
  | { kind: 'element'; value: Json; raw: string };

function decodeDisclosure(raw: string): Disclosure {
  const arr = parseJson(utf8Text(b64uDecode(raw, 'disclosure'), 'disclosure'), 'disclosure');
  if (!Array.isArray(arr)) throw new Ap2Error('disclosure: must be a JSON array');
  if (typeof arr[0] !== 'string' || arr[0].length === 0) throw new Ap2Error('disclosure: salt must be a non-empty string');
  if (arr.length === 3) {
    const name = arr[1];
    if (typeof name !== 'string') throw new Ap2Error('disclosure: claim name must be a string');
    if (name === '_sd' || name === '...') throw new Ap2Error(`disclosure: claim name ${name} is reserved`);
    return { kind: 'property', name, value: arr[2] as Json, raw };
  }
  if (arr.length === 2) return { kind: 'element', value: arr[1] as Json, raw };
  throw new Ap2Error('disclosure: array must have 2 or 3 elements');
}

/**
 * Resolve every selectively-disclosable claim in `payload` using `disclosures`. Returns the processed
 * claims (`_sd`, `...` markers and `_sd_alg` removed). Throws if a disclosure is duplicated, is not
 * referenced from the payload, collides with an existing claim, or is used in the wrong position.
 */
export function processDisclosures(payload: JsonObject, disclosures: string[], alg: SdAlg): JsonObject {
  const byDigest = new Map<string, Disclosure>();
  for (const raw of disclosures) {
    const d = decodeDisclosure(raw);
    const digest = sdDigest(raw, alg);
    if (byDigest.has(digest)) throw new Ap2Error('SD-JWT: duplicate disclosure');
    byDigest.set(digest, d);
  }
  const used = new Set<string>();

  const take = (digest: string, want: 'property' | 'element'): Disclosure | undefined => {
    const d = byDigest.get(digest);
    if (!d) return undefined; // decoy digest, or a disclosure the holder chose not to reveal
    if (used.has(digest)) throw new Ap2Error('SD-JWT: a digest is referenced more than once');
    if (d.kind !== want) throw new Ap2Error(`SD-JWT: a ${d.kind} disclosure is referenced from a ${want} position`);
    used.add(digest);
    return d;
  };

  const walk = (node: Json, depth: number): Json => {
    if (depth > 32) throw new Ap2Error('SD-JWT: nesting too deep');
    if (Array.isArray(node)) {
      const out: Json[] = [];
      for (const el of node) {
        if (isObject(el) && '...' in el) {
          const keys = Object.keys(el);
          if (keys.length !== 1 || typeof el['...'] !== 'string') throw new Ap2Error('SD-JWT: malformed array digest placeholder');
          const d = take(el['...'], 'element');
          if (d) out.push(walk(d.value, depth + 1));
        } else out.push(walk(el, depth + 1));
      }
      return out;
    }
    if (isObject(node)) {
      const out: JsonObject = {};
      for (const [k, v] of Object.entries(node)) {
        if (k === '_sd' || k === '_sd_alg') continue;
        if (k === '...') throw new Ap2Error('SD-JWT: "..." is only valid as the sole key of an array element');
        setClaim(out, k, walk(v, depth + 1));
      }
      const sd = node._sd;
      if (sd !== undefined) {
        if (!Array.isArray(sd) || sd.some((x) => typeof x !== 'string')) throw new Ap2Error('SD-JWT: _sd must be an array of strings');
        for (const digest of sd as string[]) {
          const d = take(digest, 'property');
          if (!d || d.kind !== 'property') continue;
          if (Object.prototype.hasOwnProperty.call(out, d.name)) throw new Ap2Error(`SD-JWT: disclosed claim ${d.name} collides with an existing claim`);
          setClaim(out, d.name, walk(d.value, depth + 1));
        }
      }
      return out;
    }
    return node;
  };

  const result = walk(payload, 0) as JsonObject;
  if (used.size !== byDigest.size) throw new Ap2Error('SD-JWT: a disclosure is not referenced by the signed payload');
  return result;
}

// ---------------------------------------------------------------------------------------------
// issuing
// ---------------------------------------------------------------------------------------------

export function newSalt(): string {
  return randomBytes(16).toString('base64url');
}

export interface DisclosureBuilder {
  /** Array-element disclosure for `value`; returns the `{ "...": digest }` placeholder. */
  element(value: Json): { '...': string };
  /** Property disclosure; returns the digest to put into the parent's `_sd`. */
  property(name: string, value: Json): string;
  readonly disclosures: string[];
}

export function disclosureBuilder(alg: SdAlg = 'sha-256', salt: () => string = newSalt): DisclosureBuilder {
  const disclosures: string[] = [];
  return {
    disclosures,
    element(value) {
      const raw = b64uEncode(JSON.stringify([salt(), value]));
      disclosures.push(raw);
      return { '...': sdDigest(raw, alg) };
    },
    property(name, value) {
      const raw = b64uEncode(JSON.stringify([salt(), name, value]));
      disclosures.push(raw);
      return sdDigest(raw, alg);
    },
  };
}

/** Sign `payload` as an ES256 JWT and append `disclosures`: `<jwt>~<d1>~...~<dn>~`. */
export function signSdJwt(args: {
  header: { typ: string; kid?: string; x5c?: string[] };
  payload: JsonObject;
  disclosures: string[];
  privateKey: KeyObject;
}): string {
  const header = b64uEncode(JSON.stringify({ alg: 'ES256', ...args.header }));
  const payload = b64uEncode(JSON.stringify(args.payload));
  const jwt = `${header}.${payload}.${es256Sign(args.privateKey, `${header}.${payload}`)}`;
  return `${jwt}~${args.disclosures.map((d) => `${d}~`).join('')}`;
}

/** Sign an arbitrary compact JWT (used for merchant-signed `checkout_jwt`). */
export function signJwtEs256(args: { header: Record<string, Json>; payload: JsonObject; privateKey: KeyObject }): string {
  const header = b64uEncode(JSON.stringify({ alg: 'ES256', typ: 'JWT', ...args.header }));
  const payload = b64uEncode(JSON.stringify(args.payload));
  return `${header}.${payload}.${es256Sign(args.privateKey, `${header}.${payload}`)}`;
}

export interface ParsedJwt {
  header: JwtHeader;
  payload: JsonObject;
  signingInput: string;
  signature: Buffer;
}

export function parseJwt(jwt: string, what: string): ParsedJwt {
  const seg = jwt.split('.');
  if (seg.length !== 3 || seg.some((s) => s.length === 0)) throw new Ap2Error(`${what}: must be header.payload.signature`);
  const [h, p, s] = seg as [string, string, string];
  return {
    header: decodeJsonSegment(h, `${what} header`) as JwtHeader,
    payload: decodeJsonSegment(p, `${what} payload`),
    signingInput: `${h}.${p}`,
    signature: b64uDecode(s, `${what} signature`),
  };
}

export function verifyJwtEs256(parsed: ParsedJwt, key: P256Jwk): boolean {
  if (parsed.header.alg !== 'ES256') return false;
  return es256Verify(assertP256Jwk(key, 'verification key'), parsed.signingInput, parsed.signature);
}
