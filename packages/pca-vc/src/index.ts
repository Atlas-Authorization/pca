/**
 * @atlasauth/pca-vc — emit the PCA agent passport in the converging verifiable-identity formats.
 *
 * HONEST FRAMING — a bridge, not a replacement. PCA's {@link AgentPassport} (packages/pca
 * `passport.ts`) is the source of truth: a content-addressed, attestation-rooted statement of *which*
 * agent is acting (model / weights / system-prompt / tool-manifest / operator / hardware root). This
 * package re-expresses that same passport in the shapes the wider ecosystem — Microsoft Entra Agent ID,
 * Google/AP2 agent payments, the Agent Transaction Envelope Protocol (ATEP), Cloudflare's Web Bot Auth —
 * is converging on, so a PCA agent can present a credential those systems already understand. It does not
 * mint new authority and it does not supersede the PCActn proof. Compose, don't replace.
 *
 * Standards implemented:
 *  - **W3C Verifiable Credentials Data Model 2.0** — the passport as a `VerifiableCredential`
 *    (`https://www.w3.org/ns/credentials/v2`), subtype `AgentPassportCredential`, secured as a JWT (EdDSA).
 *  - **SD-JWT VC** (draft-ietf-oauth-sd-jwt-vc, over draft-ietf-oauth-selective-disclosure-jwt) — each
 *    passport *digest* (weights / system-prompt / tool-manifest / runtime measurement) is emitted as a
 *    selectively-disclosable claim: its salted hash sits in `credentialSubject._sd` and the holder chooses
 *    which disclosures to release. The stable, always-present fields (model id, operator, hardware_rooted)
 *    stay in the clear.
 *  - **did:key** (w3c-ccg did:key, Ed25519) — issuer/subject identified by a did:key derived from an
 *    Ed25519 public key (multicodec `0xed01` + base58btc, `z…`).
 *  - **RFC 9421 HTTP Message Signatures** + **Web Bot Auth** (draft-ietf-webbotauth-httpsig-protocol) —
 *    sign a request over a covered-component set (`@method`, `@target-uri`, headers) with EdDSA, carrying
 *    the `Signature-Agent` header that points at the signer's key directory (`tag="web-bot-auth"`).
 */

import { createHash, randomBytes, sign as nodeSign, verify as nodeVerify, type KeyObject } from 'node:crypto';
import { SignJWT, jwtVerify, type KeyLike, type JWTPayload } from 'jose';
import type { AgentPassport } from '@atlasauth/pca';

// ---------------------------------------------------------------------------------------------------
// small JSON + base64url + narrowing helpers (no `any`)
// ---------------------------------------------------------------------------------------------------

type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}
function unb64u(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}
function sha256b64u(asciiInput: string): string {
  return createHash('sha256').update(asciiInput, 'ascii').digest().toString('base64url');
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function asString(v: unknown, label: string): string {
  if (typeof v !== 'string') throw new Error(`pca-vc: expected string for ${label}`);
  return v;
}
function asNumber(v: unknown, label: string): number {
  if (typeof v !== 'number') throw new Error(`pca-vc: expected number for ${label}`);
  return v;
}
function asBoolean(v: unknown, label: string): boolean {
  if (typeof v !== 'boolean') throw new Error(`pca-vc: expected boolean for ${label}`);
  return v;
}

// ---------------------------------------------------------------------------------------------------
// did:key (Ed25519) — multicodec 0xed01 + base58btc, 'z' multibase prefix
// ---------------------------------------------------------------------------------------------------

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);

function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i] as number;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i] as number];
  return out;
}

function base58btcDecode(str: string): Uint8Array {
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros++;
  const bytes: number[] = [];
  for (let i = zeros; i < str.length; i++) {
    const carryStart = B58.indexOf(str[i] as string);
    if (carryStart < 0) throw new Error('pca-vc: invalid base58btc character');
    let carry = carryStart;
    for (let j = 0; j < bytes.length; j++) {
      carry += (bytes[j] as number) * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + bytes.length - 1 - i] = bytes[i] as number;
  return out;
}

/** A `did:key` identifier for an Ed25519 public key (32 raw bytes). */
export function didKeyFromEd25519(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error('pca-vc: Ed25519 public key must be 32 bytes');
  const mc = new Uint8Array(ED25519_MULTICODEC.length + publicKey.length);
  mc.set(ED25519_MULTICODEC, 0);
  mc.set(publicKey, ED25519_MULTICODEC.length);
  return `did:key:z${base58btcEncode(mc)}`;
}

/** Recover the 32-byte Ed25519 public key from an Ed25519 `did:key`. Inverse of {@link didKeyFromEd25519}. */
export function ed25519FromDidKey(did: string): Uint8Array {
  const prefix = 'did:key:z';
  if (!did.startsWith(prefix)) throw new Error('pca-vc: not a did:key:z… identifier');
  const mc = base58btcDecode(did.slice(prefix.length));
  if (mc.length !== 34 || mc[0] !== 0xed || mc[1] !== 0x01) {
    throw new Error('pca-vc: did:key is not an Ed25519 (0xed01) key');
  }
  return mc.slice(2);
}

// ---------------------------------------------------------------------------------------------------
// W3C VC 2.0 as an SD-JWT VC
// ---------------------------------------------------------------------------------------------------

export const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
export const AGENT_PASSPORT_CONTEXT = 'https://atlasauth.net/credentials/agent-passport/v1';
export const AGENT_PASSPORT_VC_TYPE = 'AgentPassportCredential';

/** The passport fields emitted as selectively-disclosable SD-JWT claims (the sensitive measurements). */
const SD_DIGEST_FIELDS = [
  'weights_digest',
  'system_prompt_digest',
  'tool_manifest_digest',
  'runtime_measurement',
] as const;

export interface PassportToVCArgs {
  /** The issuer's Ed25519 signing key (jose `KeyLike`; a Node `KeyObject` works). */
  issuerKey: KeyLike | Uint8Array;
  /** The issuer's identifier, conventionally a did:key (see {@link didKeyFromEd25519}). */
  issuerDid: string;
  /** The subject (the agent) identifier — becomes `credentialSubject.id`. */
  subjectDid: string;
  /** Optional credential lifetime in seconds (sets `exp`). */
  ttlSec?: number;
}

/**
 * Emit an {@link AgentPassport} as a W3C VC 2.0, secured as an **SD-JWT VC** (EdDSA).
 *
 * The returned string is the SD-JWT serialization `<jwt>~<disclosure>~…~`: the JWT carries a `vc` claim
 * (`@context`, `type: ['VerifiableCredential','AgentPassportCredential']`, `credentialSubject`) whose
 * `credentialSubject._sd` holds salted hashes of each present passport digest, and each disclosure after
 * the `~` reveals one `[salt, name, value]`. A holder MAY drop disclosures to withhold claims; the bound
 * fields (model id, operator, hardware_rooted, passport id) remain visible.
 */
export async function passportToVC(passport: AgentPassport, args: PassportToVCArgs): Promise<string> {
  const { issuerKey, issuerDid, subjectDid, ttlSec } = args;

  const disclosures: string[] = [];
  const sd: string[] = [];
  for (const field of SD_DIGEST_FIELDS) {
    const value = passport[field];
    if (value === undefined) continue;
    const salt = b64u(randomBytes(16));
    const disclosure = b64u(Buffer.from(JSON.stringify([salt, field, value]), 'utf8'));
    disclosures.push(disclosure);
    sd.push(sha256b64u(disclosure));
  }

  const credentialSubject: Record<string, JsonValue> = {
    id: subjectDid,
    // the passport's own content-address, so a verifier can re-derive / match it (VC subject id is the DID)
    passport_id: passport.id,
    model_id: passport.model_id,
    operator: passport.operator,
    hardware_rooted: passport.hardware_rooted,
    issued_at: passport.issued_at,
  };
  if (passport.weights_measured !== undefined) credentialSubject.weights_measured = passport.weights_measured;
  if (sd.length > 0) {
    credentialSubject._sd = sd;
    credentialSubject._sd_alg = 'sha-256';
  }

  const vc: Record<string, JsonValue> = {
    '@context': [VC_CONTEXT, AGENT_PASSPORT_CONTEXT],
    type: ['VerifiableCredential', AGENT_PASSPORT_VC_TYPE],
    credentialSubject,
  };

  const now = Math.floor(Date.now() / 1000);
  const builder = new SignJWT({ vc })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'vc+sd-jwt' })
    .setIssuer(issuerDid)
    .setSubject(subjectDid)
    .setIssuedAt(now);
  if (ttlSec !== undefined) builder.setExpirationTime(now + ttlSec);
  const jwt = await builder.sign(issuerKey);

  // SD-JWT VC serialization: JWT, then each disclosure, each terminated by '~'.
  return [jwt, ...disclosures].map((p) => `${p}~`).join('');
}

export interface VerifiedPassportVC {
  passport: AgentPassport;
  issuerDid: string;
  subjectDid: string;
}

/**
 * Verify an SD-JWT VC produced by {@link passportToVC} and reconstruct the {@link AgentPassport}.
 *
 * The JWT signature is checked with `issuerVerifyKey`; each presented disclosure is hashed and MUST appear
 * in `credentialSubject._sd` (an unrecognised disclosure is rejected). Any tamper — a flipped JWT byte, a
 * forged disclosure — fails. Returns the reconstructed passport plus the issuer/subject DIDs.
 */
export async function verifyPassportVC(vc: string, issuerVerifyKey: KeyLike | Uint8Array): Promise<VerifiedPassportVC> {
  const parts = vc.split('~');
  const jwt = parts[0];
  if (jwt === undefined || jwt === '') throw new Error('pca-vc: empty SD-JWT');
  const disclosures = parts.slice(1).filter((p) => p.length > 0);

  const { payload } = await jwtVerify(jwt, issuerVerifyKey);
  const vcClaim = (payload as JWTPayload).vc;
  if (!isObject(vcClaim)) throw new Error('pca-vc: missing vc claim');
  const cs = vcClaim.credentialSubject;
  if (!isObject(cs)) throw new Error('pca-vc: missing credentialSubject');

  const sdList: string[] = Array.isArray(cs._sd) ? cs._sd.filter((x): x is string => typeof x === 'string') : [];
  const recovered: Record<string, string> = {};
  for (const disclosure of disclosures) {
    const digest = sha256b64u(disclosure);
    if (!sdList.includes(digest)) throw new Error('pca-vc: disclosure does not match any _sd digest');
    const decoded: unknown = JSON.parse(unb64u(disclosure).toString('utf8'));
    if (!Array.isArray(decoded) || decoded.length !== 3) throw new Error('pca-vc: malformed disclosure');
    const name = asString(decoded[1], 'disclosure name');
    const value = asString(decoded[2], 'disclosure value');
    recovered[name] = value;
  }

  const passport: AgentPassport = {
    id: asString(cs.passport_id, 'passport_id'),
    model_id: asString(cs.model_id, 'model_id'),
    operator: asString(cs.operator, 'operator'),
    hardware_rooted: asBoolean(cs.hardware_rooted, 'hardware_rooted'),
    issued_at: asNumber(cs.issued_at, 'issued_at'),
  };
  if (cs.weights_measured !== undefined) passport.weights_measured = asBoolean(cs.weights_measured, 'weights_measured');
  for (const field of SD_DIGEST_FIELDS) {
    const v = recovered[field];
    if (v !== undefined) passport[field] = v;
  }

  const issuerDid = asString(payload.iss, 'iss');
  const subjectDid = asString(cs.id, 'credentialSubject.id');
  return { passport, issuerDid, subjectDid };
}

// ---------------------------------------------------------------------------------------------------
// RFC 9421 HTTP Message Signatures + Web Bot Auth
// ---------------------------------------------------------------------------------------------------

export interface SignRequestArgs {
  method: string;
  /** Full request target URI (serialized into `@target-uri`). */
  url: string;
  /** Request headers to cover (keys case-insensitive). `host` is derived from `url` if absent. */
  headers: Record<string, string>;
  /** Ed25519 private key. */
  key: KeyObject;
  /** `keyid` signature parameter — the key's identifier (e.g. a did:key or a JWK thumbprint). */
  keyid: string;
  /** `created` signature parameter (unix seconds); defaults to now. */
  created?: number;
  /**
   * Web Bot Auth: the URL of the signer's key directory. When set it is emitted as the `Signature-Agent`
   * header, is added to the covered components, and tags the signature `web-bot-auth`.
   */
  signatureAgent?: string;
}

export interface SignedRequest {
  /** Value for the `Signature-Input` header (label `sig1`). */
  signatureInput: string;
  /** Value for the `Signature` header (label `sig1`, a base64 Byte Sequence). */
  signature: string;
  /** Value for the `Signature-Agent` header, when a directory URL was supplied. */
  signatureAgent?: string;
}

const SIG_LABEL = 'sig1';

/** Lower-case header keys. */
function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

/** The value of one covered component, RFC 9421 §2.1 / §2.2 (the subset we cover). */
function componentValue(name: string, method: string, url: string, headers: Record<string, string>): string {
  if (name === '@method') return method.toUpperCase();
  if (name === '@target-uri') return url;
  if (name === '@authority') return new URL(url).host;
  const v = headers[name];
  if (v === undefined) throw new Error(`pca-vc: covered header '${name}' absent from request`);
  return v.trim();
}

/** Build the RFC 9421 signature base from the ordered component list and the `@signature-params` value. */
function signatureBase(
  components: string[],
  sigParamsValue: string,
  method: string,
  url: string,
  headers: Record<string, string>,
): string {
  const lines = components.map((c) => `"${c}": ${componentValue(c, method, url, headers)}`);
  lines.push(`"@signature-params": ${sigParamsValue}`);
  return lines.join('\n');
}

/** Sign an HTTP request message per RFC 9421 (EdDSA) with the Web Bot Auth `Signature-Agent` pattern. */
export function signRequestMessage(args: SignRequestArgs): SignedRequest {
  const { method, url, key, keyid } = args;
  const created = args.created ?? Math.floor(Date.now() / 1000);
  const headers = normalizeHeaders(args.headers);
  if (headers.host === undefined) headers.host = new URL(url).host;
  if (args.signatureAgent !== undefined) headers['signature-agent'] = `"${args.signatureAgent}"`;

  const components = ['@method', '@target-uri', ...Object.keys(headers).sort()];
  const inner = `(${components.map((c) => `"${c}"`).join(' ')})`;
  let params = `;created=${created};keyid="${keyid}";alg="ed25519"`;
  if (args.signatureAgent !== undefined) params += ';tag="web-bot-auth"';
  const sigParamsValue = `${inner}${params}`;

  const base = signatureBase(components, sigParamsValue, method, url, headers);
  const sig = nodeSign(null, Buffer.from(base, 'utf8'), key);

  const result: SignedRequest = {
    signatureInput: `${SIG_LABEL}=${sigParamsValue}`,
    signature: `${SIG_LABEL}=:${sig.toString('base64')}:`,
  };
  if (args.signatureAgent !== undefined) result.signatureAgent = `"${args.signatureAgent}"`;
  return result;
}

export interface VerifyRequestArgs {
  method: string;
  url: string;
  headers: Record<string, string>;
  signatureInput: string;
  signature: string;
  /** The `Signature-Agent` header value as received (used if the covered set includes `signature-agent`). */
  signatureAgent?: string;
}

/** Extract the inner component list of `label=(...)...` form. */
function parseComponents(sigParamsValue: string): string[] {
  const open = sigParamsValue.indexOf('(');
  const close = sigParamsValue.indexOf(')');
  if (open !== 0 || close < 0) throw new Error('pca-vc: malformed @signature-params');
  const inner = sigParamsValue.slice(open + 1, close).trim();
  if (inner === '') return [];
  return inner.split(/\s+/).map((tok) => {
    const m = /^"(.*)"$/.exec(tok);
    if (!m) throw new Error('pca-vc: malformed component identifier');
    return m[1] as string;
  });
}

/** Verify an RFC 9421 signature produced by {@link signRequestMessage}. Returns false on any mismatch. */
export function verifyRequestSignature(args: VerifyRequestArgs, verifyKey: KeyObject): boolean {
  try {
    const eq = args.signatureInput.indexOf('=');
    if (eq < 0) return false;
    const sigParamsValue = args.signatureInput.slice(eq + 1);
    const components = parseComponents(sigParamsValue);

    const headers = normalizeHeaders(args.headers);
    if (headers.host === undefined) headers.host = new URL(args.url).host;
    if (components.includes('signature-agent') && headers['signature-agent'] === undefined) {
      if (args.signatureAgent === undefined) return false;
      headers['signature-agent'] = args.signatureAgent;
    }

    const base = signatureBase(components, sigParamsValue, args.method, args.url, headers);

    const sigEq = args.signature.indexOf('=');
    if (sigEq < 0) return false;
    const wrapped = args.signature.slice(sigEq + 1).trim();
    const m = /^:(.*):$/.exec(wrapped);
    if (!m) return false;
    const sigBytes = Buffer.from(m[1] as string, 'base64');

    return nodeVerify(null, Buffer.from(base, 'utf8'), verifyKey, sigBytes);
  } catch {
    return false;
  }
}
