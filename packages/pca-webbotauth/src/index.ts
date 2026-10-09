/**
 * Web Bot Auth for Proof-Carrying Authority — RFC 9421 HTTP Message Signatures over outbound agent
 * requests, in the Cloudflare / AWS-WAF "web-bot-auth" profile, so a PCA agent passes automated-traffic
 * bot verification AND carries its per-action proof-of-authority in the SAME request.
 *
 * WHAT IT DOES
 *  - `signRequest` builds the `Signature-Input` + `Signature` header values over the RFC 9421 signature
 *    base (`@authority` / `@method` / `@path`, plus the `Signature-Agent` component and, optionally, the
 *    PCA proof header), using the agent's Ed25519 identity — the SAME `KeyPair` (raw 32-byte secret /
 *    public) that `@atlasauth/pca` uses to sign a PCActn. Signing/verification is `node:crypto` Ed25519.
 *  - `verifySignedRequest` reconstructs the base from the request, resolves the key by `keyid` (via a
 *    resolver or a JWKS directory), verifies the Ed25519 signature, and enforces `created`/`expires`
 *    freshness and the `web-bot-auth` tag. It FAILS CLOSED: any parse error, missing field, stale window,
 *    wrong tag, unknown key or bad signature returns `{ valid: false, reason }` and never throws.
 *  - `buildKeyDirectory` / `directoryHandler` serve the JWKS at
 *    `/.well-known/http-message-signatures-directory` so a verifier (Cloudflare, a resource server) can
 *    fetch the agent's Ed25519 public key.
 *  - `signRequestWithProof` / `verifySignedRequestWithProof` bind the signed request to a PCActn: the
 *    agent's PCActn is placed in the canonical `PCA-Action` header (the exact form the rest of PCA uses)
 *    and that header is a COVERED component, so one request is both bot-verified and proof-carrying, and
 *    the proof cannot be swapped without breaking the signature.
 *
 * HONESTY: a valid signature proves the holder of `keyid`'s private key signed THIS request's method /
 * authority / path (and the covered headers) inside the freshness window. It does not, by itself, prove
 * the action is authorized — that is the PCActn verifier's job (`@atlasauth/pca` / the resource server).
 * The value of the proof binding is that both checks ride in one request and are mutually tamper-evident.
 */

import {
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
  createHash,
  type KeyObject,
  type JsonWebKey,
} from 'node:crypto';

import {
  PCA_HEADER,
  pcaHeaders,
  decodePcaHeader,
  encodePCActn,
  decodePCActn,
  pcactnDigest,
  type KeyPair,
  type PCActn,
} from '@atlasauth/pca';

export { PCA_HEADER } from '@atlasauth/pca';
export type { KeyPair, PCActn } from '@atlasauth/pca';

// --------------------------------------------------------------------------------------------------
// Constants (web-bot-auth profile)
// --------------------------------------------------------------------------------------------------

/** RFC 9421 `tag` parameter identifying the Web Bot Auth profile. */
export const WEB_BOT_AUTH_TAG = 'web-bot-auth';
/** The signature algorithm label this profile pins. */
export const WEB_BOT_AUTH_ALG = 'ed25519';
/** Well-known path the key directory (JWKS) is served from. */
export const WELL_KNOWN_DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
/** Content type for the key directory response. */
export const DIRECTORY_CONTENT_TYPE = 'application/http-message-signatures-directory+json';
/** Default signature label (RFC 9421 dictionary member key). */
export const DEFAULT_SIGNATURE_LABEL = 'sig1';
/** Default signature lifetime: short, per the web-bot-auth guidance. */
export const DEFAULT_EXPIRES_SEC = 300;
/** The request header that carries the signing directory URL. */
export const SIGNATURE_AGENT_HEADER = 'Signature-Agent';

// --------------------------------------------------------------------------------------------------
// Types
// --------------------------------------------------------------------------------------------------

/** The agent's Ed25519 signing identity — identical to `@atlasauth/pca`'s `KeyPair` (raw 32-byte keys). */
export type SigningKey = KeyPair;

/** A bare Ed25519 public JWK (OKP / Ed25519). */
export interface Ed25519PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  /** base64url(no-pad) of the 32-byte public key. */
  x: string;
}

/** A directory entry: an Ed25519 public JWK with a `kid` and optional validity window / use. */
export interface DirectoryJwk extends Ed25519PublicJwk {
  kid: string;
  use?: string;
  /** Not-before (epoch seconds). */
  nbf?: number;
  /** Expiry (epoch seconds). */
  exp?: number;
}

/** The JWKS document served at {@link WELL_KNOWN_DIRECTORY_PATH}. */
export interface KeyDirectory {
  keys: DirectoryJwk[];
}

/** Input to {@link buildKeyDirectory}: a public key plus optional metadata. */
export interface DirectoryKeyInput {
  publicKey: Uint8Array;
  /** `kid` to publish; defaults to the RFC 7638 JWK thumbprint of the key. */
  keyid?: string;
  use?: string;
  nbf?: number;
  exp?: number;
}

export interface SignRequestInput {
  method: string;
  url: string;
  /** Request headers (used to source covered-header values + the `Signature-Agent` value). */
  headers?: Record<string, string | string[]>;
  /** The agent's Ed25519 signing identity (PCA `KeyPair`). */
  key: SigningKey;
  /** The `keyid` the verifier resolves to the public key (e.g. the JWK thumbprint). */
  keyid: string;
  /** Issued-at (epoch seconds). Default: now. */
  created?: number;
  /** Seconds until the signature expires. Default {@link DEFAULT_EXPIRES_SEC}. */
  expiresInSec?: number;
  /**
   * The signing directory URL. When set, a `Signature-Agent` header carrying it is emitted AND covered by
   * the signature (the web-bot-auth component). Usually your {@link WELL_KNOWN_DIRECTORY_PATH} origin.
   */
  agentDirectoryUrl?: string;
  /**
   * Use the dictionary form of the Signature-Agent header from the current Web Bot Auth draft: the header is
   * emitted as `<key>="<url>"` and covered as `"signature-agent";key="<key>"`. Requires `agentDirectoryUrl`.
   * Without it the legacy form (a bare quoted string) is emitted.
   */
  agentDirectoryKey?: string;
  /**
   * Derived components to cover, in order, replacing the default `@authority @method @path`. `@authority` must be
   * included (the Web Bot Auth profile requires it). Header components are added via `coverHeaders`.
   */
  components?: string[];
  /** Additional request-header names (any case) to cover. Each MUST be present in `headers`. */
  coverHeaders?: string[];
  /** Optional per-signature nonce. */
  nonce?: string;
  /** Signature label. Default {@link DEFAULT_SIGNATURE_LABEL}. */
  label?: string;
}

export interface SignResult {
  /** Value for the `Signature-Input` header. */
  signatureInput: string;
  /** Value for the `Signature` header. */
  signature: string;
  /** Value for the `Signature-Agent` header, when `agentDirectoryUrl` was given. */
  signatureAgent?: string;
  /** Ordered list of covered component identifiers. */
  covered: string[];
  /** The headers to attach to the outbound request. */
  headers: Record<string, string>;
}

export interface VerifyRequestInput {
  method: string;
  url: string;
  headers: Record<string, string | string[]>;
}

/** A resolver mapping a `keyid` to its Ed25519 public key (raw 32 bytes or a public JWK). */
export type KeyResolver = (
  keyid: string,
) => Uint8Array | Ed25519PublicJwk | null | undefined | Promise<Uint8Array | Ed25519PublicJwk | null | undefined>;

export interface VerifyOptions {
  /** Resolve the public key from `keyid`. Takes precedence over `jwks`. */
  resolveKey?: KeyResolver;
  /** A key directory (JWKS) to resolve `keyid` (`kid`) from. */
  jwks?: KeyDirectory;
  /** Verification clock (epoch seconds). Default: now. */
  now?: number;
  /** Tolerated clock skew (seconds) on `created`/`expires`. Default 0. */
  clockSkewSec?: number;
  /** Reject when `now - created` exceeds this (seconds). Optional (beyond `expires`). */
  maxAgeSec?: number;
  /**
   * Require an `expires` parameter (default true, as the Web Bot Auth profile does). Set false only to verify
   * signatures from a profile that has no expiry, such as the RFC 9421 appendix examples.
   */
  requireExpires?: boolean;
  /** Required `tag`. Default {@link WEB_BOT_AUTH_TAG}; pass `null` to not enforce a tag. */
  requiredTag?: string | null;
  /** Verify this specific signature label. Default: the first whose tag matches, else the first. */
  label?: string;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
  /** The verified signature's label. */
  label?: string;
  /** The resolved `keyid`. */
  keyid?: string;
  /** Covered component identifiers, in order. */
  covered?: string[];
  created?: number;
  expires?: number;
  tag?: string;
  nonce?: string;
}

export interface DirectoryHttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

// --------------------------------------------------------------------------------------------------
// Ed25519 via node:crypto (keys are the raw 32-byte PCA representation)
// --------------------------------------------------------------------------------------------------

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function privateKeyObject(key: SigningKey): KeyObject {
  const jwk: JsonWebKey = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: b64url(key.publicKey),
    d: b64url(key.secretKey),
  };
  return createPrivateKey({ key: jwk, format: 'jwk' });
}

function publicKeyObjectFromX(x: string): KeyObject {
  const jwk: JsonWebKey = { kty: 'OKP', crv: 'Ed25519', x };
  return createPublicKey({ key: jwk, format: 'jwk' });
}

function ed25519Sign(key: SigningKey, message: Uint8Array): Uint8Array {
  return new Uint8Array(nodeSign(null, Buffer.from(message), privateKeyObject(key)));
}

function ed25519VerifyX(x: string, message: Uint8Array, sig: Uint8Array): boolean {
  try {
    if (sig.length !== 64) return false;
    return nodeVerify(null, Buffer.from(message), publicKeyObjectFromX(x), Buffer.from(sig));
  } catch {
    return false;
  }
}

const textEncoder = new TextEncoder();
function utf8(s: string): Uint8Array {
  return textEncoder.encode(s);
}

/** RFC 7638 JWK thumbprint of an Ed25519 public key (base64url of SHA-256 over the canonical JWK). */
export function jwkThumbprint(publicKey: Uint8Array): string {
  // Canonical member order for OKP per RFC 8037 §2: crv, kty, x (lexicographic).
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${b64url(publicKey)}"}`;
  return createHash('sha256').update(canonical).digest('base64url');
}

// --------------------------------------------------------------------------------------------------
// Structured-field helpers (targeted to the RFC 9421 Signature-Input / Signature grammars)
// --------------------------------------------------------------------------------------------------

/** Serialize a value as an RFC 8941 sf-string (quoted, with `\` and `"` escaped). */
function sfString(s: string): string {
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** Split at a top-level separator, honoring sf-string quoting and `( )` nesting. */
function splitTopLevel(s: string, sep: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let inStr = false;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i);
    if (inStr) {
      if (c === '\\') {
        i++;
      } else if (c === '"') {
        inStr = false;
      }
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === '(') depth++;
    else if (c === ')') depth = Math.max(0, depth - 1);
    else if (c === sep && depth === 0) {
      out.push(s.slice(start, i));
      start = i + 1;
    }
  }
  out.push(s.slice(start));
  return out;
}

/** Read an sf-string starting at `s[i]` (which must be `"`). Returns the decoded value + next index. */
function readSfString(s: string, i: number): { value: string; next: number } {
  if (s.charAt(i) !== '"') throw new WebBotAuthParseError('expected a quoted string');
  let out = '';
  let j = i + 1;
  for (; j < s.length; j++) {
    const c = s.charAt(j);
    if (c === '\\') {
      const n = s.charAt(j + 1);
      if (n !== '"' && n !== '\\') throw new WebBotAuthParseError('invalid escape in string');
      out += n;
      j++;
    } else if (c === '"') {
      return { value: out, next: j + 1 };
    } else {
      out += c;
    }
  }
  throw new WebBotAuthParseError('unterminated string');
}

/** Parse a bare sf-value used as a parameter value (string / integer / decimal / boolean / token). */
function parseParamValue(raw: string): string | number | boolean {
  const s = raw.trim();
  if (s.length === 0) return true; // valueless parameter => boolean true
  if (s.charAt(0) === '"') {
    const { value, next } = readSfString(s, 0);
    if (next !== s.length) throw new WebBotAuthParseError('trailing characters after string parameter');
    return value;
  }
  if (s === '?1') return true;
  if (s === '?0') return false;
  if (/^-?\d+$/.test(s)) return Number.parseInt(s, 10);
  if (/^-?\d+\.\d+$/.test(s)) return Number.parseFloat(s);
  return s; // token
}

/** Parse a `;a=1;b="x";c` parameter string into a record. */
function parseParams(paramStr: string): Record<string, string | number | boolean> {
  const params: Record<string, string | number | boolean> = {};
  const trimmed = paramStr.trim();
  if (trimmed.length === 0) return params;
  if (trimmed.charAt(0) !== ';') throw new WebBotAuthParseError('expected parameters to start with ";"');
  for (const part of splitTopLevel(trimmed.slice(1), ';')) {
    const seg = part.trim();
    if (seg.length === 0) continue;
    const eq = indexOfTopLevel(seg, '=');
    if (eq === -1) {
      params[seg] = true;
    } else {
      const name = seg.slice(0, eq).trim();
      params[name] = parseParamValue(seg.slice(eq + 1));
    }
  }
  return params;
}

/** Index of the `)` that closes the `(` at `s[open]` (honoring sf-string quoting), or -1. */
function matchingParen(s: string, open: number): number {
  if (s.charAt(open) !== '(') return -1;
  let depth = 0;
  let inStr = false;
  for (let i = open; i < s.length; i++) {
    const c = s.charAt(i);
    if (inStr) {
      if (c === '\\') i++;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** First index of `ch` in `s` at the top level (outside strings / parens), or -1. */
function indexOfTopLevel(s: string, ch: string): number {
  let depth = 0;
  let inStr = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i);
    if (inStr) {
      if (c === '\\') i++;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === '(') depth++;
    else if (c === ')') depth = Math.max(0, depth - 1);
    else if (c === ch && depth === 0) return i;
  }
  return -1;
}

class WebBotAuthParseError extends Error {}

interface ParsedComponent {
  /** The component identifier (derived name like `@authority`, or a lowercase header name). */
  id: string;
  /** The verbatim serialized component (id + any component params). */
  raw: string;
  /** RFC 9421 section 2.1.2 `key` parameter: the dictionary member of a Structured Field header. */
  key?: string;
}

interface ParsedSigInput {
  label: string;
  components: ParsedComponent[];
  /** The verbatim `(...)` + params string — reused byte-for-byte in the signature base. */
  paramsRaw: string;
  params: Record<string, string | number | boolean>;
}

/** Parse the `Signature-Input` dictionary into one entry per label. */
function parseSignatureInput(value: string): ParsedSigInput[] {
  const entries: ParsedSigInput[] = [];
  for (const memberRaw of splitTopLevel(value, ',')) {
    const member = memberRaw.trim();
    if (member.length === 0) continue;
    const eq = indexOfTopLevel(member, '=');
    if (eq === -1) throw new WebBotAuthParseError('malformed Signature-Input member');
    const label = member.slice(0, eq).trim();
    const paramsRaw = member.slice(eq + 1).trim();
    if (paramsRaw.charAt(0) !== '(') throw new WebBotAuthParseError('Signature-Input value must be an inner list');
    const close = matchingParen(paramsRaw, 0);
    if (close === -1) throw new WebBotAuthParseError('unterminated inner list');
    const inner = paramsRaw.slice(1, close);
    const components: ParsedComponent[] = [];
    for (const chunkRaw of splitTopLevel(inner, ' ')) {
      const chunk = chunkRaw.trim();
      if (chunk.length === 0) continue;
      const { value: id, next } = readSfString(chunk, 0);
      const lowered = id.toLowerCase();
      const rest = chunk.slice(next).trim();
      if (rest.length === 0) {
        components.push({ id: lowered, raw: `"${lowered}"` });
        continue;
      }
      // The only component parameter supported is `key` (dictionary member), on header components.
      const m = /^;key=("(?:[^"\\]|\\.)*")$/.exec(rest);
      if (m === null || lowered.startsWith('@')) {
        throw new WebBotAuthParseError(`unsupported component parameters on "${id}"`);
      }
      const key = readSfString(m[1]!, 0).value;
      components.push({ id: lowered, raw: `"${lowered}";key=${sfString(key)}`, key });
    }
    const params = parseParams(paramsRaw.slice(close + 1));
    entries.push({ label, components, paramsRaw, params });
  }
  return entries;
}

/** Parse the `Signature` dictionary into a map of label -> raw signature bytes. */
function parseSignature(value: string): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const memberRaw of splitTopLevel(value, ',')) {
    const member = memberRaw.trim();
    if (member.length === 0) continue;
    const eq = indexOfTopLevel(member, '=');
    if (eq === -1) throw new WebBotAuthParseError('malformed Signature member');
    const label = member.slice(0, eq).trim();
    const v = member.slice(eq + 1).trim();
    if (v.length < 2 || v.charAt(0) !== ':' || v.charAt(v.length - 1) !== ':') {
      throw new WebBotAuthParseError('Signature value must be a byte sequence (:base64:)');
    }
    out.set(label, new Uint8Array(Buffer.from(v.slice(1, -1), 'base64')));
  }
  return out;
}

// --------------------------------------------------------------------------------------------------
// Signature base (RFC 9421 §2.5)
// --------------------------------------------------------------------------------------------------

interface RequestContext {
  method: string;
  authority: string;
  path: string;
  targetUri: string;
  scheme: string;
  query: string;
  headers: Map<string, string>;
}

function normalizeHeaders(h?: Record<string, string | string[]>): Map<string, string> {
  const m = new Map<string, string>();
  if (!h) return m;
  for (const [k, v] of Object.entries(h)) {
    const name = k.toLowerCase();
    const value = Array.isArray(v) ? v.map((x) => x.trim()).join(', ') : v.trim();
    const prev = m.get(name);
    m.set(name, prev === undefined ? value : `${prev}, ${value}`);
  }
  return m;
}

function buildContext(method: string, url: string, headers: Map<string, string>): RequestContext {
  const u = new URL(url);
  return {
    method: method.toUpperCase(),
    authority: u.host.toLowerCase(),
    path: u.pathname === '' ? '/' : u.pathname,
    targetUri: u.href,
    scheme: u.protocol.replace(/:$/, '').toLowerCase(),
    query: u.search === '' ? '?' : u.search,
    headers,
  };
}

/** Derive one component's value. Throws (fail-closed) for unsupported derived components / missing headers. */
function deriveComponentValue(component: ParsedComponent, ctx: RequestContext): string {
  const id = component.id;
  switch (id) {
    case '@method':
      return ctx.method;
    case '@authority':
      return ctx.authority;
    case '@path':
      return ctx.path;
    case '@target-uri':
      return ctx.targetUri;
    case '@scheme':
      return ctx.scheme;
    case '@query':
      return ctx.query;
    default: {
      if (id.startsWith('@')) throw new WebBotAuthParseError(`unsupported derived component "${id}"`);
      const v = ctx.headers.get(id);
      if (v === undefined) throw new WebBotAuthParseError(`covered header "${id}" is absent from the request`);
      if (component.key !== undefined) return dictionaryMember(v, component.key, id);
      return v;
    }
  }
}

/**
 * RFC 9421 section 2.1.2: the serialized value of dictionary member `key` of a Structured Field dictionary header.
 * Only string-valued members (with canonical, compact parameters) are supported; anything else fails closed.
 */
function dictionaryMember(header: string, key: string, headerName: string): string {
  for (const memberRaw of splitTopLevel(header, ',')) {
    const member = memberRaw.trim();
    const eq = indexOfTopLevel(member, '=');
    if (eq === -1 || member.slice(0, eq).trim() !== key) continue;
    const value = member.slice(eq + 1).trim();
    const { next } = readSfString(value, 0);
    // Parameters are allowed only in compact canonical form, so the verbatim text IS the serialization.
    if (!/^(;[a-z*][a-z0-9_.*-]*(=("(?:[^"\\]|\\.)*"|[A-Za-z0-9_.:/*+%-]+))?)*$/.test(value.slice(next))) {
      throw new WebBotAuthParseError(`member "${key}" of "${headerName}" is not in canonical form`);
    }
    return value;
  }
  throw new WebBotAuthParseError(`"${headerName}" has no dictionary member "${key}"`);
}

/** Assemble the signature base from the covered components + the verbatim signature-params value. */
function buildSignatureBase(components: ParsedComponent[], paramsRaw: string, ctx: RequestContext): string {
  const lines: string[] = [];
  for (const c of components) {
    lines.push(`${c.raw}: ${deriveComponentValue(c, ctx)}`);
  }
  lines.push(`"@signature-params": ${paramsRaw}`);
  return lines.join('\n');
}

// --------------------------------------------------------------------------------------------------
// signRequest
// --------------------------------------------------------------------------------------------------

export function signRequest(input: SignRequestInput): SignResult {
  const label = input.label ?? DEFAULT_SIGNATURE_LABEL;
  const created = input.created ?? Math.floor(Date.now() / 1000);
  const expires = created + (input.expiresInSec ?? DEFAULT_EXPIRES_SEC);

  // Working header set that component values are derived from (and partly emitted).
  const working = normalizeHeaders(input.headers);
  const emitted: Record<string, string> = {};

  const components: ParsedComponent[] = [];
  const derived = input.components ?? ['@authority', '@method', '@path'];
  if (!derived.includes('@authority')) throw new Error('signRequest: the web-bot-auth profile requires @authority to be covered');
  for (const id of derived) {
    const lower = id.toLowerCase();
    if (!lower.startsWith('@')) throw new Error(`signRequest: components must be derived components, got "${id}" (use coverHeaders for headers)`);
    components.push({ id: lower, raw: `"${lower}"` });
  }

  let signatureAgent: string | undefined;
  if (input.agentDirectoryUrl !== undefined) {
    const key = input.agentDirectoryKey;
    signatureAgent = key === undefined ? sfString(input.agentDirectoryUrl) : `${key}=${sfString(input.agentDirectoryUrl)}`;
    working.set('signature-agent', signatureAgent);
    emitted[SIGNATURE_AGENT_HEADER] = signatureAgent;
    components.push(
      key === undefined
        ? { id: 'signature-agent', raw: '"signature-agent"' }
        : { id: 'signature-agent', raw: `"signature-agent";key=${sfString(key)}`, key },
    );
  } else if (input.agentDirectoryKey !== undefined) {
    throw new Error('signRequest: agentDirectoryKey requires agentDirectoryUrl');
  }

  for (const name of input.coverHeaders ?? []) {
    const lower = name.toLowerCase();
    if (!working.has(lower)) {
      throw new Error(`signRequest: covered header "${name}" is not present in headers`);
    }
    if (!components.some((c) => c.id === lower)) components.push({ id: lower, raw: `"${lower}"` });
  }

  const ctx = buildContext(input.method, input.url, working);

  // Canonical signature-params value (reused verbatim in the base and emitted in Signature-Input). The parameter
  // order follows the examples in the Web Bot Auth architecture draft: created, keyid, alg, expires, nonce, tag.
  const innerList = components.map((c) => c.raw).join(' ');
  let paramsRaw =
    `(${innerList});created=${created};keyid=${sfString(input.keyid)};alg=${sfString(WEB_BOT_AUTH_ALG)};expires=${expires}`;
  if (input.nonce !== undefined) paramsRaw += `;nonce=${sfString(input.nonce)}`;
  paramsRaw += `;tag=${sfString(WEB_BOT_AUTH_TAG)}`;

  const base = buildSignatureBase(components, paramsRaw, ctx);
  const sig = ed25519Sign(input.key, utf8(base));

  const signatureInput = `${label}=${paramsRaw}`;
  const signature = `${label}=:${Buffer.from(sig).toString('base64')}:`;

  emitted['Signature-Input'] = signatureInput;
  emitted['Signature'] = signature;

  return { signatureInput, signature, signatureAgent, covered: components.map((c) => c.id), headers: emitted };
}

// --------------------------------------------------------------------------------------------------
// verifySignedRequest
// --------------------------------------------------------------------------------------------------

function xFromResolved(k: Uint8Array | Ed25519PublicJwk | null | undefined): string | null {
  if (k === null || k === undefined) return null;
  if (k instanceof Uint8Array) return k.length === 32 ? b64url(k) : null;
  if (typeof k === 'object' && typeof k.x === 'string' && k.crv === 'Ed25519' && k.kty === 'OKP') return k.x;
  return null;
}

async function resolvePublicKeyX(keyid: string, opts: VerifyOptions): Promise<string | null> {
  if (opts.resolveKey) return xFromResolved(await opts.resolveKey(keyid));
  if (opts.jwks) {
    const match = opts.jwks.keys.find((j) => j.kid === keyid);
    return match ? match.x : null;
  }
  return null;
}

export async function verifySignedRequest(req: VerifyRequestInput, opts: VerifyOptions): Promise<VerifyResult> {
  try {
    if (!opts.resolveKey && !opts.jwks) {
      return { valid: false, reason: 'verifySignedRequest: provide resolveKey or jwks' };
    }
    const headers = normalizeHeaders(req.headers);
    const sigInputHeader = headers.get('signature-input');
    const sigHeader = headers.get('signature');
    if (sigInputHeader === undefined || sigHeader === undefined) {
      return { valid: false, reason: 'missing Signature-Input or Signature header' };
    }

    const inputs = parseSignatureInput(sigInputHeader);
    const sigs = parseSignature(sigHeader);
    const requiredTag = opts.requiredTag === undefined ? WEB_BOT_AUTH_TAG : opts.requiredTag;

    let chosen: ParsedSigInput | undefined;
    if (opts.label !== undefined) chosen = inputs.find((e) => e.label === opts.label);
    else if (requiredTag !== null) chosen = inputs.find((e) => e.params.tag === requiredTag) ?? inputs[0];
    else chosen = inputs[0];
    if (chosen === undefined) return { valid: false, reason: 'no matching signature in Signature-Input' };

    const sigBytes = sigs.get(chosen.label);
    if (sigBytes === undefined) return { valid: false, reason: `no Signature entry for label "${chosen.label}"` };

    const tag = typeof chosen.params.tag === 'string' ? chosen.params.tag : undefined;
    if (requiredTag !== null && tag !== requiredTag) {
      return { valid: false, reason: `tag "${String(tag)}" does not match required "${requiredTag}"` };
    }

    // web-bot-auth requires @authority to be covered.
    if (!chosen.components.some((c) => c.id === '@authority')) {
      return { valid: false, reason: '@authority is not a covered component' };
    }

    const alg = chosen.params.alg;
    if (alg !== undefined && alg !== WEB_BOT_AUTH_ALG) {
      return { valid: false, reason: `unsupported alg "${String(alg)}"` };
    }

    // Freshness.
    const now = opts.now ?? Math.floor(Date.now() / 1000);
    const skew = opts.clockSkewSec ?? 0;
    const created = typeof chosen.params.created === 'number' ? chosen.params.created : undefined;
    const expires = typeof chosen.params.expires === 'number' ? chosen.params.expires : undefined;
    if (expires === undefined && opts.requireExpires !== false) return { valid: false, reason: 'missing expires parameter' };
    if (expires !== undefined && now > expires + skew) return { valid: false, reason: 'signature has expired' };
    if (created !== undefined && created > now + skew) {
      return { valid: false, reason: 'signature created-time is in the future' };
    }
    if (opts.maxAgeSec !== undefined && created !== undefined && now - created > opts.maxAgeSec + skew) {
      return { valid: false, reason: 'signature is older than maxAgeSec' };
    }

    const keyid = typeof chosen.params.keyid === 'string' ? chosen.params.keyid : undefined;
    if (keyid === undefined) return { valid: false, reason: 'missing keyid parameter' };
    const x = await resolvePublicKeyX(keyid, opts);
    if (x === null) return { valid: false, reason: `could not resolve key "${keyid}"` };

    const ctx = buildContext(req.method, req.url, headers);
    const base = buildSignatureBase(chosen.components, chosen.paramsRaw, ctx);
    if (!ed25519VerifyX(x, utf8(base), sigBytes)) {
      return { valid: false, reason: 'signature does not verify under the resolved key' };
    }

    const nonce = typeof chosen.params.nonce === 'string' ? chosen.params.nonce : undefined;
    return {
      valid: true,
      label: chosen.label,
      keyid,
      covered: chosen.components.map((c) => c.id),
      created,
      expires,
      tag,
      nonce,
    };
  } catch (e) {
    return { valid: false, reason: `verification failed (fail closed): ${(e as Error).message}` };
  }
}

// --------------------------------------------------------------------------------------------------
// Key directory (JWKS) + handler
// --------------------------------------------------------------------------------------------------

export function buildKeyDirectory(keys: DirectoryKeyInput[]): KeyDirectory {
  return {
    keys: keys.map((k) => {
      const entry: DirectoryJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: b64url(k.publicKey),
        kid: k.keyid ?? jwkThumbprint(k.publicKey),
      };
      if (k.use !== undefined) entry.use = k.use;
      if (k.nbf !== undefined) entry.nbf = k.nbf;
      if (k.exp !== undefined) entry.exp = k.exp;
      return entry;
    }),
  };
}

/** Resolve a public key JWK (x) from a directory by `kid`. */
export function resolveFromDirectory(directory: KeyDirectory, keyid: string): DirectoryJwk | undefined {
  return directory.keys.find((j) => j.kid === keyid);
}

/**
 * A framework-agnostic handler for the well-known directory path: returns the 200 JSON response when
 * `pathname` is {@link WELL_KNOWN_DIRECTORY_PATH}, otherwise `null` (so a caller can fall through).
 */
export function directoryHandler(
  keys: DirectoryKeyInput[],
): (pathname: string) => DirectoryHttpResponse | null {
  const directory = buildKeyDirectory(keys);
  const body = JSON.stringify(directory);
  return (pathname: string): DirectoryHttpResponse | null => {
    const path = pathname.split('?')[0] ?? pathname;
    if (path !== WELL_KNOWN_DIRECTORY_PATH) return null;
    return {
      status: 200,
      headers: { 'content-type': DIRECTORY_CONTENT_TYPE, 'cache-control': 'max-age=86400' },
      body,
    };
  };
}

// --------------------------------------------------------------------------------------------------
// PCA proof binding — one request is both bot-verified AND proof-carrying
// --------------------------------------------------------------------------------------------------

/** The covered-component (lowercase) name of the PCA proof header. */
export const PCA_PROOF_COMPONENT = PCA_HEADER.toLowerCase();

/** Build the `PCA-Action` header carrying a PCActn (base64url of the canonical wire form). */
export function proofHeaders(pcactn: PCActn): Record<string, string> {
  return pcaHeaders(encodePCActn(pcactn));
}

/** Reverse {@link proofHeaders}: the `PCA-Action` header value → the PCActn. */
export function decodeProofHeader(value: string): PCActn {
  return decodePCActn(decodePcaHeader(value));
}

export interface SignWithProofInput extends Omit<SignRequestInput, 'coverHeaders'> {
  /** The agent's per-action proof. Placed in `PCA-Action` and covered by the signature. */
  pcactn: PCActn;
  /** Extra request headers to cover (the proof header is always covered). */
  coverHeaders?: string[];
}

/**
 * Sign a request AND bind it to a PCActn: the PCActn goes in the canonical `PCA-Action` header and that
 * header is a covered component, so the single request is bot-verifiable and carries tamper-evident
 * proof-of-authority. Returns the sign result with the proof header merged into `headers`.
 */
export function signRequestWithProof(input: SignWithProofInput): SignResult & { proofHeader: Record<string, string> } {
  const proof = proofHeaders(input.pcactn);
  const headers: Record<string, string | string[]> = { ...(input.headers ?? {}), ...proof };
  const coverHeaders = [...(input.coverHeaders ?? []), PCA_PROOF_COMPONENT];
  const { pcactn: _pcactn, ...rest } = input;
  void _pcactn;
  const result = signRequest({ ...rest, headers, coverHeaders });
  return { ...result, headers: { ...result.headers, ...proof }, proofHeader: proof };
}

export interface VerifyWithProofOptions extends VerifyOptions {
  /** When set, the carried PCActn must equal this one (by canonical digest). */
  expectedPCActn?: PCActn;
}

export interface VerifyWithProofResult extends VerifyResult {
  /** The PCActn carried in the (signature-protected) `PCA-Action` header. */
  pcactn?: PCActn;
}

/**
 * Verify the HTTP Message Signature AND extract the proof: requires `PCA-Action` to be a covered
 * component (else fail closed), decodes the PCActn from it, and — when `expectedPCActn` is given —
 * checks the carried proof equals it. The returned `pcactn` is bound to the verified signature.
 */
export async function verifySignedRequestWithProof(
  req: VerifyRequestInput,
  opts: VerifyWithProofOptions,
): Promise<VerifyWithProofResult> {
  const base = await verifySignedRequest(req, opts);
  if (!base.valid) return base;
  if (!base.covered?.includes(PCA_PROOF_COMPONENT)) {
    return { valid: false, reason: `the ${PCA_HEADER} proof header is not covered by the signature` };
  }
  const headers = normalizeHeaders(req.headers);
  const headerValue = headers.get(PCA_PROOF_COMPONENT);
  if (headerValue === undefined) return { valid: false, reason: `missing ${PCA_HEADER} header` };
  let pcactn: PCActn;
  try {
    pcactn = decodeProofHeader(headerValue);
  } catch (e) {
    return { valid: false, reason: `invalid PCActn in ${PCA_HEADER}: ${(e as Error).message}` };
  }
  if (opts.expectedPCActn !== undefined && pcactnDigest(pcactn) !== pcactnDigest(opts.expectedPCActn)) {
    return { valid: false, reason: 'carried PCActn does not match the expected proof' };
  }
  return { ...base, pcactn };
}
