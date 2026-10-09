/**
 * @atlasauth/pca-sdjwt — SD-JWT serialization of a PCA `PCActn`.
 *
 * ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
 * │  A PCActn is an EPHEMERAL, signed proof-of-authority for ONE action (packages/pca `pcactn.ts`). │
 * │  This package re-expresses that proof as an IETF SD-JWT so it drops into the JWT / SD-JWT        │
 * │  verifiers the wider ecosystem already runs, with selective disclosure of the capability claims │
 * │  and optional holder key-binding. It is a BRIDGE, not a replacement: the PCActn's own canonical  │
 * │  signature (`sig`, over `thresholdMessage`) remains the source of truth; here it rides as a      │
 * │  selectively-disclosable claim alongside the rest of the proof.                                  │
 * └──────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * STANDARDS
 *  - **IETF SD-JWT** (draft-ietf-oauth-selective-disclosure-jwt → RFC 9701 family): an issuer-signed JWT
 *    whose payload carries `_sd` (an array of base64url SHA-256 digests of salted *Disclosures*) and
 *    `_sd_alg: "sha-256"`, serialized as `<Issuer-signed JWT>~<Disclosure 1>~…~<Disclosure N>~[<KB-JWT>]`.
 *    Each Disclosure is `base64url(UTF-8(JSON([salt, claim_name, claim_value])))`; its digest is
 *    `base64url(SHA-256(ASCII(<Disclosure>)))`. A holder MAY drop Disclosures to withhold claims.
 *  - **SD-JWT Key Binding**: the issuer-signed JWT carries a `cnf` confirmation claim holding the holder's
 *    public JWK; at presentation the holder appends a **KB-JWT** (`typ: "kb+jwt"`) signed by that key, whose
 *    payload binds `iat`, `aud`, optional `nonce`, and `sd_hash` = `base64url(SHA-256(ASCII(<everything up
 *    to and including the last '~' before the KB-JWT>)))`. This is holder proof-of-possession.
 *
 * ──────────────────────────────────────────────────────────────────────────────────────────────────
 *  CLAIM MAPPING  (PCActn  ↔  SD-JWT)
 * ──────────────────────────────────────────────────────────────────────────────────────────────────
 *  Standard JWT claims (always in the clear, so a plain JWT verifier reads them):
 *    iss   ← `cap_chain[0].issuer`                 (the ROOT issuer = the principal public key)
 *    sub   ← `cap_chain[last].holder`              (the acting agent — the leaf holder; the cnf key)
 *    aud   ← `aud`                                 (the resource server / Atlas instance id)
 *    iat   ← floor(`iat` / 1000)                   (PCActn `iat` is epoch MS; JWT NumericDate is seconds)
 *    exp   ← ceil(`exp` / 1000)                    (PCActn `exp` is epoch MS; JWT NumericDate is seconds)
 *    ver   ← `ver`                                 (protocol version; a stable, non-sensitive discriminator)
 *
 *  Capability claims (selectively-disclosable by default — one Disclosure + `_sd` digest each; the claim
 *  name equals the PCActn field name so a full disclosure reconstructs the proof verbatim):
 *    action, grant_ref, cap_chain, plan, attestation, provenance, freshness, counter, risk_claim,
 *    nonce?, caution?, rationale_commitment?, progress_step?, prohibition_evidence?, tool_binding?,
 *    alg?, pq_pk?, sig, pq_sig?, threshold?, zk_compliance?, bond_ref?
 *  (`disclosable` overrides this set; any capability claim NOT selected is emitted in the clear instead.)
 *
 *  cnf   → `{ jwk: <holder public JWK> }` when key-binding is requested (defaults to the leaf holder key).
 *
 * ──────────────────────────────────────────────────────────────────────────────────────────────────
 *  AP2 / WIMSE ALIGNMENT
 * ──────────────────────────────────────────────────────────────────────────────────────────────────
 *  - **WIMSE** (IETF Workload Identity in Multi-System Environments): a workload-identity token is a JWT
 *    whose SUBJECT is the acting workload, proof-of-possession–bound to a key in `cnf`. A PCA SD-JWT is
 *    exactly that shape — `sub` is the acting agent (leaf holder) and `cnf` carries its PoP key — so a PCA
 *    proof travels as a WIMSE-style WIT, with the authority chain + action attached as SD claims.
 *  - **AP2** (Agent Payments Protocol): AP2 mandates are a chain of signed credentials that only ever
 *    NARROW authority (Intent → Cart → Payment). A PCActn's `cap_chain` is the same attenuating chain, and
 *    this SD-JWT is the single-action analogue of an AP2 mandate credential — `aud`/`exp` bound, holder
 *    key-bound, selectively disclosable. See `@atlasauth/pca-ap2` for the full Intent→Cart→Payment bridge;
 *    this package is the generic single-proof SD-JWT those mandates can be carried as.
 */

import { createHash, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import {
  SignJWT,
  jwtVerify,
  importJWK,
  exportJWK,
  type JWK,
  type JWTPayload,
  type JWTHeaderParameters,
  type KeyLike,
} from 'jose';
import type { PCActn } from '@atlasauth/pca';

// ===================================================================================================
// Constants
// ===================================================================================================

/** The SD-JWT hash algorithm (`_sd_alg`) this package emits and the only one it accepts. */
export const SD_ALG = 'sha-256' as const;
/** `typ` of the issuer-signed JWT — a PCA SD-JWT media type. */
export const PCA_SD_JWT_TYP = 'pca+sd-jwt' as const;
/** `typ` of the Key-Binding JWT, per the SD-JWT spec. */
export const KB_JWT_TYP = 'kb+jwt' as const;
/** Default JWS algorithm for both the issuer JWT and the KB-JWT (PCA leaf keys are Ed25519 ⇒ EdDSA). */
export const DEFAULT_SIGNING_ALG = 'EdDSA' as const;

/**
 * The PCActn fields carried as selectively-disclosable capability claims by default (claim name == field
 * name). The standard-mapped fields (`aud`/`iat`/`exp`) and the clear discriminator (`ver`) are excluded.
 */
export const PCA_CAPABILITY_CLAIMS: readonly string[] = [
  'action',
  'grant_ref',
  'cap_chain',
  'plan',
  'attestation',
  'provenance',
  'freshness',
  'counter',
  'risk_claim',
  'nonce',
  'caution',
  'rationale_commitment',
  'progress_step',
  'prohibition_evidence',
  'tool_binding',
  'alg',
  'pq_pk',
  'sig',
  'pq_sig',
  'threshold',
  'zk_compliance',
  'bond_ref',
];

/** PCActn fields that become standard JWT claims (not eligible for a capability Disclosure). */
const STANDARD_MAPPED: ReadonlySet<string> = new Set(['aud', 'iat', 'exp']);
/** Field carried in the clear as a discriminator (not disclosable). */
const CLEAR_DISCRIMINATOR = 'ver';
/** Claims RFC 9901 §9.7 treats as security-critical: never accepted behind a Disclosure. */
const CRITICAL_CLAIMS: ReadonlySet<string> = new Set(['iss', 'aud', 'exp', 'nbf', 'cnf', 'status']);
/** Reserved top-level claim names that are never treated as recovered capability claims. */
const RESERVED_CLAIMS: ReadonlySet<string> = new Set(['iss', 'sub', 'aud', 'iat', 'exp', '_sd', '_sd_alg', 'cnf']);

// ===================================================================================================
// base64url / sha-256 helpers (Node built-ins only; no new deps)
// ===================================================================================================

function b64uBytes(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** `base64url(SHA-256(ASCII(input)))` — the SD-JWT Disclosure digest / KB `sd_hash` construction. */
function sha256b64u(asciiInput: string): string {
  return createHash('sha256').update(asciiInput, 'ascii').digest().toString('base64url');
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && !(v instanceof Uint8Array);
}

function isJwk(v: unknown): v is JWK {
  return isPlainObject(v) && typeof v.kty === 'string';
}

// ===================================================================================================
// Ed25519 raw-key ⇄ jose bridge (so the actual PCA leaf keys can issue / bind, not only jose keys)
// ===================================================================================================

// Fixed ASN.1 prefixes for a 32-byte Ed25519 key (RFC 8410): PKCS#8 private, SPKI public.
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** A `{ kty:'OKP', crv:'Ed25519', x }` JWK for a raw 32-byte Ed25519 public key. */
export function ed25519PublicJwk(raw: Uint8Array): JWK {
  if (raw.length !== 32) throw new Error('pca-sdjwt: Ed25519 public key must be 32 bytes');
  return { kty: 'OKP', crv: 'Ed25519', x: b64uBytes(raw) };
}

/** Import a raw 32-byte Ed25519 SEED (the PCA secret key) into a jose-signable `KeyLike`. */
export function importEd25519PrivateKey(rawSeed: Uint8Array): KeyLike {
  if (rawSeed.length !== 32) throw new Error('pca-sdjwt: Ed25519 private seed must be 32 bytes');
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(rawSeed)]);
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

/** Import a raw 32-byte Ed25519 public key into a jose-verifiable `KeyLike`. */
export function importEd25519PublicKey(raw: Uint8Array): KeyLike {
  if (raw.length !== 32) throw new Error('pca-sdjwt: Ed25519 public key must be 32 bytes');
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

// ===================================================================================================
// PCActn → SD-JWT (issuance)
// ===================================================================================================

/** Holder key material to embed as the `cnf` confirmation claim (enables later KB-JWT binding). */
export interface KeyBindingEmbed {
  /**
   * The holder's PUBLIC key for `cnf`: either a JWK, a raw 32-byte Ed25519 public key, or omitted. When
   * omitted the leaf holder of the capability chain (`cap_chain[last].holder`, a b64u Ed25519 key) is used,
   * binding the proof to the acting agent itself.
   */
  holderPublicKey?: JWK | Uint8Array;
}

export interface IssueOptions {
  /** The issuer's signing key (jose `KeyLike`; a Node `KeyObject` works). EdDSA keys are the default. */
  issuerKey: KeyLike | Uint8Array;
  /**
   * Capability claim names to make selectively-disclosable. Default: {@link PCA_CAPABILITY_CLAIMS}. Any
   * capability claim NOT selected here is emitted in the CLEAR instead of behind a Disclosure.
   */
  disclosable?: readonly string[];
  /** Embed a `cnf` holder key so the proof can later be KB-bound at presentation. */
  keyBinding?: KeyBindingEmbed;
  /** Override the `iss` claim (default: the capability chain's root issuer). */
  iss?: string;
  /** Override the `sub` claim (default: the capability chain's leaf holder). */
  sub?: string;
  /** Override the issuer JWT `typ` header (default {@link PCA_SD_JWT_TYP}). */
  typ?: string;
  /** JWS algorithm for the issuer JWT (default {@link DEFAULT_SIGNING_ALG}). */
  signingAlg?: string;
}

function decodeB64uToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

function leafHolderJwk(pcActn: PCActn): JWK {
  const chain = pcActn.cap_chain;
  const leaf = Array.isArray(chain) && chain.length > 0 ? chain[chain.length - 1] : undefined;
  if (!leaf || typeof leaf.holder !== 'string' || leaf.holder.length === 0) {
    throw new Error('pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing');
  }
  const raw = decodeB64uToBytes(leaf.holder);
  return ed25519PublicJwk(raw);
}

function resolveCnfJwk(pcActn: PCActn, kb: KeyBindingEmbed): JWK {
  const hp = kb.holderPublicKey;
  if (hp === undefined) return leafHolderJwk(pcActn);
  if (hp instanceof Uint8Array) return ed25519PublicJwk(hp);
  if (isJwk(hp)) return hp;
  throw new Error('pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key');
}

function toNumericDate(ms: unknown, label: string, round: (n: number) => number): number {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) throw new Error(`pca-sdjwt: PCActn.${label} must be a finite number (epoch ms)`);
  return round(ms / 1000);
}

/** One SD-JWT Disclosure for an object property, plus its `_sd` digest. */
interface Disclosure {
  readonly name: string;
  readonly encoded: string;
  readonly digest: string;
}

function makeDisclosure(name: string, value: unknown): Disclosure {
  const salt = randomBytes(16).toString('base64url');
  const encoded = Buffer.from(JSON.stringify([salt, name, value]), 'utf8').toString('base64url');
  return { name, encoded, digest: sha256b64u(encoded) };
}

/**
 * Serialize a signed `PCActn` as an IETF SD-JWT: `<Issuer-signed JWT>~<Disclosure 1>~…~<Disclosure N>~`.
 * The standard JWT claims (`iss`/`sub`/`aud`/`iat`/`exp`/`ver`) are in the clear; the capability claims are
 * selectively disclosable (one Disclosure each, digests in `_sd`). No KB-JWT is attached at issuance — the
 * holder attaches one at {@link present} time; `keyBinding` only embeds the `cnf` key that enables it.
 */
export async function issuePcaSdJwt(pcActn: PCActn, options: IssueOptions): Promise<string> {
  if (!isPlainObject(pcActn)) throw new Error('pca-sdjwt: pcActn must be an object');
  const chain = pcActn.cap_chain;
  if (!Array.isArray(chain) || chain.length === 0) throw new Error('pca-sdjwt: pcActn.cap_chain must be a non-empty array');
  const root = chain[0];
  const leaf = chain[chain.length - 1];
  if (!root || typeof root.issuer !== 'string') throw new Error('pca-sdjwt: cap_chain root issuer is missing');
  if (!leaf || typeof leaf.holder !== 'string') throw new Error('pca-sdjwt: cap_chain leaf holder is missing');
  if (typeof pcActn.aud !== 'string' || pcActn.aud.length === 0) throw new Error('pca-sdjwt: pcActn.aud is required');

  const iss = options.iss ?? root.issuer;
  const sub = options.sub ?? leaf.holder;
  const iat = toNumericDate(pcActn.iat, 'iat', Math.floor);
  let exp = toNumericDate(pcActn.exp, 'exp', Math.ceil);
  if (exp <= iat) exp = iat + 1; // keep exp strictly after iat even for sub-second lifetimes

  const disclosableSet: ReadonlySet<string> = new Set(options.disclosable ?? PCA_CAPABILITY_CLAIMS);

  const payload: JWTPayload = { iss, sub, aud: pcActn.aud, iat, exp, [CLEAR_DISCRIMINATOR]: pcActn.ver, _sd_alg: SD_ALG };
  const disclosures: Disclosure[] = [];
  const sd: string[] = [];

  const record = pcActn as unknown as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (STANDARD_MAPPED.has(key) || key === CLEAR_DISCRIMINATOR) continue; // mapped to a standard/clear claim
    const value = record[key];
    if (value === undefined) continue;
    if (disclosableSet.has(key)) {
      const d = makeDisclosure(key, value);
      disclosures.push(d);
      sd.push(d.digest);
    } else {
      payload[key] = value; // caller chose to keep this capability claim in the clear
    }
  }
  if (sd.length > 0) payload._sd = sd;

  if (options.keyBinding) payload.cnf = { jwk: resolveCnfJwk(pcActn, options.keyBinding) };

  const header: JWTHeaderParameters = { alg: options.signingAlg ?? DEFAULT_SIGNING_ALG, typ: options.typ ?? PCA_SD_JWT_TYP };
  const jwt = await new SignJWT(payload).setProtectedHeader(header).sign(options.issuerKey);

  // SD-JWT serialization: issuer JWT then each Disclosure, each terminated by '~'. No KB-JWT at issuance.
  return [jwt, ...disclosures.map((d) => d.encoded)].map((p) => `${p}~`).join('');
}

// ===================================================================================================
// Parsing
// ===================================================================================================

interface ParsedSdJwt {
  readonly jwt: string;
  readonly disclosures: readonly string[];
  /** The KB-JWT when a holder attached one, else undefined. */
  readonly kbJwt?: string;
  /** Exact bytes a KB `sd_hash` covers: `<jwt>~<D1>~…~<Dn>~` (everything up to the KB-JWT). */
  readonly presentationHead: string;
}

function parseSdJwt(sdjwt: string): ParsedSdJwt {
  if (typeof sdjwt !== 'string' || sdjwt.length === 0) throw new Error('pca-sdjwt: empty SD-JWT');
  const segments = sdjwt.split('~');
  if (segments.length < 2) throw new Error('pca-sdjwt: malformed SD-JWT (missing ~ separator)');
  const jwt = segments[0];
  if (jwt === undefined || jwt === '') throw new Error('pca-sdjwt: empty issuer JWT');
  const last = segments[segments.length - 1];
  const disclosures = segments.slice(1, segments.length - 1).filter((s) => s.length > 0);
  if (last === undefined || last === '') {
    // No KB-JWT: the string ends with '~'. The whole string is the presentation head.
    return { jwt, disclosures, presentationHead: sdjwt };
  }
  // KB-JWT present: head is everything up to and including the final '~' before it.
  const presentationHead = sdjwt.slice(0, sdjwt.length - last.length);
  return { jwt, disclosures, kbJwt: last, presentationHead };
}

function decodeDisclosureParts(encoded: string): { parts: readonly unknown[] } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    throw new Error('pca-sdjwt: disclosure is not valid base64url JSON');
  }
  if (!Array.isArray(parsed) || (parsed.length !== 2 && parsed.length !== 3)) {
    throw new Error('pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair');
  }
  if (typeof parsed[0] !== 'string') throw new Error('pca-sdjwt: disclosure salt must be a string');
  return { parts: parsed };
}

// ===================================================================================================
// Holder presentation
// ===================================================================================================

/** Every digest referenced by `_sd` arrays or `{"...": digest}` array entries anywhere inside `node`. */
function collectDigests(node: unknown): string[] {
  const out: string[] = [];
  const visit = (n: unknown): void => {
    if (Array.isArray(n)) {
      n.forEach(visit);
    } else if (isPlainObject(n)) {
      for (const [k, v] of Object.entries(n)) {
        if (k === '_sd' && Array.isArray(v)) out.push(...v.filter((x): x is string => typeof x === 'string'));
        else if (k === '...' && typeof v === 'string') out.push(v);
        else visit(v);
      }
    }
  };
  visit(node);
  return out;
}

/** Key-binding material the holder uses to sign a KB-JWT at presentation time. */
export interface PresentKeyBinding {
  /** The holder's signing key (jose `KeyLike`). Use {@link importEd25519PrivateKey} for a raw PCA seed. */
  holderKey: KeyLike | Uint8Array;
  /** The verifier this presentation is for (KB-JWT `aud`). */
  audience: string;
  /** Verifier-supplied anti-replay nonce (KB-JWT `nonce`). */
  nonce?: string;
  /** KB-JWT `iat` (unix seconds); defaults to now. */
  iat?: number;
  /** JWS algorithm for the KB-JWT (default {@link DEFAULT_SIGNING_ALG}). */
  alg?: string;
}

export interface PresentOptions {
  /** When set, append a KB-JWT proving holder possession of the `cnf` key over this exact presentation. */
  keyBinding?: PresentKeyBinding;
}

/**
 * Produce a holder presentation of an issued SD-JWT that discloses ONLY `selectClaims` (by claim name) and
 * drops every other Disclosure. Any existing KB-JWT is stripped and, when `options.keyBinding` is given, a
 * fresh KB-JWT is signed over the new presentation. Claim names that are not disclosable (they are in the
 * clear, or absent) are simply ignored.
 */
export async function present(sdjwt: string, selectClaims: readonly string[], options?: PresentOptions): Promise<string> {
  const parsed = parseSdJwt(sdjwt);
  const keep = new Set(selectClaims);
  const byDigest = new Map<string, string>();
  for (const encoded of parsed.disclosures) byDigest.set(sha256b64u(encoded), encoded);

  // Selecting a claim discloses it in full: its Disclosure plus every Disclosure nested inside its value.
  const keptDigests = new Set<string>();
  const include = (digest: string): void => {
    const encoded = byDigest.get(digest);
    if (encoded === undefined || keptDigests.has(digest)) return;
    keptDigests.add(digest);
    const { parts } = decodeDisclosureParts(encoded);
    for (const d of collectDigests(parts[parts.length - 1])) include(d);
  };
  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(parsed.jwt.split('.')[1] ?? '', 'base64url').toString('utf8'));
  } catch {
    throw new Error('pca-sdjwt: issuer JWT payload is not valid base64url JSON');
  }
  if (isPlainObject(payload)) {
    // Object-property Disclosures referenced from the top-level `_sd`, selected by claim name.
    const sd = Array.isArray(payload._sd) ? payload._sd : [];
    for (const digest of sd) {
      if (typeof digest !== 'string') continue;
      const encoded = byDigest.get(digest);
      if (encoded === undefined) continue;
      const { parts } = decodeDisclosureParts(encoded);
      if (typeof parts[1] === 'string' && parts.length === 3 && keep.has(parts[1])) include(digest);
    }
    // Clear claims that contain selectively-disclosable parts (e.g. an array with `...` entries).
    for (const key of Object.keys(payload)) {
      if (key !== '_sd' && keep.has(key)) for (const d of collectDigests(payload[key])) include(d);
    }
  }
  const kept = parsed.disclosures.filter((e) => keptDigests.has(sha256b64u(e)));
  const head = [parsed.jwt, ...kept].join('~') + '~';
  if (!options?.keyBinding) return head;

  const kb = options.keyBinding;
  const now = kb.iat ?? Math.floor(Date.now() / 1000);
  const kbPayload: JWTPayload = { iat: now, aud: kb.audience, sd_hash: sha256b64u(head) };
  if (kb.nonce !== undefined) kbPayload.nonce = kb.nonce;
  const kbHeader: JWTHeaderParameters = { alg: kb.alg ?? DEFAULT_SIGNING_ALG, typ: KB_JWT_TYP };
  const kbJwt = await new SignJWT(kbPayload).setProtectedHeader(kbHeader).sign(kb.holderKey);
  return head + kbJwt;
}

// ===================================================================================================
// Verification
// ===================================================================================================

/** Outcome of the key-binding check. */
export interface KeyBindingResult {
  /** Whether a KB-JWT was attached to the presentation. */
  presented: boolean;
  /** Whether the KB-JWT verified (signature, `sd_hash`, and any aud/nonce expectations). */
  verified: boolean;
  /** The KB-JWT `aud`, when present. */
  aud?: string;
  /** The KB-JWT `nonce`, when present. */
  nonce?: string;
}

export interface VerifyOptions {
  /** The issuer's public key (jose `KeyLike`). Use {@link importEd25519PublicKey} for a raw PCA key. */
  issuerKey: KeyLike | Uint8Array;
  /** Claim names that MUST be among the presented Disclosures (else verification fails). */
  requiredDisclosures?: readonly string[];
  /** When set, the `aud` claim MUST equal this (enforced on BOTH the issuer JWT and any KB-JWT). */
  expectedAudience?: string;
  /**
   * The holder key the KB MUST be bound to. When set, verification REQUIRES a KB-JWT and requires that the
   * issuer's `cnf` key equals this key (JWK, raw Ed25519 bytes, or a `KeyLike`).
   */
  keyBindingKey?: KeyLike | JWK | Uint8Array;
  /**
   * When set, the KB-JWT `aud` MUST equal this, independent of the issuer JWT's `aud` (RFC 9901 §7.3 step 5f).
   * Takes precedence over `expectedAudience` for the KB-JWT only.
   */
  expectedKbAudience?: string;
  /** When set, the KB-JWT `nonce` MUST equal this. */
  expectedNonce?: string;
  /** Require a KB-JWT even without `keyBindingKey` (default false). */
  requireKeyBinding?: boolean;
  /** Permitted issuer-JWT JWS algorithms (default `['EdDSA']`). */
  algorithms?: string[];
  /** Permitted KB-JWT JWS algorithms (default `['EdDSA']`). */
  kbAlgorithms?: string[];
  /** Verification clock (unix ms); defaults to the real clock. */
  now?: number;
  /** When set, the KB-JWT `iat` MUST be within this many seconds of `now` (RFC 9901 §7.3 step 5e). */
  kbMaxAgeSec?: number;
  /** Clock tolerance (seconds) passed through to jose. */
  clockToleranceSec?: number;
}

export type VerifyResult =
  | {
      ok: true;
      /** The issuer JWT payload (standard + any clear capability claims). */
      payload: JWTPayload;
      /** The Processed SD-JWT Payload (RFC 9901 §7.1): all presented disclosures resolved, `_sd`/`_sd_alg` removed. */
      processed: Record<string, unknown>;
      /** The issuer JWT protected header. */
      protectedHeader: JWTHeaderParameters;
      /** The capability claims recovered from the presented Disclosures. */
      disclosed: Record<string, unknown>;
      /** Clear capability claims ∪ disclosed capability claims (everything but the reserved std claims). */
      claims: Record<string, unknown>;
      keyBinding: KeyBindingResult;
    }
  | { ok: false; reason: string };

async function jwkThumbX(k: KeyLike | JWK | Uint8Array): Promise<string | undefined> {
  if (k instanceof Uint8Array) return b64uBytes(k);
  if (isJwk(k)) return typeof k.x === 'string' ? k.x : undefined;
  const j = await exportJWK(k);
  return typeof j.x === 'string' ? j.x : undefined;
}

/** One presented Disclosure, decoded: a 3-element object-property entry or a 2-element array entry. */
interface DecodedDisclosure {
  readonly encoded: string;
  readonly parts: readonly unknown[];
  used: boolean;
}

class SdJwtProcessingError extends Error {}

/**
 * RFC 9901 §7.1 step 3-5 payload processing: resolve `_sd` digests in objects and `{"...": digest}`
 * array elements recursively, rejecting reserved/colliding names, reused digests and unreferenced
 * Disclosures. Returns the Processed SD-JWT Payload (without `_sd` / `_sd_alg`) and the names disclosed at
 * the top level.
 */
function processDisclosures(
  payload: JWTPayload,
  byDigest: ReadonlyMap<string, DecodedDisclosure>,
): { processed: Record<string, unknown>; disclosedTop: Record<string, unknown> } {
  const seen = new Set<string>();
  const claimDigest = (d: string): DecodedDisclosure | undefined => {
    if (seen.has(d)) throw new SdJwtProcessingError('a digest appears more than once in the payload');
    seen.add(d);
    return byDigest.get(d);
  };
  const disclosedTop: Record<string, unknown> = {};

  const walk = (node: unknown, top: boolean): unknown => {
    if (Array.isArray(node)) {
      const out: unknown[] = [];
      for (const el of node) {
        const keys = isPlainObject(el) ? Object.keys(el) : [];
        if (isPlainObject(el) && keys.length === 1 && keys[0] === '...') {
          const digest = el['...'];
          if (typeof digest !== 'string') throw new SdJwtProcessingError("an array '...' entry must reference a string digest");
          const d = claimDigest(digest);
          if (d === undefined) continue; // undisclosed element or decoy: removed
          if (d.parts.length !== 2) throw new SdJwtProcessingError('an array-element disclosure must be [salt, value]');
          d.used = true;
          out.push(walk(d.parts[1], false));
        } else {
          out.push(walk(el, false));
        }
      }
      return out;
    }
    if (isPlainObject(node)) {
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(node)) {
        if (key === '_sd') continue;
        out[key] = walk(node[key], false);
      }
      const sd = node._sd;
      if (sd !== undefined) {
        if (!Array.isArray(sd) || !sd.every((x): x is string => typeof x === 'string')) {
          throw new SdJwtProcessingError('_sd must be an array of strings');
        }
        for (const digest of sd) {
          const d = claimDigest(digest);
          if (d === undefined) continue; // decoy or undisclosed claim
          if (d.parts.length !== 3) throw new SdJwtProcessingError('an object-property disclosure must be [salt, name, value]');
          const name = d.parts[1];
          if (typeof name !== 'string') throw new SdJwtProcessingError('disclosure claim name must be a string');
          if (name === '_sd' || name === '...') throw new SdJwtProcessingError(`disclosure claim name '${name}' is reserved`);
          if (Object.prototype.hasOwnProperty.call(out, name)) {
            throw new SdJwtProcessingError(`disclosure claim '${name}' collides with an existing claim`);
          }
          if (top && CRITICAL_CLAIMS.has(name)) {
            throw new SdJwtProcessingError(`'${name}' is security-critical and must not be selectively disclosable`);
          }
          d.used = true;
          const value = walk(d.parts[2], false);
          out[name] = value;
          if (top) disclosedTop[name] = value;
        }
      }
      return out;
    }
    return node;
  };

  const processed = walk(payload, true);
  if (!isPlainObject(processed)) throw new SdJwtProcessingError('payload is not an object');
  delete processed._sd_alg;
  for (const d of byDigest.values()) {
    if (!d.used) throw new SdJwtProcessingError('a presented disclosure is not referenced by any digest in the payload');
  }
  return { processed, disclosedTop };
}

/**
 * Verify a PCA SD-JWT, FAIL-CLOSED: any bad signature, unknown `_sd_alg`, unmatched/forged Disclosure,
 * audience/expiry violation, or key-binding failure returns `{ ok: false }`. On success it returns the
 * issuer payload, the recovered capability claims, and the key-binding outcome.
 *
 * Steps: (1) verify the issuer JWS (jose enforces `exp`/`nbf`, and `aud` when `expectedAudience` is set);
 * (2) require `_sd_alg === "sha-256"` when any `_sd` is present; (3) for each presented Disclosure,
 * recompute its digest and require it to appear in `_sd` (an unknown Disclosure is a tamper → fail);
 * (4) enforce `requiredDisclosures`; (5) verify the KB-JWT when present/required.
 */
export async function verifyPcaSdJwt(sdjwt: string, options: VerifyOptions): Promise<VerifyResult> {
  try {
    const parsed = parseSdJwt(sdjwt);
    const algorithms = options.algorithms ?? [DEFAULT_SIGNING_ALG];

    const verified = await jwtVerify(parsed.jwt, options.issuerKey, {
      algorithms,
      ...(options.expectedAudience !== undefined ? { audience: options.expectedAudience } : {}),
      ...(options.now !== undefined ? { currentDate: new Date(options.now) } : {}),
      ...(options.clockToleranceSec !== undefined ? { clockTolerance: options.clockToleranceSec } : {}),
    });
    const payload = verified.payload;
    const protectedHeader = verified.protectedHeader;

    // _sd / Disclosure matching (RFC 9901 §7.1), recursive over nested objects and arrays.
    // `_sd_alg` defaults to sha-256 when absent; any other value is unsupported.
    if (payload._sd_alg !== undefined && payload._sd_alg !== SD_ALG) {
      return { ok: false, reason: `unsupported _sd_alg (require "${SD_ALG}")` };
    }
    const byDigest = new Map<string, DecodedDisclosure>();
    for (const encoded of parsed.disclosures) {
      const digest = sha256b64u(encoded);
      if (byDigest.has(digest)) return { ok: false, reason: 'duplicate disclosure' };
      const { parts } = decodeDisclosureParts(encoded);
      byDigest.set(digest, { encoded, parts, used: false });
    }
    let processedPayload: Record<string, unknown>;
    let disclosed: Record<string, unknown>;
    try {
      const r = processDisclosures(payload, byDigest);
      processedPayload = r.processed;
      disclosed = r.disclosedTop;
    } catch (e) {
      if (e instanceof SdJwtProcessingError) {
        const unmatched = e.message.includes('not referenced');
        return { ok: false, reason: unmatched ? 'a presented disclosure does not match any _sd digest (tampered)' : e.message };
      }
      throw e;
    }

    for (const required of options.requiredDisclosures ?? []) {
      if (!Object.prototype.hasOwnProperty.call(disclosed, required)) {
        return { ok: false, reason: `required disclosure '${required}' was not presented` };
      }
    }

    // Key binding.
    const cnf = payload.cnf;
    const cnfJwk = isPlainObject(cnf) && isJwk(cnf.jwk) ? cnf.jwk : undefined;
    const keyBinding: KeyBindingResult = { presented: parsed.kbJwt !== undefined, verified: false };

    if (parsed.kbJwt !== undefined) {
      if (cnfJwk === undefined) return { ok: false, reason: 'KB-JWT presented but issuer JWT has no cnf key' };
      if (options.keyBindingKey !== undefined) {
        const [want, have] = await Promise.all([jwkThumbX(options.keyBindingKey), jwkThumbX(cnfJwk)]);
        if (want === undefined || have === undefined || want !== have) {
          return { ok: false, reason: 'cnf key does not match the expected keyBindingKey' };
        }
      }
      const kbAlgorithms = options.kbAlgorithms ?? [DEFAULT_SIGNING_ALG];
      const kbKey = await importJWK(cnfJwk, kbAlgorithms[0] ?? DEFAULT_SIGNING_ALG);
      let kb;
      try {
        const kbAudience = options.expectedKbAudience ?? options.expectedAudience;
        kb = await jwtVerify(parsed.kbJwt, kbKey, {
          algorithms: kbAlgorithms,
          ...(kbAudience !== undefined ? { audience: kbAudience } : {}),
          ...(options.now !== undefined ? { currentDate: new Date(options.now) } : {}),
          ...(options.clockToleranceSec !== undefined ? { clockTolerance: options.clockToleranceSec } : {}),
        });
      } catch (e) {
        return { ok: false, reason: `KB-JWT signature/claims invalid: ${(e as Error).message}` };
      }
      if (kb.protectedHeader.typ !== KB_JWT_TYP) return { ok: false, reason: `KB-JWT typ must be "${KB_JWT_TYP}"` };
      if (typeof kb.payload.iat !== 'number') return { ok: false, reason: 'KB-JWT iat is required' };
      if (options.kbMaxAgeSec !== undefined) {
        const nowSec = Math.floor((options.now ?? Date.now()) / 1000);
        if (nowSec - kb.payload.iat > options.kbMaxAgeSec) return { ok: false, reason: 'KB-JWT is older than the accepted window' };
        if (kb.payload.iat - nowSec > (options.clockToleranceSec ?? 0)) return { ok: false, reason: 'KB-JWT iat is in the future' };
      }
      if (typeof kb.payload.aud !== 'string' && !Array.isArray(kb.payload.aud)) return { ok: false, reason: 'KB-JWT aud is required' };
      if (kb.payload.sd_hash !== sha256b64u(parsed.presentationHead)) {
        return { ok: false, reason: 'KB-JWT sd_hash does not cover this presentation' };
      }
      if (options.expectedNonce !== undefined && kb.payload.nonce !== options.expectedNonce) {
        return { ok: false, reason: 'KB-JWT nonce does not match' };
      }
      keyBinding.verified = true;
      if (typeof kb.payload.aud === 'string') keyBinding.aud = kb.payload.aud;
      if (typeof kb.payload.nonce === 'string') keyBinding.nonce = kb.payload.nonce;
    } else if (options.keyBindingKey !== undefined || options.requireKeyBinding) {
      return { ok: false, reason: 'key binding required but no KB-JWT was presented' };
    }

    // Recovered capability claims = clear (non-reserved) ∪ disclosed, from the Processed SD-JWT Payload.
    const claims: Record<string, unknown> = {};
    for (const key of Object.keys(processedPayload)) {
      if (!RESERVED_CLAIMS.has(key)) claims[key] = processedPayload[key];
    }

    return { ok: true, payload, processed: processedPayload, protectedHeader, disclosed, claims, keyBinding };
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
}
