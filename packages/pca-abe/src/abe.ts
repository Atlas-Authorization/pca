import { canonicalBytes, type Capability } from '@atlasauth/pca';
import {
  R,
  type G1Point,
  type G2Point,
  type GtElement,
  bytesToScalar,
  g1FromBytes,
  g1ToBytes,
  g2FromBytes,
  g2ToBytes,
  gtFromBytes,
  gtToBytes,
  isIllFormedUtf16,
  kdf32,
  randomScalar,
  scalarToBytes,
} from './bls';
import { open, seal } from './aead';
import { capabilityAttributes, type CapabilityAttributeOpts } from './attributes';
import {
  type FameCiphertext,
  type FameKey,
  type FameMpk,
  type FameMsk,
  type G1x3,
  type G2x3,
  fameDecrypt,
  fameEncrypt,
  fameKeygen,
  fameSetup,
  firstRepeatedAttribute,
  leafCount,
} from './fame';
import { MAX_POLICY_DEPTH, MAX_POLICY_NODES, normalizePolicy, type Policy, type ThresholdTree } from './policy';
import { b64u, isObject, isPosInt, isString, unb64u } from './wire';
import { randomBytes } from '@noble/hashes/utils';

/**
 * Proof-carrying encryption: Ciphertext-Policy Attribute-Based Encryption with the FAME scheme of Agrawal and
 * Chase, "FAME: Fast Attribute-based Message Encryption" (ACM CCS 2017, ePrint 2017/807), in the asymmetric
 * (type-3) pairing e: G1 x G2 -> GT of BLS12-381, with the payload sealed under AES-256-GCM. The group arithmetic
 * and the full set of equations are in `fame.ts`.
 *
 * SECURITY NOTION (honest)
 *   FAME is proven ADAPTIVELY secure against chosen-plaintext attack, and collusion resistant, in the random-oracle
 *   model under the SXDH-family assumption the paper states, for the type-3 setting this package uses; it is a
 *   published, peer-reviewed construction, not a design of this package. What this package adds, and what is NOT
 *   covered by the paper: the translation of the AND / OR / k-of-n tree into a span program (Shamir down the tree),
 *   the choice of the hash-to-curve random oracle, the wire format, and the AES-256-GCM layer (the whole header is
 *   authenticated, so tampering is detected: integrity, not a CCA proof of the ABE layer). The scheme requires an
 *   injective row labelling, so a policy that names one attribute in two leaves is refused. There is no key
 *   revocation, no attribute hiding (the policy is public in the ciphertext), the MSK holder decrypts everything,
 *   and it is not post-quantum or constant-time (JavaScript). Hardened, awaiting an independent audit.
 */

export const ABE_ALG = 'fame-cpabe-bls12381-type3/aes-256-gcm';
const CEK_INFO = 'atlas-pca-abe/cek/v3';
const SALT_LEN = 16;

// ---- key material -----------------------------------------------------------------------------

export interface MasterPublicKey {
  v: 2;
  curve: 'bls12-381';
  /** b64u compressed G2 points `h^a1`, `h^a2`. */
  h: [string, string];
  /** b64u 576-byte GT elements `e(g,h)^(d1*a1 + d3)`, `e(g,h)^(d2*a2 + d3)`. */
  t: [string, string];
}

export interface MasterSecretKey {
  v: 2;
  curve: 'bls12-381';
  /** b64u 32-byte scalars `a1, a2`. */
  a: [string, string];
  /** b64u 32-byte scalars `b1, b2`. */
  b: [string, string];
  /** b64u compressed G1 points `g^d1, g^d2, g^d3`. */
  g: [string, string, string];
}

/** Per-attribute key component: three G1 points `K_y,0`, `K_y,1`, `K_y,2`. */
export interface AttributeKey {
  k: [string, string, string];
}

export interface DecryptionKey {
  v: 2;
  curve: 'bls12-381';
  /** The capability's bound holder key, when issued from a capability (informational). */
  holder?: string;
  /** b64u compressed G2 points `K0` (bound to this key's randomisers r1, r2). */
  k0: [string, string, string];
  /** b64u compressed G1 points `K'`. */
  kp: [string, string, string];
  /** attribute token -> its components. */
  attrs: Record<string, AttributeKey>;
}

// ---- ciphertext wire format -------------------------------------------------------------------

export interface AbeCiphertext {
  v: 2;
  alg: typeof ABE_ALG;
  /** b64u HKDF salt (16 bytes) bound into the CEK. */
  salt: string;
  /** b64u compressed G2 points `C0`. */
  ct0: [string, string, string];
  /** The access tree (also the authenticated access structure). Leaves in depth-first order own `rows`. */
  tree: ThresholdTree;
  /** One row of three b64u G1 points per leaf, in depth-first leaf order. */
  rows: [string, string, string][];
  /** b64u AES-256-GCM IV (12 bytes). */
  iv: string;
  /** b64u AES-256-GCM ciphertext. */
  ct: string;
  /** b64u AES-256-GCM tag (16 bytes). */
  tag: string;
}

export class PcaEncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PcaEncryptionError';
  }
}

const g1s = (p: G1Point): string => b64u(g1ToBytes(p));
const g2s = (p: G2Point): string => b64u(g2ToBytes(p));
const tri1 = (x: G1x3): [string, string, string] => [g1s(x[0]), g1s(x[1]), g1s(x[2])];
const tri2 = (x: G2x3): [string, string, string] => [g2s(x[0]), g2s(x[1]), g2s(x[2])];

function readG1(x: unknown): G1Point | null {
  const b = unb64u(x);
  return b === null ? null : g1FromBytes(b);
}
function readG2(x: unknown): G2Point | null {
  const b = unb64u(x);
  return b === null ? null : g2FromBytes(b);
}
function readTri<T>(x: unknown, read: (y: unknown) => T | null): [T, T, T] | null {
  if (!Array.isArray(x) || x.length !== 3) return null;
  const a = read(x[0]);
  const b = read(x[1]);
  const c = read(x[2]);
  return a === null || b === null || c === null ? null : [a, b, c];
}

// ---- setup / keygen ---------------------------------------------------------------------------

/** Generate a fresh master key pair. */
export function setup(): { mpk: MasterPublicKey; msk: MasterSecretKey } {
  const rs = randomScalar;
  const a: [bigint, bigint] = [rs(), rs()];
  const b: [bigint, bigint] = [rs(), rs()];
  const { mpk, msk } = fameSetup(a, b, [rs(), rs(), rs()]);
  return {
    msk: {
      v: 2,
      curve: 'bls12-381',
      a: [b64u(scalarToBytes(msk.a[0])), b64u(scalarToBytes(msk.a[1]))],
      b: [b64u(scalarToBytes(msk.b[0])), b64u(scalarToBytes(msk.b[1]))],
      g: [g1s(msk.g[0]), g1s(msk.g[1]), g1s(msk.g[2])],
    },
    mpk: {
      v: 2,
      curve: 'bls12-381',
      h: [g2s(mpk.h1), g2s(mpk.h2)],
      t: [b64u(gtToBytes(mpk.t1)), b64u(gtToBytes(mpk.t2))],
    },
  };
}

/** Exactly one encoding per scalar: 32 bytes, non-zero, and < r (so `x + r` cannot alias `x`). */
function canonicalScalar(enc: unknown): bigint | null {
  const bytes = unb64u(enc);
  const x = bytes === null ? null : bytesToScalar(bytes);
  if (bytes === null || x === null || x === 0n || BigInt('0x' + Buffer.from(bytes).toString('hex')) >= R) return null;
  return x;
}

function parseMsk(msk: MasterSecretKey): FameMsk {
  const a = Array.isArray(msk?.a) ? msk.a.map(canonicalScalar) : [];
  const b = Array.isArray(msk?.b) ? msk.b.map(canonicalScalar) : [];
  const g = readTri(msk?.g, readG1);
  if (msk?.v !== 2 || a.length !== 2 || b.length !== 2 || a.includes(null) || b.includes(null) || g === null) {
    throw new PcaEncryptionError('invalid master secret key');
  }
  return { a: a as [bigint, bigint], b: b as [bigint, bigint], g };
}

function parseMpk(mpk: MasterPublicKey): FameMpk {
  const h = Array.isArray(mpk?.h) && mpk.h.length === 2 ? [readG2(mpk.h[0]), readG2(mpk.h[1])] : null;
  const t = Array.isArray(mpk?.t) && mpk.t.length === 2 ? mpk.t.map((x) => (unb64u(x) === null ? null : gtFromBytes(unb64u(x) as Uint8Array))) : null;
  if (mpk?.v !== 2 || h === null || t === null || h.includes(null) || t.includes(null)) throw new PcaEncryptionError('invalid master public key');
  return { h1: h[0] as G2Point, h2: h[1] as G2Point, t1: t[0] as GtElement, t2: t[1] as GtElement };
}

/** Issue a decryption key for an explicit set of attribute tokens. */
export function keygenForAttributes(msk: MasterSecretKey, attrs: Iterable<string>): DecryptionKey {
  const m = parseMsk(msk);
  // Ill-formed UTF-16 can never be named by a valid policy (see normalizePolicy), so no key is issued for it.
  const names = [...new Set(attrs)].filter((a) => typeof a === 'string' && a.length > 0 && !isIllFormedUtf16(a));
  const key = fameKeygen(m, names, [randomScalar(), randomScalar()], names.map(() => randomScalar()), randomScalar());
  // fromEntries defines OWN data properties, so an attribute literally named "__proto__" is issued like any other.
  return {
    v: 2,
    curve: 'bls12-381',
    k0: tri2(key.k0),
    kp: tri1(key.kp),
    attrs: Object.fromEntries(names.map((n) => [n, { k: tri1(key.attrs.get(n) as G1x3) }])),
  };
}

/**
 * Issue a decryption key BOUND to a PCA capability: its attributes are exactly those the (signed)
 * capability carries — holder, and the verbs/resources/scopes of its policy envelope — optionally
 * extended with explicit extra tokens. The key can decrypt only ciphertexts whose policy is satisfied
 * by this capability's authority.
 */
export function keygenForCapability(
  msk: MasterSecretKey,
  capability: Capability,
  extraAttributes: Iterable<string> = [],
  opts: CapabilityAttributeOpts = {},
): DecryptionKey {
  const attrs = capabilityAttributes(capability, opts);
  for (const a of extraAttributes) if (typeof a === 'string' && a.length > 0) attrs.add(a);
  const key = keygenForAttributes(msk, attrs);
  if (typeof capability.holder === 'string') key.holder = capability.holder;
  return key;
}

/** Parse an untrusted key; a malformed attribute component is treated as not held. Null if `K0`, `K'` or the container is malformed. */
function parseKey(key: unknown): FameKey | null {
  if (!isObject(key) || key.v !== 2 || !isObject(key.attrs)) return null;
  const k0 = readTri(key.k0, readG2);
  const kp = readTri(key.kp, readG1);
  if (k0 === null || kp === null) return null;
  const attrs = new Map<string, G1x3>();
  for (const name of Object.keys(key.attrs)) {
    const comp = key.attrs[name];
    const k = isObject(comp) ? readTri(comp.k, readG1) : null;
    if (k !== null) attrs.set(name, k);
  }
  return { k0, kp, attrs };
}

// ---- encrypt ----------------------------------------------------------------------------------

function aad(c: Pick<AbeCiphertext, 'v' | 'alg' | 'salt' | 'ct0' | 'tree' | 'rows'>): Uint8Array {
  return canonicalBytes({ v: c.v, alg: c.alg, salt: c.salt, ct0: c.ct0, tree: c.tree, rows: c.rows });
}

/**
 * Encrypt `plaintext` so that it decrypts only for a holder whose attribute set satisfies `policy`.
 * Throws {@link PcaEncryptionError} on an invalid policy (including one that names an attribute twice) or master public key.
 */
export function encryptForPolicy(
  mpk: MasterPublicKey,
  policy: Policy,
  plaintext: Uint8Array | string,
): { ciphertext: AbeCiphertext } {
  const norm = normalizePolicy(policy);
  if (!norm.ok) throw new PcaEncryptionError(`invalid policy: ${norm.reason}`);
  const dup = firstRepeatedAttribute(norm.tree);
  if (dup !== null) throw new PcaEncryptionError(`invalid policy: attribute ${JSON.stringify(dup)} is named by more than one leaf (single-use attributes only)`);
  const pk = parseMpk(mpk);

  const salt = new Uint8Array(randomBytes(SALT_LEN));
  const { ct, k } = fameEncrypt(pk, norm.tree, [randomScalar(), randomScalar()]);
  const header: Pick<AbeCiphertext, 'v' | 'alg' | 'salt' | 'ct0' | 'tree' | 'rows'> = {
    v: 2,
    alg: ABE_ALG,
    salt: b64u(salt),
    ct0: tri2(ct.ct0),
    tree: norm.tree,
    rows: ct.rows.map(tri1),
  };
  const cek = kdf32(gtToBytes(k), salt, CEK_INFO);
  const pt = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  let headerAad: Uint8Array;
  try {
    headerAad = aad(header);
  } catch {
    throw new PcaEncryptionError('policy cannot be authenticated (header outside the canonical JSON profile)');
  }
  const sealed = seal(cek, pt, headerAad);
  return { ciphertext: { ...header, iv: b64u(sealed.iv), ct: b64u(sealed.ct), tag: b64u(sealed.tag) } };
}

/** Mutable budget shared across one parse so untrusted input cannot make decrypt do unbounded work. */
interface ParseBudget {
  nodes: number;
}

function parseTree(x: unknown, gates: number, budget: ParseBudget): ThresholdTree | null {
  if (++budget.nodes > MAX_POLICY_NODES || !isObject(x)) return null;
  if (x.kind === 'leaf') {
    if (!isString(x.attr) || x.attr.length === 0 || isIllFormedUtf16(x.attr) || Object.keys(x).length !== 2) return null;
    return { kind: 'leaf', attr: x.attr };
  }
  if (x.kind === 'gate') {
    if (gates + 1 > MAX_POLICY_DEPTH || Object.keys(x).length !== 3) return null;
    if (!isPosInt(x.t) || !Array.isArray(x.of) || x.of.length === 0 || x.t > x.of.length || x.of.length >= MAX_POLICY_NODES) return null;
    const of: ThresholdTree[] = [];
    for (const branch of x.of) {
      const sub = parseTree(branch, gates + 1, budget);
      if (sub === null) return null;
      of.push(sub);
    }
    return { kind: 'gate', t: x.t, of };
  }
  return null;
}

function strTri(x: unknown): [string, string, string] | null {
  if (!Array.isArray(x) || x.length !== 3 || !x.every((e) => isString(e) && unb64u(e) !== null)) return null;
  return [x[0] as string, x[1] as string, x[2] as string];
}

/** Validate an untrusted value as an {@link AbeCiphertext}; null (fail-closed) on any deviation. */
export function parseCiphertext(x: unknown): AbeCiphertext | null {
  if (!isObject(x) || x.v !== 2 || x.alg !== ABE_ALG) return null;
  if (!isString(x.salt) || !isString(x.iv) || !isString(x.ct) || !isString(x.tag)) return null;
  if (unb64u(x.salt) === null || unb64u(x.iv) === null || unb64u(x.ct) === null || unb64u(x.tag) === null) return null;
  const ct0 = strTri(x.ct0);
  const tree = parseTree(x.tree, 0, { nodes: 0 });
  if (ct0 === null || tree === null || !Array.isArray(x.rows)) return null;
  if (x.rows.length !== leafCount(tree) || firstRepeatedAttribute(tree) !== null) return null;
  const rows: [string, string, string][] = [];
  for (const r of x.rows) {
    const t = strTri(r);
    if (t === null) return null;
    rows.push(t);
  }
  return { v: 2, alg: ABE_ALG, salt: x.salt, ct0, tree, rows, iv: x.iv, ct: x.ct, tag: x.tag };
}

/**
 * Decrypt. Returns the plaintext iff the key's attribute set satisfies the ciphertext's policy AND the
 * AEAD authenticates; otherwise returns null (never throws). Components of keys issued to different users
 * carry different randomisers and cannot be combined.
 */
export function decrypt(key: DecryptionKey, ciphertext: unknown): Uint8Array | null {
  const ct = parseCiphertext(ciphertext);
  if (ct === null) return null;
  const pk = parseKey(key);
  if (pk === null) return null;

  const salt = unb64u(ct.salt);
  const iv = unb64u(ct.iv);
  const body = unb64u(ct.ct);
  const tag = unb64u(ct.tag);
  const ct0 = readTri(ct.ct0, readG2);
  const rows: G1x3[] = [];
  for (const r of ct.rows) {
    const t = readTri(r, readG1);
    if (t === null) return null;
    rows.push(t);
  }
  if (salt === null || iv === null || body === null || tag === null || ct0 === null) return null;
  const fc: FameCiphertext = { ct0, rows };
  const k = fameDecrypt(pk, ct.tree, fc); // null: the attribute set does not satisfy the policy
  if (k === null) return null;

  const cek = kdf32(gtToBytes(k), salt, CEK_INFO);
  // The AEAD is the final integrity gate: a wrong K (mixed-randomiser pool / cross-master key / tamper) or a
  // tampered payload/header yields a null here.
  let headerAad: Uint8Array;
  try {
    headerAad = aad(ct);
  } catch {
    return null; // header outside the canonical profile: cannot be authentic
  }
  return open(cek, { iv, ct: body, tag }, headerAad);
}

/** Like {@link decrypt} but returns the plaintext decoded as UTF-8 text, or null. */
export function decryptText(key: DecryptionKey, ciphertext: unknown): string | null {
  const pt = decrypt(key, ciphertext);
  return pt === null ? null : new TextDecoder().decode(pt);
}
