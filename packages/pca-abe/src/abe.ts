import { canonicalBytes, type Capability } from '@atlasauth/pca';
import {
  G1_BASE,
  G2_BASE,
  R,
  type G1Point,
  type G2Point,
  type GtElement,
  bytesToScalar,
  frAdd,
  frInv,
  frMul,
  g1FromBytes,
  g1Mul,
  g1ToBytes,
  g2FromBytes,
  g2Mul,
  g2ToBytes,
  gtEql,
  gtFromBytes,
  gtPow,
  gtToBytes,
  hashAttrToG1,
  isIllFormedUtf16,
  kdf32,
  pairing,
  pairingProduct,
  randomScalar,
  scalarToBytes,
} from './bls';
import { open, seal } from './aead';
import { lagrangeAtZero, randomSecret, splitSecret, type Share } from './sss';
import { capabilityAttributes, type CapabilityAttributeOpts } from './attributes';
import { MAX_POLICY_DEPTH, MAX_POLICY_NODES, normalizePolicy, type Policy, type ThresholdTree } from './policy';
import { b64u, isObject, isPosInt, isString, unb64u } from './wire';
import { randomBytes } from '@noble/hashes/utils';

/**
 * Proof-carrying encryption: Ciphertext-Policy Attribute-Based Encryption after Bethencourt, Sahai and
 * Waters, "Ciphertext-Policy Attribute-Based Encryption" (IEEE S&P 2007, ePrint 2006/309; "BSW07"),
 * Section 4, adapted to the asymmetric (type-3) pairing e: G1 x G2 -> GT of BLS12-381, with the payload
 * sealed under AES-256-GCM. The access structure is the package's AND / OR / k-of-n tree, realised as a
 * Shamir sharing down the tree exactly as BSW's access tree.
 *
 * CONSTRUCTION (g1, g2 the generators of G1, G2; H: {0,1}* -> G1 hash-to-curve, a random oracle)
 *   setup()           alpha, beta <- Z_r*.   MSK = (alpha, beta).
 *                     MPK = ( h = beta*g2 in G2,  f = beta^-1 * g1 in G1,  Y = e(g1,g2)^alpha in GT ).
 *   keygen(S)         r <- Z_r*; for each attribute j in S, r_j <- Z_r*.
 *                     D = ((alpha + r)/beta) * g1                                  (G1)
 *                     D_j = r*g1 + r_j*H(j)   (G1),      D'_j = r_j*g2   (G2)     for j in S
 *                     The per-USER randomiser r is shared by every component of one key and is what makes
 *                     keys of different users incompatible (collusion resistance).
 *   encrypt(T, m)     s <- Z_r*; C_0 = s*h (G2). Share s down the tree T (q_root(0) = s, Shamir per gate);
 *                     for each leaf x with attribute j: C_x = q_x(0)*g2 (G2), C'_x = q_x(0)*H(j) (G1).
 *                     The blinding value is K = Y^s = e(g1,g2)^(alpha*s); CEK = HKDF(K, salt).
 *   decrypt(SK, CT)   DecryptNode at a leaf x (j in S):
 *                         F_x = e(D_j, C_x) / e(C'_x, D'_j) = e(g1,g2)^(r*q_x(0)).
 *                     At a gate, F_gate = prod_i F_i^{Delta_i(0)} over any t recovered children (Lagrange
 *                     interpolation in the exponent) = e(g1,g2)^(r*q_gate(0)). At the root
 *                         A = e(g1,g2)^(r*s),   K = e(D, C_0) / A = e(g1,g2)^((alpha+r)*s - r*s) = Y^s.
 *
 * ADAPTATION TO TYPE-3 PAIRINGS (this is the package's adaptation, not a result of the BSW paper)
 *   BSW07 is stated in a symmetric bilinear group of composite-free prime order p with a single generator g.
 *   Here every element is assigned a fixed side so that each pairing in the scheme has one G1 and one G2
 *   argument: D, D_j, C'_x, f, H(.) in G1; h, D'_j, C_x, C_0 in G2. The one extra public element f = g^(1/beta)
 *   (present in BSW07's public key for Delegate) is used here for key re-randomisation and delegation
 *   (`rerandomizeKey`). The equations above are exactly BSW07's with g replaced by g1 or g2 according to the side.
 *
 * SECURITY NOTION (honest)
 *   BSW07 proves the scheme secure against collusion and chosen-plaintext attack in the SELECTIVE model
 *   (the adversary commits to the challenge access structure before seeing the public key), in the GENERIC
 *   BILINEAR GROUP model with H a random oracle (the paper's Theorem 1 is for the symmetric setting). This
 *   package does NOT carry that proof over: the type-3 adaptation above has no proof of its own here, the
 *   generic-group argument is not a reduction to a standard assumption, and no standard-model security is
 *   claimed. No adaptive (full) security, no CCA security of the ABE layer (the AES-GCM tag over the whole
 *   header makes tampering detectable, which is integrity, not a CCA proof), no key-revocation, no
 *   attribute hiding (the policy is public in the ciphertext), and the MSK holder can decrypt everything.
 *   Not a NIZK: confidentiality is bound to POSSESSION of capability-derived keys, not to a verified proof.
 *   Research-grade, not independently audited.
 *
 *   What the construction does give, in the paper's model: two users whose attribute sets individually do
 *   not satisfy a policy cannot combine their keys (or components of them) to decrypt it, because every
 *   leaf recovery yields e(g1,g2)^(r*q) with the randomiser r of the key it was computed from, and the root
 *   needs a single consistent r.
 */

export const ABE_ALG = 'bsw07-cpabe-bls12381-type3/lsss/aes-256-gcm';
const CEK_INFO = 'atlas-pca-abe/cek/v2';
const SALT_LEN = 16;

// ---- key material -----------------------------------------------------------------------------

export interface MasterPublicKey {
  v: 1;
  curve: 'bls12-381';
  /** b64u compressed G2 point `h = beta * g2`. */
  h: string;
  /** b64u compressed G1 point `f = beta^-1 * g1` (used to re-randomise / delegate keys). */
  f: string;
  /** b64u 576-byte GT element `Y = e(g1, g2)^alpha`. */
  egga: string;
}

export interface MasterSecretKey {
  v: 1;
  curve: 'bls12-381';
  /** b64u 32-byte master scalar `alpha`. */
  alpha: string;
  /** b64u 32-byte master scalar `beta`. */
  beta: string;
}

/** Per-attribute key component: `D_j = r*g1 + r_j*H(j)` (G1) and `D'_j = r_j*g2` (G2). */
export interface AttributeKey {
  /** b64u compressed G1 point `D_j`. */
  dj: string;
  /** b64u compressed G2 point `D'_j`. */
  dpj: string;
}

export interface DecryptionKey {
  v: 1;
  curve: 'bls12-381';
  /** The capability's bound holder key, when issued from a capability (informational). */
  holder?: string;
  /** b64u compressed G1 point `D = ((alpha + r)/beta) * g1`, bound to this key's randomiser `r`. */
  d: string;
  /** attribute token -> its `(D_j, D'_j)` components. */
  attrs: Record<string, AttributeKey>;
}

// ---- ciphertext wire format -------------------------------------------------------------------

/** The access tree: gates carry the Shamir threshold; leaves carry `C_x = q_x(0)*g2` and `C'_x = q_x(0)*H(attr)`. */
export type KemTree =
  | { kind: 'leaf'; attr: string; c: string; cp: string }
  | { kind: 'gate'; t: number; of: { i: number; sub: KemTree }[] };

export interface AbeCiphertext {
  v: 1;
  alg: typeof ABE_ALG;
  /** b64u HKDF salt (16 bytes) bound into the CEK. */
  salt: string;
  /** b64u compressed G2 point `C_0 = s * h`. */
  c0: string;
  /** The access tree (also the authenticated access structure). */
  kem: KemTree;
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

// ---- setup / keygen ---------------------------------------------------------------------------

/** Generate a fresh master key pair. */
export function setup(): { mpk: MasterPublicKey; msk: MasterSecretKey } {
  const alpha = randomScalar();
  const beta = randomScalar();
  return {
    msk: { v: 1, curve: 'bls12-381', alpha: b64u(scalarToBytes(alpha)), beta: b64u(scalarToBytes(beta)) },
    mpk: {
      v: 1,
      curve: 'bls12-381',
      h: b64u(g2ToBytes(g2Mul(G2_BASE, beta))),
      f: b64u(g1ToBytes(g1Mul(G1_BASE, frInv(beta)))),
      egga: b64u(gtToBytes(gtPow(pairing(G1_BASE, G2_BASE), alpha))),
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

function mskScalars(msk: MasterSecretKey): { alpha: bigint; beta: bigint } {
  const alpha = canonicalScalar(msk?.alpha);
  const beta = canonicalScalar(msk?.beta);
  if (alpha === null || beta === null) throw new PcaEncryptionError('invalid master secret key');
  return { alpha, beta };
}

interface ParsedMpk {
  h: G2Point;
  f: G1Point;
  y: GtElement;
}

let eGen: GtElement | undefined;
/** Small bounded memo of already-validated public keys (validation costs a GT exponentiation and pairings). */
const mpkMemo = new Map<string, ParsedMpk>();
const MPK_MEMO_MAX = 16;

/** Parse and consistency-check a master public key: valid subgroup points, GT element, and e(f, h) = e(g1, g2). */
function parseMpk(mpk: MasterPublicKey): ParsedMpk {
  const memoKey = isString(mpk?.h) && isString(mpk?.f) && isString(mpk?.egga) ? `${mpk.h}|${mpk.f}|${mpk.egga}` : null;
  const hit = memoKey === null ? undefined : mpkMemo.get(memoKey);
  if (hit !== undefined) return hit;
  const hb = unb64u(mpk?.h);
  const fb = unb64u(mpk?.f);
  const yb = unb64u(mpk?.egga);
  const h = hb === null ? null : g2FromBytes(hb);
  const f = fb === null ? null : g1FromBytes(fb);
  const y = yb === null ? null : gtFromBytes(yb);
  if (h === null || f === null || y === null) throw new PcaEncryptionError('invalid master public key');
  eGen ??= pairing(G1_BASE, G2_BASE);
  if (!gtEql(pairing(f, h), eGen)) throw new PcaEncryptionError('invalid master public key');
  const parsed = { h, f, y };
  if (memoKey !== null) {
    if (mpkMemo.size >= MPK_MEMO_MAX) mpkMemo.delete(mpkMemo.keys().next().value as string);
    mpkMemo.set(memoKey, parsed);
  }
  return parsed;
}

/** Issue a decryption key for an explicit set of attribute tokens. */
export function keygenForAttributes(msk: MasterSecretKey, attrs: Iterable<string>): DecryptionKey {
  const { alpha, beta } = mskScalars(msk);
  const r = randomScalar(); // the per-user randomiser: a fresh one for EVERY issued key
  const rg = g1Mul(G1_BASE, r);
  const d = g1Mul(G1_BASE, frMul(frAdd(alpha, r), frInv(beta)));
  const entries = new Map<string, AttributeKey>();
  for (const a of attrs) {
    // Ill-formed UTF-16 can never be named by a valid policy (see normalizePolicy), so no key is issued for it.
    if (typeof a !== 'string' || a.length === 0 || isIllFormedUtf16(a) || entries.has(a)) continue;
    const rj = randomScalar();
    entries.set(a, {
      dj: b64u(g1ToBytes(rg.add(g1Mul(hashAttrToG1(a), rj)))),
      dpj: b64u(g2ToBytes(g2Mul(G2_BASE, rj))),
    });
  }
  // fromEntries defines OWN data properties, so an attribute literally named "__proto__" is issued like any other
  // (plain `out[a] = ...` would invoke the __proto__ setter and silently drop the key).
  return { v: 1, curve: 'bls12-381', d: b64u(g1ToBytes(d)), attrs: Object.fromEntries(entries) };
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

interface ParsedKey {
  d: G1Point;
  /** Lazily parses (and memoises) the components of one attribute; null when absent or malformed. */
  attr(name: string): { dj: G1Point; dpj: G2Point } | null;
  /** Names of the attributes whose components are present (not yet validated). */
  names(): string[];
}

/** Parse an untrusted key; a malformed attribute component is treated as not held. Null if `D` or the container is malformed. */
function parseKey(key: unknown): ParsedKey | null {
  if (!isObject(key) || !isObject(key.attrs)) return null;
  const db = unb64u(key.d);
  const d = db === null ? null : g1FromBytes(db);
  if (d === null) return null;
  const raw = key.attrs;
  const memo = new Map<string, { dj: G1Point; dpj: G2Point } | null>();
  return {
    d,
    names: () => Object.keys(raw),
    attr(name) {
      const cached = memo.get(name);
      if (cached !== undefined) return cached;
      let out: { dj: G1Point; dpj: G2Point } | null = null;
      const comp = Object.prototype.hasOwnProperty.call(raw, name) ? raw[name] : undefined;
      if (isObject(comp)) {
        const djb = unb64u(comp.dj);
        const dpb = unb64u(comp.dpj);
        const dj = djb === null ? null : g1FromBytes(djb);
        const dpj = dpb === null ? null : g2FromBytes(dpb);
        if (dj !== null && dpj !== null) out = { dj, dpj };
      }
      memo.set(name, out);
      return out;
    },
  };
}

/**
 * Re-randomise a key with fresh randomness (BSW07 Delegate): the result decrypts exactly what `key` decrypts
 * (restricted to `subset` when given, which must be attributes the key holds) but shares no component with it
 * and carries a new randomiser `r + r~`, so it is as incompatible with the original as with any other user's key.
 * Needs only the public key. Throws {@link PcaEncryptionError} on a malformed key / mpk or a subset attribute not held.
 */
export function rerandomizeKey(mpk: MasterPublicKey, key: DecryptionKey, subset?: Iterable<string>): DecryptionKey {
  const { f } = parseMpk(mpk);
  const pk = parseKey(key);
  if (pk === null) throw new PcaEncryptionError('invalid decryption key');
  const want = subset === undefined ? pk.names() : [...new Set(subset)];
  const rt = randomScalar();
  const rtg = g1Mul(G1_BASE, rt);
  const entries = new Map<string, AttributeKey>();
  for (const a of want) {
    const comp = pk.attr(a);
    if (comp === null) throw new PcaEncryptionError('subset names an attribute the key does not hold');
    const rtj = randomScalar();
    entries.set(a, {
      dj: b64u(g1ToBytes(comp.dj.add(rtg).add(g1Mul(hashAttrToG1(a), rtj)))),
      dpj: b64u(g2ToBytes(comp.dpj.add(g2Mul(G2_BASE, rtj)))),
    });
  }
  const out: DecryptionKey = {
    v: 1,
    curve: 'bls12-381',
    d: b64u(g1ToBytes(pk.d.add(g1Mul(f, rt)))),
    attrs: Object.fromEntries(entries),
  };
  if (typeof key.holder === 'string') out.holder = key.holder;
  return out;
}

// ---- encrypt ----------------------------------------------------------------------------------

function distribute(node: ThresholdTree, nodeSecret: bigint): KemTree {
  if (node.kind === 'leaf') {
    return {
      kind: 'leaf',
      attr: node.attr,
      c: b64u(g2ToBytes(g2Mul(G2_BASE, nodeSecret))),
      cp: b64u(g1ToBytes(g1Mul(hashAttrToG1(node.attr), nodeSecret))),
    };
  }
  const shares: Share[] = splitSecret(nodeSecret, node.t, node.of.length);
  const of: { i: number; sub: KemTree }[] = [];
  for (let idx = 0; idx < node.of.length; idx++) {
    const child = node.of[idx];
    const share = shares[idx];
    if (child === undefined || share === undefined) throw new PcaEncryptionError('internal: share/child mismatch');
    of.push({ i: Number(share.x), sub: distribute(child, share.y) });
  }
  return { kind: 'gate', t: node.t, of };
}

function aad(c: Pick<AbeCiphertext, 'v' | 'alg' | 'salt' | 'c0' | 'kem'>): Uint8Array {
  return canonicalBytes({ v: c.v, alg: c.alg, salt: c.salt, c0: c.c0, kem: c.kem });
}

/**
 * Encrypt `plaintext` so that it decrypts only for a holder whose attribute set satisfies `policy`.
 * Throws {@link PcaEncryptionError} on an invalid policy or master public key.
 */
export function encryptForPolicy(
  mpk: MasterPublicKey,
  policy: Policy,
  plaintext: Uint8Array | string,
): { ciphertext: AbeCiphertext } {
  const norm = normalizePolicy(policy);
  if (!norm.ok) throw new PcaEncryptionError(`invalid policy: ${norm.reason}`);
  const { h, y } = parseMpk(mpk);

  const salt = new Uint8Array(randomBytes(SALT_LEN));
  const { scalar: s } = randomSecret();
  const kem = distribute(norm.tree, s);
  const c0 = b64u(g2ToBytes(g2Mul(h, s)));

  const header: Pick<AbeCiphertext, 'v' | 'alg' | 'salt' | 'c0' | 'kem'> = { v: 1, alg: ABE_ALG, salt: b64u(salt), c0, kem };
  const cek = kdf32(gtToBytes(gtPow(y, s)), salt, CEK_INFO);
  const pt = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  let headerAad: Uint8Array;
  try {
    headerAad = aad(header);
  } catch {
    throw new PcaEncryptionError('policy cannot be authenticated (header outside the canonical JSON profile)');
  }
  const sealed = seal(cek, pt, headerAad);

  return {
    ciphertext: { ...header, iv: b64u(sealed.iv), ct: b64u(sealed.ct), tag: b64u(sealed.tag) },
  };
}

/** Mutable budget shared across one parse so untrusted input cannot make decrypt do unbounded work. */
interface ParseBudget {
  nodes: number;
}

function parseKemTree(x: unknown, gates: number, budget: ParseBudget): KemTree | null {
  if (++budget.nodes > MAX_POLICY_NODES || !isObject(x)) return null;
  if (x.kind === 'leaf') {
    if (!isString(x.attr) || !isString(x.c) || !isString(x.cp)) return null;
    if (unb64u(x.c) === null || unb64u(x.cp) === null) return null;
    return { kind: 'leaf', attr: x.attr, c: x.c, cp: x.cp };
  }
  if (x.kind === 'gate') {
    if (gates + 1 > MAX_POLICY_DEPTH) return null;
    if (!isPosInt(x.t) || !Array.isArray(x.of) || x.of.length === 0) return null;
    if (x.t > x.of.length || x.of.length >= MAX_POLICY_NODES) return null;
    const of: { i: number; sub: KemTree }[] = [];
    for (const branch of x.of) {
      // Canonical form: branch k (0-based) carries evaluation point k+1, exactly as encryptForPolicy emits it.
      if (!isObject(branch) || !isPosInt(branch.i) || branch.i !== of.length + 1) return null;
      const sub = parseKemTree(branch.sub, gates + 1, budget);
      if (sub === null) return null;
      of.push({ i: branch.i, sub });
    }
    return { kind: 'gate', t: x.t, of };
  }
  return null;
}

/** Validate an untrusted value as an {@link AbeCiphertext}; null (fail-closed) on any deviation. */
export function parseCiphertext(x: unknown): AbeCiphertext | null {
  if (!isObject(x) || x.v !== 1 || x.alg !== ABE_ALG) return null;
  if (!isString(x.salt) || !isString(x.c0) || !isString(x.iv) || !isString(x.ct) || !isString(x.tag)) return null;
  if (unb64u(x.salt) === null || unb64u(x.c0) === null || unb64u(x.iv) === null || unb64u(x.ct) === null || unb64u(x.tag) === null) return null;
  const kem = parseKemTree(x.kem, 0, { nodes: 0 });
  if (kem === null) return null;
  return { v: 1, alg: ABE_ALG, salt: x.salt, c0: x.c0, kem, iv: x.iv, ct: x.ct, tag: x.tag };
}

/** A satisfying sub-selection of the access tree: which leaves are used and which `t` children each gate uses. */
type Plan =
  | { kind: 'leaf'; dj: G1Point; dpj: G2Point; c: G2Point; cp: G1Point }
  | { kind: 'gate'; of: { x: bigint; sub: Plan }[] };

/** Choose, bottom-up, the first `t` satisfiable children of every gate; null when the key's attributes do not satisfy the subtree. */
function plan(node: KemTree, key: ParsedKey): Plan | null {
  if (node.kind === 'leaf') {
    const comp = key.attr(node.attr);
    if (comp === null) return null; // the key does not own this attribute: nothing to recover here.
    const cb = unb64u(node.c);
    const cpb = unb64u(node.cp);
    const c = cb === null ? null : g2FromBytes(cb);
    const cp = cpb === null ? null : g1FromBytes(cpb);
    if (c === null || cp === null) return null;
    return { kind: 'leaf', dj: comp.dj, dpj: comp.dpj, c, cp };
  }
  const of: { x: bigint; sub: Plan }[] = [];
  for (const branch of node.of) {
    const sub = plan(branch.sub, key);
    if (sub !== null) of.push({ x: BigInt(branch.i), sub });
    if (of.length >= node.t) break; // enough branches recovered; no need to look at more.
  }
  return of.length < node.t ? null : { kind: 'gate', of };
}

/**
 * BSW07 DecryptNode, evaluated in one pass. Leaf recovery is F_x = e(D_j, C_x) / e(C'_x, D'_j) = e(g1,g2)^(r*q_x(0)),
 * and a gate multiplies its chosen children's values raised to their Lagrange coefficients. Because
 * (F)^w = e(w*D_j, C_x) / e(w*C'_x, D'_j), the product of the Lagrange coefficients along the path to the root can be
 * folded into the group points, so the whole tree collapses into ONE multi-pairing:
 *     K = e(D, C_0) / A = e(D, C_0) * prod_x e(-w_x*D_j, C_x) * e(w_x*C'_x, D'_j)     (A = e(g1,g2)^(r*s)).
 * Pushes the leaf terms (G1/G2 pairs) onto `out`; false if an interpolation is degenerate.
 */
function collect(p: Plan, w: bigint, out: { g1: G1Point; g2: G2Point }[]): boolean {
  if (p.kind === 'leaf') {
    out.push({ g1: g1Mul(p.dj, w).negate(), g2: p.c }, { g1: g1Mul(p.cp, w), g2: p.dpj });
    return true;
  }
  const lambda = lagrangeAtZero(p.of.map((c) => c.x));
  if (lambda === null) return false;
  for (let i = 0; i < p.of.length; i++) {
    const child = p.of[i];
    if (child === undefined || !collect(child.sub, frMul(w, lambda[i] ?? 0n), out)) return false;
  }
  return true;
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
  const c0b = unb64u(ct.c0);
  const c0 = c0b === null ? null : g2FromBytes(c0b);
  if (salt === null || iv === null || body === null || tag === null || c0 === null) return null;

  const selection = plan(ct.kem, pk);
  if (selection === null) return null; // attribute set does not satisfy the policy.
  const pairs: { g1: G1Point; g2: G2Point }[] = [{ g1: pk.d, g2: c0 }];
  if (!collect(selection, 1n, pairs)) return null;
  let k: GtElement;
  try {
    k = pairingProduct(pairs); // = e(g1,g2)^((alpha+r)*s - r*s) = Y^s
  } catch {
    return null;
  }

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
