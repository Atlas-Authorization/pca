import { canonicalBytes, hashCanonical, unb64u, utf8 } from './hash';
import {
  type MlDsaKeyPair,
  type SigAlg,
  type SigSuite,
  type SlhDsaKeyPair,
  bindSuiteFields,
  encodeMlDsa87PublicKey,
  encodeMlDsaPublicKey,
  encodeSlhDsa256sPublicKey,
  encodeSlhDsaPublicKey,
  resolveSigAlg,
  signWithSuite,
  verifyWithSuite,
} from './pq';

/**
 * Attenuable capability chain (spec §5.2).
 *
 * M0 enforces STRUCTURAL attenuation only: caveats are append-only (a child's caveat array must
 * start with the parent's full array), every hop is signed by the correct key, and parents are
 * hash-linked. SEMANTIC caveat evaluation — "does this action satisfy these caveats?" — is the
 * Policy VM (M1); see `CaveatEvaluator` below for the extension point. Because caveats can only
 * be appended and every caveat is a conjunctive constraint, a child can never be wider than its
 * parent: widening is impossible by construction.
 */

export interface Caveat {
  type: string;
  [k: string]: unknown;
}

export interface Capability {
  /** Hash of the signed body (content address). */
  id: string;
  /** Public key (b64u) that signed this hop. Root: the principal; child: the parent's holder. */
  issuer: string;
  /** Public key (b64u) this capability is bound to (cnf). */
  holder: string;
  caveats: Caveat[];
  /** capHash() of the parent capability; absent on the root. */
  parent?: string;
  body_digest: string;
  sig: string;
  /**
   * Signature suite (crypto-agility). Absent == `ed25519` (byte-identical to pre-agility: no suite
   * fields appear and the signed body is unchanged). For ANY non-ed25519 suite (the lattice ml-dsa-65 /
   * ml-dsa-87 and the hash-based slh-dsa-sha2-128f / slh-dsa-sha2-256s families, plain or hybrid, plus the
   * nested SUF-CMA hybrid) the suite + the issuer's PQ public key `pq_pk` are SIGNED INTO the body (so a
   * downgrade or key-swap breaks the signature), and `sig`/`pq_sig` carry the component signatures per the suite.
   */
  alg?: SigAlg;
  /** b64u PQ public key of the hop ISSUER (ML-DSA or SLH-DSA, per `alg`) — body-bound for every non-ed25519 suite. */
  pq_pk?: string;
  /** b64u PQ hop signature (ML-DSA or SLH-DSA, per `alg`) — present for the hybrid suites only (alongside the Ed25519 `sig`). */
  pq_sig?: string;
}

/**
 * Optional per-hop signature suite material (default: ed25519, byte-identical to pre-agility). A hop can
 * now be signed under ANY registered suite — supply the key pair for the family `alg` selects; the issuer's
 * PQ public key becomes the body-bound `pq_pk`.
 */
export interface CapSuiteOpts {
  alg?: SigAlg;
  /** The issuer's ML-DSA-65 key pair — ml-dsa-65 / its hybrids / the nested hybrid. */
  mlDsa?: MlDsaKeyPair;
  /** The issuer's SLH-DSA-SHA2-128f key pair — slh-dsa-sha2-128f / its hybrid. */
  slhDsa?: SlhDsaKeyPair;
  /** The issuer's ML-DSA-87 key pair — ml-dsa-87 / its hybrid (Category-5 / CNSA 2.0). */
  mlDsa87?: MlDsaKeyPair;
  /** The issuer's SLH-DSA-SHA2-256s key pair — slh-dsa-sha2-256s / its hybrid (Category-5). */
  slhDsa256s?: SlhDsaKeyPair;
}

export type CapabilityChain = Capability[];

/** M1 extension point: semantic evaluation of a caveat against an action/context. */
export type CaveatEvaluator = (caveat: Caveat, ctx: unknown) => boolean;

const CAP_DOMAIN = 'atlas-pca/cap/v1\0';

// ---- per-child budget subtree: carried allocation caveat (UCAN/Biscuit-style lineage) -------------
//
// A hop MAY carry a `budget_alloc` caveat declaring B_sub, the trust-budget allocation for its whole
// delegation subtree. It is APPEND-ONLY and MONOTONE: because caveats can only be appended down the
// chain, and verifyChain rejects any `budget_alloc` whose limit exceeds the nearest ancestor
// allocation, a child can only ever allocate <= what its parent carried. This AUTHENTICATES the budget
// tree offline (it rides inside the signed capability body); the STATEFUL consumption metering that
// actually debits each node lives server-side (see @atlas/db `pca_budget_nodes` + the adjudicator).
// A chain that carries NO `budget_alloc` caveat is unaffected: it is metered by the single grant pool,
// exactly as before (backward-compatible single-pool path).

export const BUDGET_ALLOC_CAVEAT = 'budget_alloc';

export interface BudgetAllocCaveat extends Caveat {
  type: typeof BUDGET_ALLOC_CAVEAT;
  /** B_sub: the trust-budget allocation for this delegation subtree. Finite and >= 0. */
  limit: number;
}

/** Build a signed carried-allocation caveat `{ type: 'budget_alloc', limit }` for a delegation hop. */
export function budgetAllocCaveat(limit: number): BudgetAllocCaveat {
  return { type: BUDGET_ALLOC_CAVEAT, limit };
}

export function isBudgetAllocCaveat(cv: unknown): cv is BudgetAllocCaveat {
  return (
    cv !== null &&
    typeof cv === 'object' &&
    (cv as Caveat).type === BUDGET_ALLOC_CAVEAT &&
    typeof (cv as { limit?: unknown }).limit === 'number' &&
    Number.isFinite((cv as BudgetAllocCaveat).limit) &&
    (cv as BudgetAllocCaveat).limit >= 0
  );
}

/**
 * Verify the carried allocations in a (flattened, append-only) caveat list are well-formed and MONOTONE
 * non-increasing in delegation order: every `budget_alloc.limit` is finite and >= 0, and never greater
 * than the previous one. A widening (a child allocating more than its parent carried) is rejected. A
 * list with zero `budget_alloc` caveats trivially passes (the single-pool path).
 */
export function allocationsMonotone(caveats: Caveat[]): ChainResult {
  if (!Array.isArray(caveats)) return { ok: false, reason: 'malformed caveats' };
  let prev = Infinity;
  for (let i = 0; i < caveats.length; i++) {
    const cv = caveats[i];
    if (cv === null || typeof cv !== 'object' || (cv as Caveat).type !== BUDGET_ALLOC_CAVEAT) continue;
    const lim = (cv as { limit?: unknown }).limit;
    if (typeof lim !== 'number' || !Number.isFinite(lim) || lim < 0) {
      return { ok: false, reason: `budget_alloc caveat ${i}: limit must be a finite number >= 0` };
    }
    if (lim > prev) {
      return {
        ok: false,
        reason: `budget_alloc caveat ${i}: allocation ${lim} widens the parent's carried allocation ${prev} (monotone: a child can only allocate <= its parent)`,
      };
    }
    prev = lim;
  }
  return { ok: true };
}

export interface BudgetAllocNode {
  /** Stable content-addressed key for this allocation node's stateful meter row. */
  nodePath: string;
  /** The capability id of the hop that carries this allocation. */
  capId: string;
  /** That hop's bound holder (the sub-agent key). */
  holder: string;
  /** Hop index down the chain (0 = the root grant). */
  depth: number;
  /** Index of the caveat in the leaf's flattened caveat array. */
  caveatIndex: number;
  /** The carried allocation B_sub (monotone non-increasing down the path; authenticated by the signed caveat). */
  limit: number;
}

const BUDGET_NODE_DOMAIN = 'atlas-pca/budget-node/v1';

/**
 * The per-node budget subtree carried by a chain: one node per `budget_alloc` caveat, in delegation
 * order (root -> leaf). Each node's `nodePath` is a stable key for its server-side consumption meter and
 * `limit` is its carried allocation. The acting leaf's spend is debited against EVERY node on this path
 * (the leaf's own allocation and every ancestor's), so a swarm under any node can never collectively
 * exceed that node's allocation. Empty for a chain with no allocations (the single-pool path). Run
 * `verifyChain` first — this does not re-verify signatures, only reads the (append-only) caveat lineage.
 */
export function budgetAllocNodes(chain: CapabilityChain): BudgetAllocNode[] {
  const out: BudgetAllocNode[] = [];
  if (!Array.isArray(chain) || chain.length === 0) return out;
  const leaf = chain[chain.length - 1]!;
  if (!Array.isArray(leaf.caveats)) return out;
  // Caveats are append-only, so leaf.caveats is the full cumulative list and each hop's caveat count is
  // non-decreasing. Advance `hop` to the first hop that introduced caveat index `ci`.
  let hop = 0;
  for (let ci = 0; ci < leaf.caveats.length; ci++) {
    while (hop < chain.length - 1 && (chain[hop]!.caveats?.length ?? 0) <= ci) hop++;
    const cv = leaf.caveats[ci];
    if (cv === null || typeof cv !== 'object' || (cv as Caveat).type !== BUDGET_ALLOC_CAVEAT) continue;
    const lim = (cv as { limit?: unknown }).limit;
    if (typeof lim !== 'number' || !Number.isFinite(lim) || lim < 0) continue;
    const introducing = chain[hop]!;
    out.push({
      nodePath: hashCanonical({ d: BUDGET_NODE_DOMAIN, cap: introducing.id, i: ci }),
      capId: introducing.id,
      holder: introducing.holder,
      depth: hop,
      caveatIndex: ci,
      limit: lim,
    });
  }
  return out;
}

function bodyOf(c: Pick<Capability, 'issuer' | 'holder' | 'caveats' | 'parent'>) {
  return {
    issuer: c.issuer,
    holder: c.holder,
    caveats: c.caveats,
    parent: c.parent ?? null,
  };
}

function sigMessage(bodyDigest: string): Uint8Array {
  const d = unb64u(bodyDigest);
  const p = utf8(CAP_DOMAIN);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}

/** Hash of a full capability (including signature); used as the child's `parent` link. */
export function capHash(c: Capability): string {
  return hashCanonical(c);
}

/** The canonical hop body that is hashed into `body_digest` — the suite fields (`alg`, `pq_pk`) are
 *  bound in for a non-default suite, and omitted (byte-identical) for ed25519. */
function signableBody(
  body: Pick<Capability, 'issuer' | 'holder' | 'caveats' | 'parent'>,
  alg: SigAlg | undefined,
  pqPk: string | undefined,
) {
  return bindSuiteFields(bodyOf(body), alg, pqPk);
}

/**
 * The b64u PQ public key a non-ed25519 hop suite binds into `pq_pk`, from whichever family `alg` selects.
 * THROWS (naming the missing family) when the matching key pair is absent, so a hop is never sealed without
 * the key material its suite requires. Returns `undefined` for ed25519 (no `pq_pk`).
 */
function capPqPublicKey(resolved: SigSuite, suite: CapSuiteOpts | undefined): string | undefined {
  if (!resolved.needsPqPk) return undefined;
  if (resolved.hasMlDsa) {
    if (!(suite?.mlDsa && suite.mlDsa.secretKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires an mlDsa key pair`);
    return encodeMlDsaPublicKey(suite.mlDsa.publicKey);
  }
  if (resolved.hasSlhDsa) {
    if (!(suite?.slhDsa && suite.slhDsa.secretKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires an slhDsa key pair`);
    return encodeSlhDsaPublicKey(suite.slhDsa.publicKey);
  }
  if (resolved.hasMlDsa87) {
    if (!(suite?.mlDsa87 && suite.mlDsa87.secretKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires an mlDsa87 key pair`);
    return encodeMlDsa87PublicKey(suite.mlDsa87.publicKey);
  }
  if (resolved.hasSlhDsa256s) {
    if (!(suite?.slhDsa256s && suite.slhDsa256s.secretKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires an slhDsa256s key pair`);
    return encodeSlhDsa256sPublicKey(suite.slhDsa256s.publicKey);
  }
  return undefined; // unreachable: a needsPqPk suite always sets exactly one family flag.
}

function seal(
  body: { issuer: string; holder: string; caveats: Caveat[]; parent?: string },
  signerSecret: Uint8Array,
  suite?: CapSuiteOpts,
): Capability {
  const resolved = resolveSigAlg(suite?.alg);
  if (resolved === null) throw new RangeError(`capability: unknown signature alg '${String(suite?.alg)}'`);
  const pqPk = capPqPublicKey(resolved, suite);
  const body_digest = hashCanonical(signableBody(body, suite?.alg, pqPk));
  const parts = signWithSuite(
    suite?.alg,
    { edSecret: signerSecret, mlDsa: suite?.mlDsa, slhDsa: suite?.slhDsa, mlDsa87: suite?.mlDsa87, slhDsa256s: suite?.slhDsa256s },
    sigMessage(body_digest),
  );
  const cap: Capability = {
    id: body_digest,
    issuer: body.issuer,
    holder: body.holder,
    caveats: body.caveats,
    body_digest,
    sig: parts.sig,
  };
  if (body.parent !== undefined) cap.parent = body.parent;
  if (resolved.alg !== 'ed25519') {
    cap.alg = resolved.alg;
    if (pqPk !== undefined) cap.pq_pk = pqPk;
    if (parts.pq_sig !== undefined) cap.pq_sig = parts.pq_sig;
  }
  return cap;
}

function cloneCaveats(cs: Caveat[]): Caveat[] {
  return JSON.parse(new TextDecoder().decode(canonicalBytes(cs))) as Caveat[];
}

export function mintRoot(args: {
  principalSecret: Uint8Array;
  /** b64u */
  principalPublic: string;
  /** b64u holder key */
  holder: string;
  caveats: Caveat[];
  /**
   * Signature suite for the ROOT hop. The root is signed by the PRINCIPAL — the LONGEST-LIVED key in
   * the whole system — so this is the highest-priority surface to make post-quantum (hybrid). Default
   * ed25519 (byte-identical to pre-agility). For ml-dsa-65/hybrid, `suite.mlDsa` is the principal's
   * ML-DSA-65 key pair and `principalPublic` remains the Ed25519 identity the chain is rooted at.
   */
  suite?: CapSuiteOpts;
}): Capability {
  return seal(
    { issuer: args.principalPublic, holder: args.holder, caveats: cloneCaveats(args.caveats) },
    args.principalSecret,
    args.suite,
  );
}

/** Child with the same holder; caveats = parent.caveats ++ added. Signed by the parent's holder. */
export function attenuate(parent: Capability, addedCaveats: Caveat[], signerSecret: Uint8Array, suite?: CapSuiteOpts): Capability {
  return delegate(parent, parent.holder, addedCaveats, signerSecret, suite);
}

/** Like attenuate, but rebinds `holder` to a new key (sub-agent). */
export function delegate(
  parent: Capability,
  toHolder: string,
  addedCaveats: Caveat[],
  signerSecret: Uint8Array,
  suite?: CapSuiteOpts,
): Capability {
  return seal(
    {
      issuer: parent.holder,
      holder: toHolder,
      caveats: [...cloneCaveats(parent.caveats), ...cloneCaveats(addedCaveats)],
      parent: capHash(parent),
    },
    signerSecret,
    suite,
  );
}

export interface ChainResult {
  ok: boolean;
  reason?: string;
}

function checkSig(c: Capability, signer: string, label: string): string | undefined {
  // Unknown suite => fail-closed (before any hashing).
  if (resolveSigAlg(c.alg) === null) return `${label}: unknown signature alg '${String(c.alg)}'`;
  let digest: string;
  try {
    // The signed body binds the suite (alg + issuer ML-DSA key) exactly as `seal` did; absent == ed25519.
    digest = hashCanonical(signableBody(c, c.alg, c.pq_pk));
  } catch {
    return `${label}: malformed body`;
  }
  if (digest !== c.body_digest || c.id !== c.body_digest) return `${label}: body digest mismatch`;
  // The signer is the EXPECTED Ed25519 key (root issuer / parent holder); `pq_pk` is the issuer's PQ key
  // (ML-DSA or SLH-DSA, per `alg`), body-bound so a hybrid hop's Ed25519 signature commits to it. A hop
  // carries ONE suite, so the single `pq_pk` feeds every PQ slot and `verifyWithSuite` reads only the one
  // its `alg` selects. verifyWithSuite requires BOTH for hybrid and is byte-identical to
  // verifyB64u(signer, …, sig) for ed25519.
  if (
    !verifyWithSuite(
      c.alg,
      { edPub: signer, mlDsaPub: c.pq_pk, slhDsaPub: c.pq_pk, mlDsa87Pub: c.pq_pk, slhDsa256sPub: c.pq_pk },
      sigMessage(c.body_digest),
      { sig: c.sig, pq_sig: c.pq_sig },
    )
  ) {
    return `${label}: bad signature (not signed by expected key)`;
  }
  return undefined;
}

/** Longest delegation chain accepted (checked before any Ed25519 work: bounds verification cost). */
export const MAX_CHAIN_DEPTH = 16;

function wellTyped(c: unknown): c is Capability {
  if (c === null || typeof c !== 'object') return false;
  const x = c as Record<string, unknown>;
  return (
    typeof x.id === 'string' &&
    typeof x.issuer === 'string' &&
    typeof x.holder === 'string' &&
    typeof x.body_digest === 'string' &&
    typeof x.sig === 'string' &&
    (x.alg === undefined || typeof x.alg === 'string') &&
    (x.pq_pk === undefined || typeof x.pq_pk === 'string') &&
    (x.pq_sig === undefined || typeof x.pq_sig === 'string') &&
    (x.parent === undefined || typeof x.parent === 'string') &&
    Array.isArray(x.caveats) &&
    x.caveats.every((cv) => cv !== null && typeof cv === 'object' && !Array.isArray(cv) && typeof (cv as Caveat).type === 'string')
  );
}

export function verifyChain(chain: CapabilityChain, expectedRootIssuer?: string): ChainResult {
  if (!Array.isArray(chain) || chain.length === 0) return { ok: false, reason: 'empty chain' };
  if (chain.length > MAX_CHAIN_DEPTH) return { ok: false, reason: `chain too long (max ${MAX_CHAIN_DEPTH} hops)` };
  for (let i = 0; i < chain.length; i++) {
    if (!wellTyped(chain[i])) return { ok: false, reason: `hop ${i}: malformed capability` };
  }
  const root = chain[0]!;
  if (root.parent !== undefined) return { ok: false, reason: 'hop 0: root must not have a parent' };
  if (expectedRootIssuer !== undefined && root.issuer !== expectedRootIssuer) {
    return { ok: false, reason: 'hop 0: root issuer is not the expected principal' };
  }
  const rootErr = checkSig(root, root.issuer, 'hop 0');
  if (rootErr) return { ok: false, reason: rootErr };

  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1]!;
    const c = chain[i]!;
    const label = `hop ${i}`;
    if (c.parent !== capHash(parent)) return { ok: false, reason: `${label}: broken parent link` };
    // Holder-binding continuity: the hop must be issued by the key the parent is bound to.
    if (c.issuer !== parent.holder) {
      return { ok: false, reason: `${label}: issuer is not the parent's bound holder` };
    }
    const err = checkSig(c, parent.holder, label);
    if (err) return { ok: false, reason: err };
    // Attenuation-only: parent caveats must be an exact prefix (no drop, reorder or edit).
    if (c.caveats.length < parent.caveats.length) {
      return { ok: false, reason: `${label}: drops parent caveat(s)` };
    }
    for (let j = 0; j < parent.caveats.length; j++) {
      if (hashCanonical(c.caveats[j]) !== hashCanonical(parent.caveats[j])) {
        return { ok: false, reason: `${label}: caveat ${j} altered or reordered` };
      }
    }
  }
  // Carried budget allocations must be monotone non-increasing down the chain (a child can only ever
  // allocate <= what its parent carried). The leaf holds the full append-only caveat list, so checking
  // it covers every hop. A chain with no `budget_alloc` caveats passes trivially (single-pool path).
  const alloc = allocationsMonotone(chain[chain.length - 1]!.caveats);
  if (!alloc.ok) return alloc;
  return { ok: true };
}
