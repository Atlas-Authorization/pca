// FROZEN SNAPSHOT of packages/pca/src/capability.ts BEFORE the verified-core wiring of chain/threshold/replay (git 6b0a2ac4). Legacy reference for the differential tests; never edit.
import { canonicalBytes, hashCanonical, unb64u, utf8 } from '../../../../pca/src/hash';
import {
  type FnDsaSuiteKey,
  type LessSuiteKey,
  type MlDsaKeyPair,
  type SigAlg,
  type SigSuite,
  type SlhDsaKeyPair,
  bindSuiteFields,
  holderPqCommitment,
  resolvePqVerifyKey,
  type PinnedPqKey,
  encodeFnDsaPublicKey,
  encodeMlDsa87PublicKey,
  encodeMlDsaPublicKey,
  encodeLessPublicKey,
  encodeSlhDsa256sPublicKey,
  encodeSlhDsaPublicKey,
  resolveSigAlg,
  signWithSuite,
  verifyWithSuite,
} from '../../../../pca/src/pq';

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
  /**
   * Commitment to the HOLDER's post-quantum public key: `holderPqCommitment(pq_pk_of_holder)`. SIGNED INTO THE BODY by
   * the issuer, so the holder identity this hop binds is the pair (Ed25519 key, PQ key), not the Ed25519 key alone.
   * A hybrid / pure-PQ signature by this holder (a delegated hop, or the PCActn leaf) is accepted only under a
   * `pq_pk` that hashes to this value; without it an Ed25519 forger could substitute its own ML-DSA key and the
   * hybrid would give no PQ protection (finding F-2). Absent for an Ed25519-only holder (body byte-identical).
   */
  holder_pq?: string;
}

export { holderPqCommitment };

/** Chain-level suite policy (F-2 / F-4). The DEFAULT is strict: see each field. */
export interface ChainPolicy {
  /**
   * Accept a hybrid / pure-PQ hop whose PQ key is NOT committed to by the parent's `holder_pq`. DEFAULT false.
   * Setting it restores the pre-fix behaviour in which the PQ key is read from the artifact, so the hybrid gives
   * NO protection against an Ed25519 forger and a pure-PQ hop is signed by an arbitrary key. Legacy only.
   */
  allowUnboundPq?: boolean;
  /** If set, every hop's suite (`alg`, absent == `ed25519`) must be listed. Unset: any registered suite. */
  allowedSuites?: readonly SigAlg[];
  /**
   * R3-01: verifier-side PQ pins by Ed25519 identity (`{ [ed25519 b64u]: pq_pk }`, from {@link pqPinFor} or the
   * verifier's own registry). A pure-PQ or hybrid ROOT hop has no parent holding a `holder_pq` commitment, so its
   * `pq_pk` is accepted only when it equals the pin of `root.issuer` (or the root is `trustedRoot`). With neither,
   * a non-ed25519 root is REFUSED (an artifact-supplied PQ key proves nothing about who issued the root).
   */
  pqPins?: Readonly<Record<string, string>>;
  /**
   * R3-01: the verifier's OWN stored copy of the root grant. When the chain's root is byte-identical (same content
   * hash) to it, the root's PQ key is the one the verifier already stored, so no pin is needed
   * (verifyPCActnCore passes its stored grant).
   */
  trustedRoot?: Capability;
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
  /** The issuer's FN-DSA-512 key material (+ signSeed) — fn-dsa-512 (pure; no hybrid is defined). */
  fnDsa512?: FnDsaSuiteKey;
  /** The issuer's FN-DSA-1024 key material (+ signSeed) — fn-dsa-1024. */
  fnDsa1024?: FnDsaSuiteKey;
  /** The issuer's LESS (category 1) key material + signSeed — less-cat1 / its hybrid (OPTIONAL pca-less-wasm backend). */
  lessCat1?: LessSuiteKey;
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

function bodyOf(c: Pick<Capability, 'issuer' | 'holder' | 'caveats' | 'parent' | 'holder_pq'>) {
  return {
    issuer: c.issuer,
    holder: c.holder,
    caveats: c.caveats,
    parent: c.parent ?? null,
    ...(c.holder_pq !== undefined ? { holder_pq: c.holder_pq } : {}),
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
  body: Pick<Capability, 'issuer' | 'holder' | 'caveats' | 'parent' | 'holder_pq'>,
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
  if (resolved.hasFnDsa512) {
    if (!(suite?.fnDsa512 && suite.fnDsa512.signingKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires an fnDsa512 key`);
    return encodeFnDsaPublicKey(suite.fnDsa512.verifyingKey);
  }
  if (resolved.hasFnDsa1024) {
    if (!(suite?.fnDsa1024 && suite.fnDsa1024.signingKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires an fnDsa1024 key`);
    return encodeFnDsaPublicKey(suite.fnDsa1024.verifyingKey);
  }
  if (resolved.hasLessCat1) {
    if (!(suite?.lessCat1 && suite.lessCat1.secretKey instanceof Uint8Array)) throw new TypeError(`capability: '${resolved.alg}' requires a lessCat1 key`);
    return encodeLessPublicKey(suite.lessCat1.publicKey);
  }
  return undefined; // unreachable: a needsPqPk suite always sets exactly one family flag.
}

function seal(
  body: { issuer: string; holder: string; caveats: Caveat[]; parent?: string; holder_pq?: string },
  signerSecret: Uint8Array,
  suite?: CapSuiteOpts,
): Capability {
  const resolved = resolveSigAlg(suite?.alg);
  if (resolved === null) throw new RangeError(`capability: unknown signature alg '${String(suite?.alg)}'`);
  const pqPk = capPqPublicKey(resolved, suite);
  const body_digest = hashCanonical(signableBody(body, suite?.alg, pqPk));
  const parts = signWithSuite(
    suite?.alg,
    { edSecret: signerSecret, mlDsa: suite?.mlDsa, slhDsa: suite?.slhDsa, mlDsa87: suite?.mlDsa87, slhDsa256s: suite?.slhDsa256s, fnDsa512: suite?.fnDsa512, fnDsa1024: suite?.fnDsa1024, lessCat1: suite?.lessCat1 },
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
  if (body.holder_pq !== undefined) cap.holder_pq = body.holder_pq;
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
  /** b64u PQ public key of the holder (as it will appear in the holder's `pq_pk`); committed into the root body as `holder_pq`. */
  holderPq?: string;
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
    {
      issuer: args.principalPublic,
      holder: args.holder,
      caveats: cloneCaveats(args.caveats),
      ...(args.holderPq !== undefined ? { holder_pq: holderPqCommitment(args.holderPq) } : {}),
    },
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
  /** b64u PQ public key of the NEW holder, committed as `holder_pq`. Omitted: kept if the holder is unchanged. */
  holderPq?: string,
): Capability {
  const holder_pq = holderPq !== undefined ? holderPqCommitment(holderPq) : toHolder === parent.holder ? parent.holder_pq : undefined;
  return seal(
    {
      issuer: parent.holder,
      holder: toHolder,
      caveats: [...cloneCaveats(parent.caveats), ...cloneCaveats(addedCaveats)],
      parent: capHash(parent),
      ...(holder_pq !== undefined ? { holder_pq } : {}),
    },
    signerSecret,
    suite,
  );
}

export interface ChainResult {
  ok: boolean;
  reason?: string;
}

function checkSig(c: Capability, signer: string, label: string, pq: PinnedPqKey | null): string | undefined {
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
  // R3-01: the PQ key is an opaque PinnedPqKey minted by the resolver (never the raw artifact `pq_pk`).
  const needsPq = resolveSigAlg(c.alg)?.needsPqPk === true;
  if (needsPq && pq === null) return `${label}: no verifier-authorised PQ key for suite '${String(c.alg)}' (refused)`;
  if (
    !verifyWithSuite(
      c.alg,
      { edPub: signer, ...(pq !== null ? { pq } : {}) },
      sigMessage(c.body_digest),
      { sig: c.sig, pq_sig: c.pq_sig },
    )
  ) {
    return `${label}: bad signature (not signed by expected key)`;
  }
  return undefined;
}

/** `allowedSuites` policy for one hop (absent `alg` == ed25519). */
function suitePolicyError(c: Capability, label: string, policy: ChainPolicy | undefined): string | undefined {
  const allowed = policy?.allowedSuites;
  if (allowed === undefined) return undefined;
  const alg = c.alg ?? 'ed25519';
  return allowed.includes(alg) ? undefined : `${label}: signature suite '${String(alg)}' is not allowed by this verifier's suite policy`;
}

/**
 * F-2 / F-4: a hop or leaf of a suite that carries a PQ key (hybrid or pure PQ) is accepted only if that `pq_pk`
 * is the one the issuer's holder committed to (`holder_pq`). `committed` is the holder commitment of whoever
 * signs (the parent hop's `holder_pq`). Returns an error string, or undefined when fine / not applicable.
 */
export function pqBindingError(
  alg: unknown,
  pqPk: unknown,
  committed: string | undefined,
  label: string,
  policy: ChainPolicy | undefined,
): string | undefined {
  const suite = resolveSigAlg(alg);
  if (suite === null || !suite.needsPqPk || policy?.allowUnboundPq === true) return undefined;
  if (committed === undefined) {
    return `${label}: suite '${suite.alg}' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)`;
  }
  if (typeof pqPk !== 'string' || holderPqCommitment(pqPk) !== committed) {
    return `${label}: pq_pk does not match the signer's committed holder_pq (F-2)`;
  }
  return undefined;
}

/**
 * The PQ verification key for a signature by `holder` (a chain leaf / threshold share) under suite `alg`: minted by
 * the {@link resolvePqVerifyKey} choke point from the holder's `holder_pq` commitment. `{}` for ed25519; also `{}` (so
 * the signature check fails closed) when the artifact's `pq_pk` is not the committed key.
 */
export function holderPqKey(
  alg: unknown,
  holder: string,
  artifactPqPk: unknown,
  holderPq: string | undefined,
  allowUnboundPq?: boolean,
): { pq?: PinnedPqKey } {
  const suite = resolveSigAlg(alg);
  if (suite === null || !suite.needsPqPk) return {};
  const pq = resolvePqVerifyKey(holder, artifactPqPk, { holderPq, allowUnboundPq });
  return pq === null ? {} : { pq };
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
    (x.holder_pq === undefined || typeof x.holder_pq === 'string') &&
    (x.parent === undefined || typeof x.parent === 'string') &&
    Array.isArray(x.caveats) &&
    x.caveats.every((cv) => cv !== null && typeof cv === 'object' && !Array.isArray(cv) && typeof (cv as Caveat).type === 'string')
  );
}

export function verifyChain(chain: CapabilityChain, expectedRootIssuer?: string, policy?: ChainPolicy): ChainResult {
  // TOTAL: a hostile chain (e.g. a caveat whose number cannot be canonicalized) is a verdict, never an exception.
  try {
    return verifyChainUnchecked(chain, expectedRootIssuer, policy);
  } catch (e) {
    return { ok: false, reason: `malformed capability chain: ${e instanceof Error ? e.message : 'unverifiable'}` };
  }
}

function verifyChainUnchecked(chain: CapabilityChain, expectedRootIssuer?: string, policy?: ChainPolicy): ChainResult {
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
  const rootPol = suitePolicyError(root, 'hop 0', policy);
  if (rootPol) return { ok: false, reason: rootPol };
  // R3-01: the ROOT has no parent holding a holder_pq commitment, so a non-ed25519 root's PQ key must come from a
  // verifier-side authority: the verifier's stored copy of this very grant (trustedRoot, byte-identical), or a pin
  // for root.issuer. Otherwise the root would verify under its OWN pq_pk and any grant for any principal is forgeable.
  const rootSuite = resolveSigAlg(root.alg);
  let rootPq: PinnedPqKey | null = null;
  if (rootSuite !== null && rootSuite.needsPqPk) {
    rootPq =
      policy?.trustedRoot !== undefined && typeof root.pq_pk === 'string' && capHash(policy.trustedRoot) === capHash(root)
        ? resolvePqVerifyKey(root.issuer, root.pq_pk, { trustedPk: root.pq_pk })
        : resolvePqVerifyKey(root.issuer, root.pq_pk, { pqPins: policy?.pqPins, allowUnboundPq: policy?.allowUnboundPq });
    if (rootPq === null) {
      return {
        ok: false,
        reason: `hop 0: root suite '${rootSuite.alg}' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)`,
      };
    }
  }
  const rootErr = checkSig(root, root.issuer, 'hop 0', rootPq);
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
    const pol = suitePolicyError(c, label, policy);
    if (pol) return { ok: false, reason: pol };
    const unbound = pqBindingError(c.alg, c.pq_pk, parent.holder_pq, label, policy);
    if (unbound) return { ok: false, reason: unbound };
    const hopSuite = resolveSigAlg(c.alg);
    const hopPq =
      hopSuite !== null && hopSuite.needsPqPk
        ? resolvePqVerifyKey(parent.holder, c.pq_pk, { holderPq: parent.holder_pq, allowUnboundPq: policy?.allowUnboundPq })
        : null;
    const err = checkSig(c, parent.holder, label, hopPq);
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
