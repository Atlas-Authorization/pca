/**
 * Cross-domain proof-carrying delegation: the agent mesh (frontier research section 3.3).
 *
 * A human at hop 0 mints an attenuable capability. It flows through N hops of agents (each hop may
 * cross an organisation / domain boundary) and ends in a leaf action. The leaf action carries the
 * WHOLE chain plus compact per-hop evidence, so any service verifies it OFFLINE, trusting no central
 * authority:
 *
 *  - Authority: capability.ts `verifyChain` - hash-linked, signed by the previous holder, caveats
 *    append-only. The chain is a monotone narrowing rooted in the hop-0 human key.
 *  - Cross-org trust: every hop is recorded in the ISSUING domain's append-only Merkle log. The
 *    domain publishes a head `{size, log root, revocation root, timestamp}` signed by its own key and
 *    CO-SIGNED by k-of-n independent witnesses (C2SP style). A witness cosigns a head ONLY IF it is a
 *    verified RFC 9162 append-only extension of the previous head it cosigned for that domain (real
 *    consistency proof, not a size check), and its revocation set is a superset of the previous one.
 *    A domain therefore cannot show two verifiers different histories, roll back, or rewrite a hop,
 *    without a witness refusing (and, if witnesses collude, a signed contradiction existing).
 *  - Revocation: each domain's head also commits its revocation set (sorted Merkle set). Every hop must
 *    carry a NON-membership proof for its capability id and its issuer key against its domain's head,
 *    so revoking any hop in any domain kills every descendant leaf, within the latency bound given by
 *    `revocationLatencyBound`.
 *  - Verifier-side pins: a verifier that remembers the newest head per domain rejects rollback and, for
 *    any larger head, demands a consistency proof from its pin (`MeshProof.pin_proofs`).
 *
 * Proof compaction: heads are carried once in a table (`heads`) and referenced by index from every hop
 * issued in that domain; revocation-bracketing leaves are carried once in `rev_leaves`.
 *
 * Trust anchors: the human principal key and a pinned witness set with a threshold. No CA, no domain
 * keys. Domain ids are their own public keys.
 *
 * Production vs integration remainder: see docs/pca-frontier/cross-domain-mesh.md.
 *
 * Pure and deterministic: Ed25519 signatures are deterministic, and every timestamp is explicit.
 */
import { b64u, canonicalBytes, hashCanonical, utf8 } from './hash';
import { type Capability, type Caveat, capHash, delegate, mintRoot, verifyChain } from './capability';
import { encodeKey, publicKeyOf, sign, verifyB64u } from './keys';
import { type TrustBudget, debit, debitConsolidated, safetyBound, subBudget } from './risk';
import { type ConsistencyProof, TransparencyLedger, verifyLedgerConsistency } from './ledger';
import { type InclusionProof, merkleProof, merkleRoot, verifyInclusion } from './merkle';
import { type LeafProof, type NonMembershipProof, RevocationSet, verifyNonMembership } from './revocation';

// ---------------------------------------------------------------------------------------------
// Messages (all domain-separated)
// ---------------------------------------------------------------------------------------------

const HEAD_DOMAIN = 'atlas-pca/mesh-head/v1\0';
const COSIG_DOMAIN = 'atlas-pca/mesh-cosig/v1\0';
const BINDING_DOMAIN = 'atlas-pca/mesh-binding/v1\0';
const ACTION_DOMAIN = 'atlas-pca/mesh-action/v1\0';

/** Default maximum accepted head age (revocation freshness window): 5 minutes. */
export const DEFAULT_MAX_HEAD_AGE_MS = 5 * 60_000;
/** Default tolerated clock skew for heads and actions timestamped in the verifier's future: 60 s. */
export const DEFAULT_MAX_CLOCK_SKEW_MS = 60_000;
/** Default cap on delegation chain length a verifier will process. */
export const DEFAULT_MAX_CHAIN_LENGTH = 64;
/** Cap on cosignatures / table entries processed per head (DoS bound). */
const MAX_COSIGS = 256;
/** Cap on consistency / inclusion path length (2^128 leaves is unreachable). */
const MAX_PATH = 128;
/** Cap on a witness's accepted revocation list. */
const MAX_REV_IDS = 1_000_000;

function msg(domain: string, body: unknown): Uint8Array {
  const b = canonicalBytes(body);
  const p = utf8(domain);
  const m = new Uint8Array(p.length + b.length);
  m.set(p);
  m.set(b, p.length);
  return m;
}

/** Id used in a domain's revocation set to revoke an agent KEY (kills every cap it issues). */
export function keyRevocationId(agentPublic: string): string {
  return `key:${agentPublic}`;
}

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

/** What a domain publishes. `domain` is the domain's own public key (self-certifying id). */
export interface MeshHead {
  domain: string;
  size: number;
  /** Merkle root of the delegation log ('' when empty). */
  root: string;
  /** Size-bound root of the revocation set (revocation.ts RevocationSet.root). */
  rev_root: string;
  /** Number of revoked ids committed by `rev_root`. */
  rev_size: number;
  /** epoch ms. */
  timestamp: number;
}

/** A witness's signature over a head (message domain-separated from every other signature). */
export interface Cosignature {
  witness: string;
  sig: string;
}

/** A head with the domain's signature and the witness cosignatures. */
export interface CosignedHead {
  head: MeshHead;
  /** Domain's own signature over the head. */
  sig: string;
  cosigs: Cosignature[];
}

/** The domain vouches that `agent` is one of its principals (used for domain policy, not authority). */
export interface DomainBinding {
  agent: string;
  domain: string;
  role: string;
  sig: string;
}

/** Non-membership proof whose bracketing leaves are indices into `MeshProof.rev_leaves`. */
export interface CompactNonMembership {
  size: number;
  lo?: number;
  hi?: number;
}

/** Uncompacted per-hop evidence as built by `MeshDomain.evidence` (compacted by `assembleMeshProof`). */
export interface HopEvidenceInput {
  /** The domain that issued (and logged) this hop. */
  domain: string;
  head: CosignedHead;
  inclusion: InclusionProof;
  /** Absent for hop 0, whose issuer is the human principal. */
  binding?: DomainBinding;
  revocation: { cap: NonMembershipProof; issuer_key: NonMembershipProof };
}

/** Compact per-hop evidence carried in a `MeshProof`. */
export interface HopEvidence {
  /** The domain that issued (and logged) this hop. */
  domain: string;
  /** Index into `MeshProof.heads` (shared by every hop issued in this domain at that head). */
  head: number;
  inclusion: InclusionProof;
  /** Absent for hop 0, whose issuer is the human principal. */
  binding?: DomainBinding;
  revocation: { cap: CompactNonMembership; issuer_key: CompactNonMembership };
}

/** The leaf action the proof authorises. */
export interface MeshAction {
  type: string;
  resource: string;
  amount?: number;
  /** Domain id (key) of the service the action is addressed to. */
  service_domain: string;
  nonce: string;
  /** epoch ms. */
  at: number;
}

/** Everything a service needs to verify a cross-domain action offline. */
export interface MeshProof {
  chain: Capability[];
  /** De-duplicated table of cosigned heads referenced by `hops[i].head`. */
  heads: CosignedHead[];
  /** De-duplicated revocation bracketing leaves referenced by compact non-membership proofs. */
  rev_leaves: LeafProof[];
  hops: HopEvidence[];
  /** Optional: consistency proofs from the verifier's pinned head to a larger presented head. */
  pin_proofs?: { domain: string; proof: ConsistencyProof }[];
  action: MeshAction;
  /** By the chain tip's holder over {action, tip}. */
  action_sig: string;
}

/** Verifier-side trust anchors. NOTE: no domain keys and no CA - only the human and witnesses. */
export interface MeshTrust {
  /** The hop-0 principal (the human) this service accepts as authority root. */
  humanPrincipal: string;
  /** Pinned witness public keys (b64u). */
  witnesses: string[];
  /** How many distinct pinned witnesses must have cosigned each head (1..distinct witnesses). */
  threshold: number;
  /** Verifier clock, epoch ms. */
  now: number;
  /** Reject heads older than this (revocation freshness). Default {@link DEFAULT_MAX_HEAD_AGE_MS}. */
  maxHeadAgeMs?: number;
  /** Tolerated future skew for heads and actions. Default {@link DEFAULT_MAX_CLOCK_SKEW_MS}. */
  maxClockSkewMs?: number;
  /** Optional: reject actions whose signed `at` is older than this. */
  maxActionAgeMs?: number;
  /** Max chain length. Default {@link DEFAULT_MAX_CHAIN_LENGTH}. */
  maxChainLength?: number;
  /** Optional policy: only accept hops issued in these domains. */
  allowedDomains?: string[];
  /** Optional verifier memory of newest heads seen per domain (rollback + fork defence). */
  pinnedHeads?: Record<string, MeshHead>;
}

/** Per-hop record of what was verified. */
export interface HopTrace {
  hop: number;
  domain: string;
  issuer: string;
  holder: string;
  /** true when the NEXT hop is issued in a different domain (or the action targets another). */
  crosses_boundary: boolean;
  effective: EffectiveAuthority;
}

/** Result of `verifyMeshProof`. Never throws; `ok:false` always carries a `reason`. */
export interface MeshVerdict {
  ok: boolean;
  reason?: string;
  /** Hop index that failed, when applicable. */
  hop?: number;
  trace: HopTrace[];
  root_principal?: string;
  leaf?: string;
}

// ---------------------------------------------------------------------------------------------
// Shape guards (every untrusted structure is validated before use; failures are fail-closed)
// ---------------------------------------------------------------------------------------------

const isRec = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const isStr = (x: unknown): x is string => typeof x === 'string';
const isNat = (x: unknown): x is number => typeof x === 'number' && Number.isSafeInteger(x) && x >= 0;
const isNum = (x: unknown): x is number => typeof x === 'number' && Number.isFinite(x);
const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

function validHead(h: unknown): h is MeshHead {
  if (!isRec(h)) return false;
  if (!isStr(h.domain) || !isStr(h.root) || !isStr(h.rev_root)) return false;
  if (!isNat(h.size) || !isNat(h.rev_size) || !isNum(h.timestamp)) return false;
  return (h.size === 0) === (h.root === '');
}

function validConsistency(c: unknown): c is ConsistencyProof {
  return isRec(c) && isNat(c.oldSize) && isNat(c.newSize) && Array.isArray(c.path) && c.path.length <= MAX_PATH && c.path.every(isStr);
}

function validInclusion(i: unknown): i is InclusionProof {
  return isRec(i) && isNat(i.index) && isNat(i.size) && Array.isArray(i.path) && i.path.length <= MAX_PATH;
}

function validAction(a: unknown): a is MeshAction {
  if (!isRec(a)) return false;
  if (!isStr(a.type) || !isStr(a.resource) || !isStr(a.service_domain) || !isStr(a.nonce) || !isNum(a.at)) return false;
  return a.amount === undefined || isNum(a.amount);
}

// ---------------------------------------------------------------------------------------------
// Caveats: effective authority (conjunction of all caveats; fail closed on unknown types)
// ---------------------------------------------------------------------------------------------
//
//   {type:'scope',    actions:[...]}      action.type must be listed
//   {type:'resource', prefix:'/x'}        action.resource must start with prefix
//   {type:'max_amount', max:N}            action.amount <= N
//   {type:'expires',  at:ms}              now <= at
//   {type:'audience', domains:[...]}      action.service_domain must be listed
//   {type:'max_hops', n:N}                chain length <= N

/** The combined constraint a chain of caveats imposes. */
export interface EffectiveAuthority {
  /** undefined = unconstrained. */
  actions?: string[];
  prefixes: string[];
  maxAmount?: number;
  expiresAt?: number;
  audience?: string[];
  maxHops?: number;
}

const KNOWN = new Set(['scope', 'resource', 'max_amount', 'expires', 'audience', 'max_hops']);

function intersect(a: string[] | undefined, b: string[]): string[] {
  return a === undefined ? [...new Set(b)].sort() : a.filter((x) => b.includes(x));
}
function minOf(a: number | undefined, b: number): number {
  return a === undefined ? b : Math.min(a, b);
}

/** Conjunction of all caveats as one authority; unknown or malformed caveats fail closed with an `error` result. */
export function effectiveAuthority(caveats: Caveat[]): EffectiveAuthority | { error: string } {
  const e: EffectiveAuthority = { prefixes: [] };
  for (const c of caveats) {
    if (!KNOWN.has(c.type)) return { error: `unknown caveat type "${c.type}" (fail closed)` };
    switch (c.type) {
      case 'scope':
        if (!Array.isArray(c.actions) || !c.actions.every((x) => typeof x === 'string')) return { error: 'malformed scope caveat' };
        e.actions = intersect(e.actions, c.actions as string[]);
        break;
      case 'resource':
        if (typeof c.prefix !== 'string') return { error: 'malformed resource caveat' };
        e.prefixes.push(c.prefix);
        break;
      case 'max_amount':
        if (typeof c.max !== 'number' || !Number.isFinite(c.max)) return { error: 'malformed max_amount caveat' };
        e.maxAmount = minOf(e.maxAmount, c.max);
        break;
      case 'expires':
        if (typeof c.at !== 'number' || !Number.isFinite(c.at)) return { error: 'malformed expires caveat' };
        e.expiresAt = minOf(e.expiresAt, c.at);
        break;
      case 'audience':
        if (!Array.isArray(c.domains) || !c.domains.every((x) => typeof x === 'string')) return { error: 'malformed audience caveat' };
        e.audience = intersect(e.audience, c.domains as string[]);
        break;
      case 'max_hops':
        if (typeof c.n !== 'number' || !Number.isFinite(c.n)) return { error: 'malformed max_hops caveat' };
        e.maxHops = minOf(e.maxHops, c.n);
        break;
    }
  }
  return e;
}

/** Does every action admitted by `child` also pass `parent`? (Defence in depth: monotone narrowing.) */
function narrows(child: EffectiveAuthority, parent: EffectiveAuthority): boolean {
  if (parent.actions !== undefined && (child.actions === undefined || !child.actions.every((a) => parent.actions!.includes(a)))) return false;
  if (parent.audience !== undefined && (child.audience === undefined || !child.audience.every((a) => parent.audience!.includes(a)))) return false;
  if (parent.maxAmount !== undefined && (child.maxAmount === undefined || child.maxAmount > parent.maxAmount)) return false;
  if (parent.expiresAt !== undefined && (child.expiresAt === undefined || child.expiresAt > parent.expiresAt)) return false;
  if (parent.maxHops !== undefined && (child.maxHops === undefined || child.maxHops > parent.maxHops)) return false;
  // Every parent prefix constraint must still be implied by the child's (child keeps all of them).
  for (const p of parent.prefixes) if (!child.prefixes.includes(p)) return false;
  return true;
}

function admits(e: EffectiveAuthority, a: MeshAction, now: number, chainLen: number): string | undefined {
  if (e.actions !== undefined && !e.actions.includes(a.type)) return `action "${a.type}" not in scope`;
  for (const p of e.prefixes) if (!a.resource.startsWith(p)) return `resource "${a.resource}" outside prefix "${p}"`;
  if (e.maxAmount !== undefined && (a.amount === undefined || a.amount > e.maxAmount)) return `amount exceeds ceiling ${e.maxAmount}`;
  if (e.expiresAt !== undefined && now > e.expiresAt) return 'capability expired';
  if (e.audience !== undefined && !e.audience.includes(a.service_domain)) return 'service domain not in audience';
  if (e.maxHops !== undefined && chainLen > e.maxHops) return `chain exceeds max_hops ${e.maxHops}`;
  return undefined;
}

// ---------------------------------------------------------------------------------------------
// Head advance: the ONE append-only rule used by witnesses (cosign) and verifiers (pins)
// ---------------------------------------------------------------------------------------------

/**
 * Is `next` a legitimate successor of `prev` (same domain)? Returns a failure reason or undefined.
 *
 *  - sizes (log and revocation) never shrink;
 *  - equal log size => identical log root (else equivocation);
 *  - larger log size => a real RFC 9162 consistency proof from prev to next must verify (this catches
 *    rollback AND any fork that merely grew past the previous size);
 *  - equal revocation size => identical revocation root.
 *
 * Revocation sets are sorted (not append-only by index), so superset-ness is enforced by witnesses
 * (which are shown the revocation list), and only size-monotone + equal-size equivocation is checkable
 * by a verifier from the heads alone. Timestamps are NOT compared here (witnesses add that rule).
 */
export function checkHeadAdvance(prev: MeshHead, next: MeshHead, proof?: ConsistencyProof): string | undefined {
  try {
    if (!validHead(prev) || !validHead(next)) return 'malformed head';
    if (prev.domain !== next.domain) return 'head is for a different domain';
    if (next.size < prev.size || next.rev_size < prev.rev_size) return 'head rolls back';
    if (next.size === prev.size) {
      if (next.root !== prev.root) return 'equivocation (same size, different log)';
    } else {
      if (!validConsistency(proof) || proof.oldSize !== prev.size || proof.newSize !== next.size) {
        return 'consistency proof required for a larger head';
      }
      if (!verifyLedgerConsistency(prev.root, next.root, proof)) return 'head is not consistent with the previous head (fork or rewrite)';
    }
    if (next.rev_size === prev.rev_size && next.rev_root !== prev.rev_root) return 'equivocation (revocation set)';
    return undefined;
  } catch {
    return 'malformed head';
  }
}

// ---------------------------------------------------------------------------------------------
// Witness
// ---------------------------------------------------------------------------------------------

/** What a domain submits to a witness: the head, a consistency proof from the witness's last head, and the revocation list. */
export interface CosignRequest {
  head: CosignedHead;
  /** Required whenever the head's log is larger than the witness's last-seen head for this domain. */
  consistency?: ConsistencyProof;
  /** Full sorted revocation id list committed by `head.head.rev_root` (witness recomputes the root). */
  rev_ids: string[];
}

/** Serializable witness memory (for persistence across restarts). */
export interface MeshWitnessState {
  seen: { head: MeshHead; rev_ids: string[] }[];
}

/** Optional witness configuration. */
export interface MeshWitnessOptions {
  /** Witness's own clock; when set, heads timestamped beyond `now + maxClockSkewMs` are refused. */
  clock?: () => number;
  /** Default {@link DEFAULT_MAX_CLOCK_SKEW_MS}. */
  maxClockSkewMs?: number;
}

/**
 * An independent log witness. It cosigns a domain head only if (1) the domain signed it, (2) it is an
 * RFC 9162-verified append-only extension of the last head THIS witness cosigned for that domain
 * (`checkHeadAdvance`), (3) its revocation list reproduces `rev_root` and is a superset of the
 * previously cosigned list, and (4) the timestamp does not regress (nor run ahead of the witness's own
 * clock, when configured). State is committed only after every check passes. First sight of a domain
 * is trust-on-first-use (a witness cannot know a domain's genesis).
 */
export class MeshWitness {
  readonly id: string;
  private readonly seen = new Map<string, { head: MeshHead; rev: string[] }>();
  constructor(
    private readonly secret: Uint8Array,
    private readonly opts: MeshWitnessOptions = {},
  ) {
    this.id = encodeKey(publicKeyOf(secret));
  }

  /** The newest head this witness cosigned for `domain` (what a domain must prove consistency from). */
  lastSeen(domain: string): MeshHead | undefined {
    const s = this.seen.get(domain);
    return s ? { ...s.head } : undefined;
  }

  /** Cosign a head. Throws (and changes nothing) if any rule is violated. */
  cosign(req: CosignRequest): Cosignature {
    const ch = req?.head;
    if (!ch || !validHead(ch.head) || !isStr(ch.sig)) throw new Error('witness: malformed head');
    const h = ch.head;
    if (!verifyB64u(h.domain, msg(HEAD_DOMAIN, h), ch.sig)) throw new Error('witness: head not signed by its domain');
    if (this.opts.clock) {
      const skew = this.opts.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;
      if (h.timestamp > this.opts.clock() + skew) throw new Error('witness: head timestamp is in the future');
    }
    const ids = req.rev_ids;
    if (!Array.isArray(ids) || ids.length > MAX_REV_IDS || !ids.every(isStr)) throw new Error('witness: malformed revocation list');
    const set = new RevocationSet(ids);
    if (set.size !== h.rev_size || set.root !== h.rev_root) throw new Error('witness: revocation list does not match head');
    const prev = this.seen.get(h.domain);
    if (prev) {
      const why = checkHeadAdvance(prev.head, h, req.consistency);
      if (why) throw new Error(`witness: ${why}`);
      if (h.timestamp < prev.head.timestamp) throw new Error('witness: timestamp regresses');
      const now = new Set(set.list());
      if (!prev.rev.every((id) => now.has(id))) throw new Error('witness: revocation set drops a previously cosigned revocation');
    }
    this.seen.set(h.domain, { head: { ...h }, rev: set.list() });
    return { witness: this.id, sig: b64u(sign(this.secret, msg(COSIG_DOMAIN, h))) };
  }

  /** Export memory for persistence. Deterministic order. */
  exportState(): MeshWitnessState {
    return { seen: [...this.seen.values()].map((s) => ({ head: { ...s.head }, rev_ids: [...s.rev] })).sort((a, b) => (a.head.domain < b.head.domain ? -1 : 1)) };
  }

  /** Restore memory; each record must be internally consistent (revocation list reproduces its root). */
  importState(state: MeshWitnessState): void {
    const next = new Map<string, { head: MeshHead; rev: string[] }>();
    for (const s of state?.seen ?? []) {
      if (!validHead(s?.head) || !Array.isArray(s.rev_ids) || !s.rev_ids.every(isStr)) throw new Error('witness: malformed state');
      const set = new RevocationSet(s.rev_ids);
      if (set.size !== s.head.rev_size || set.root !== s.head.rev_root) throw new Error('witness: malformed state');
      next.set(s.head.domain, { head: { ...s.head }, rev: set.list() });
    }
    this.seen.clear();
    for (const [k, v] of next) this.seen.set(k, v);
  }
}

// ---------------------------------------------------------------------------------------------
// Domain (issuer side: log + revocation set + head publication)
// ---------------------------------------------------------------------------------------------

interface Snapshot {
  log: string[];
  rev: RevocationSet;
}

/** Options for `MeshDomain.publishHead`. */
export interface PublishOptions {
  /** Tolerate witness refusals as long as at least this many cosign. Default: every witness must cosign. */
  threshold?: number;
}

/**
 * Issuer-side state of one organisation: an append-only delegation log, a revocation set, and head
 * publication. In production this is the deployed signed-tree-head + revocation-epoch machinery; here
 * it is in-memory so the protocol can be exercised end to end.
 */
export class MeshDomain {
  readonly id: string;
  private readonly log: string[] = [];
  private readonly rev = new RevocationSet();
  private readonly snaps = new Map<string, Snapshot>(); // keyed by head signature

  constructor(
    readonly name: string,
    private readonly secret: Uint8Array,
  ) {
    this.id = encodeKey(publicKeyOf(secret));
  }

  /** Vouch that an agent key belongs to this domain. */
  enroll(agent: string, role: string): DomainBinding {
    return { agent, domain: this.id, role, sig: b64u(sign(this.secret, msg(BINDING_DOMAIN, { agent, domain: this.id, role }))) };
  }

  /** Log a delegation hop issued in this domain. Idempotent. */
  record(cap: Capability): number {
    const h = capHash(cap);
    const i = this.log.indexOf(h);
    if (i >= 0) return i;
    this.log.push(h);
    return this.log.length - 1;
  }

  /** Revoke a capability id (cap.id) or an agent key (keyRevocationId). */
  revoke(id: string): void {
    this.rev.revoke(id);
  }

  /** RFC 9162 consistency proof between two sizes of this domain's current log. */
  consistencyProof(oldSize: number, newSize: number = this.log.length): ConsistencyProof {
    return TransparencyLedger.fromEntries(this.log.map((commit) => ({ commit }))).consistencyProof(oldSize, newSize);
  }

  /**
   * Proof a verifier holding `pin` needs to accept `head` (a head this domain published, larger than
   * the pin). Throws if the pin is not a prefix of that head's log.
   */
  pinProof(pin: MeshHead, head: CosignedHead): { domain: string; proof: ConsistencyProof } {
    const snap = this.snaps.get(head.sig);
    if (!snap) throw new Error('pinProof: unknown head');
    const l = TransparencyLedger.fromEntries(snap.log.map((commit) => ({ commit })));
    return { domain: this.id, proof: l.consistencyProof(pin.size, head.head.size) };
  }

  /**
   * Publish a head: domain-signed, then cosigned by `witnesses`, each shown a real consistency proof
   * from ITS last-seen head plus the revocation list. Throws if a witness refuses (unless
   * `opts.threshold` tolerates it); nothing is recorded as published on failure.
   */
  publishHead(witnesses: MeshWitness[], timestamp: number, opts: PublishOptions = {}): CosignedHead {
    const head: MeshHead = {
      domain: this.id,
      size: this.log.length,
      root: this.log.length === 0 ? '' : merkleRoot(this.log),
      rev_root: this.rev.root,
      rev_size: this.rev.size,
      timestamp,
    };
    const ch: CosignedHead = { head, sig: b64u(sign(this.secret, msg(HEAD_DOMAIN, head))), cosigs: [] };
    const ledger = TransparencyLedger.fromEntries(this.log.map((commit) => ({ commit })));
    const rev_ids = this.rev.list();
    const errors: Error[] = [];
    for (const w of witnesses) {
      const prev = w.lastSeen(this.id);
      let consistency: ConsistencyProof | undefined;
      if (prev && prev.size < head.size) consistency = ledger.consistencyProof(prev.size, head.size);
      else if (prev && prev.size > head.size) consistency = { oldSize: prev.size, newSize: head.size, path: [] }; // will be refused as rollback
      try {
        ch.cosigs.push(w.cosign({ head: ch, ...(consistency ? { consistency } : {}), rev_ids }));
      } catch (e) {
        errors.push(e as Error);
      }
    }
    const need = opts.threshold ?? witnesses.length;
    if (ch.cosigs.length < need) throw errors[0] ?? new Error('publishHead: not enough witnesses');
    this.snaps.set(ch.sig, { log: [...this.log], rev: new RevocationSet(this.rev.list()) });
    return ch;
  }

  /**
   * Build per-hop evidence against a previously published head. Throws if the cap is not in that
   * head's log or if the cap / issuer key is revoked as of that head (no non-membership proof can exist).
   */
  evidence(cap: Capability, head: CosignedHead, binding?: DomainBinding): HopEvidenceInput {
    const snap = this.snaps.get(head.sig);
    if (!snap) throw new Error('evidence: unknown head');
    const idx = snap.log.indexOf(capHash(cap));
    if (idx < 0) throw new Error('evidence: capability not in this head');
    const ev: HopEvidenceInput = {
      domain: this.id,
      head,
      inclusion: merkleProof(snap.log, idx),
      revocation: {
        cap: snap.rev.nonMembershipProof(cap.id),
        issuer_key: snap.rev.nonMembershipProof(keyRevocationId(cap.issuer)),
      },
    };
    if (binding) ev.binding = binding;
    return ev;
  }
}

// ---------------------------------------------------------------------------------------------
// Action signing + proof assembly (compaction)
// ---------------------------------------------------------------------------------------------

/** The leaf holder signs the action, bound to the chain tip. */
export function signMeshAction(chain: Capability[], action: MeshAction, leafSecret: Uint8Array): string {
  const tip = capHash(chain[chain.length - 1]!);
  return b64u(sign(leafSecret, msg(ACTION_DOMAIN, { action, tip })));
}

/**
 * Assemble a compact proof. Hops issued against the same head share ONE table entry (cosignatures
 * for the same head are merged), and identical revocation bracketing leaves are carried once.
 */
export function assembleMeshProof(args: {
  chain: Capability[];
  hops: HopEvidenceInput[];
  action: MeshAction;
  leafSecret: Uint8Array;
  pinProofs?: { domain: string; proof: ConsistencyProof }[];
}): MeshProof {
  const heads: CosignedHead[] = [];
  const headIdx = new Map<string, number>();
  const leaves: LeafProof[] = [];
  const leafIdx = new Map<string, number>();
  const leaf = (l: LeafProof): number => {
    const k = JSON.stringify(l);
    let i = leafIdx.get(k);
    if (i === undefined) {
      i = leaves.length;
      leaves.push(l);
      leafIdx.set(k, i);
    }
    return i;
  };
  const compact = (n: NonMembershipProof): CompactNonMembership => ({
    size: n.size,
    ...(n.lo ? { lo: leaf(n.lo) } : {}),
    ...(n.hi ? { hi: leaf(n.hi) } : {}),
  });
  const hops: HopEvidence[] = args.hops.map((ev) => {
    const k = `${ev.head.sig}|${JSON.stringify(ev.head.head)}`;
    let i = headIdx.get(k);
    if (i === undefined) {
      i = heads.length;
      heads.push({ head: ev.head.head, sig: ev.head.sig, cosigs: [...ev.head.cosigs] });
      headIdx.set(k, i);
    } else {
      const have = new Set(heads[i]!.cosigs.map((c) => c.witness));
      for (const c of ev.head.cosigs) if (!have.has(c.witness)) heads[i]!.cosigs.push(c);
    }
    const out: HopEvidence = {
      domain: ev.domain,
      head: i,
      inclusion: ev.inclusion,
      revocation: { cap: compact(ev.revocation.cap), issuer_key: compact(ev.revocation.issuer_key) },
    };
    if (ev.binding) out.binding = ev.binding;
    return out;
  });
  const proof: MeshProof = {
    chain: args.chain,
    heads,
    rev_leaves: leaves,
    hops,
    action: args.action,
    action_sig: signMeshAction(args.chain, args.action, args.leafSecret),
  };
  if (args.pinProofs && args.pinProofs.length > 0) proof.pin_proofs = args.pinProofs;
  return proof;
}

// ---------------------------------------------------------------------------------------------
// Size model
// ---------------------------------------------------------------------------------------------

/** Byte sizes (canonical JSON) of a proof's parts. */
export interface MeshProofSize {
  total_bytes: number;
  chain_bytes: number;
  heads_bytes: number;
  rev_leaves_bytes: number;
  hops_bytes: number;
  /** Size had every hop carried its own head copy and inline revocation leaves (the v0 layout). */
  uncompacted_bytes: number;
}

const bytes = (x: unknown): number => canonicalBytes(x).length;

/**
 * Size accounting. Characteristics, for N hops across D distinct (domain, head) pairs and a revocation
 * set of R ids per head:
 *  - chain: O(N) (each hop one signed capability);
 *  - heads: O(D * (1 + k)) - one head + k witness cosignatures per DOMAIN, independent of N;
 *  - hops: O(N * (log2 L + 1)) inclusion path (L = domain log size) + binding;
 *  - revocation: O(N * log2 R) for the bracketing leaves, halved or better when adjacent / shared.
 * Compared with v0 (head + 2 inline non-membership proofs per hop) the saving grows with hops-per-domain.
 */
export function meshProofSize(p: MeshProof): MeshProofSize {
  const expand = (c: CompactNonMembership): NonMembershipProof => ({
    size: c.size,
    ...(c.lo !== undefined && p.rev_leaves[c.lo] ? { lo: p.rev_leaves[c.lo]! } : {}),
    ...(c.hi !== undefined && p.rev_leaves[c.hi] ? { hi: p.rev_leaves[c.hi]! } : {}),
  });
  const uncompacted =
    bytes(p.chain) +
    bytes(p.action) +
    bytes(p.action_sig) +
    p.hops.reduce((n, h) => n + bytes({ ...h, head: p.heads[h.head], revocation: { cap: expand(h.revocation.cap), issuer_key: expand(h.revocation.issuer_key) } }), 0);
  return {
    total_bytes: bytes(p),
    chain_bytes: bytes(p.chain),
    heads_bytes: bytes(p.heads),
    rev_leaves_bytes: bytes(p.rev_leaves),
    hops_bytes: bytes(p.hops),
    uncompacted_bytes: uncompacted,
  };
}

// ---------------------------------------------------------------------------------------------
// Freshness + revocation latency model
// ---------------------------------------------------------------------------------------------

/** Inputs of the revocation latency model (all milliseconds). */
export interface LatencyParams {
  /** Verifier's `maxHeadAgeMs`. */
  maxHeadAgeMs: number;
  /** Verifier's `maxClockSkewMs` (clock disagreement between verifier and domain). Default 0. */
  maxClockSkewMs?: number;
  /** How often a domain republishes a head (also covers revocations). */
  headIntervalMs: number;
  /** How often a pinning verifier advances its pin from a witnessed head. Unset = verifier does not pin. */
  pinRefreshMs?: number;
}

/** Worst-case time from "revocation made" until it is enforced, per verifier posture. */
export interface LatencyBound {
  /** Until the revocation is visible in a head that new provers hold (domain-side propagation). */
  published_ms: number;
  /** Non-pinning verifier: a pre-revocation head (timestamp <= r) is rejected as stale by then. */
  unpinned_ms: number;
  /** Pinning verifier: min(unpinned, pin refresh). */
  pinned_ms: number;
  /**
   * Honest provers can always hold a fresh head only if headIntervalMs < maxHeadAgeMs (after skew);
   * otherwise legitimate proofs go stale between publications.
   */
  honest_provers_viable: boolean;
}

/**
 * The explicit, tunable revocation-latency bound. Derivation: a head with timestamp T <= r (the time
 * of revocation) cannot contain the revocation, and is accepted only while `now - T <= maxHeadAgeMs`,
 * so it stops verifying no later than `r + maxHeadAgeMs` (plus clock skew). A head that does contain
 * it is available within `headIntervalMs`. A verifier with a pin refreshed every `pinRefreshMs`
 * rejects the older head as soon as the pin advances. Shrinking `maxHeadAgeMs` tightens the bound at
 * the cost of requiring a smaller `headIntervalMs` (frequent heartbeats). Non-finite or negative
 * inputs yield an unusable bound (Infinity, not viable).
 */
export function revocationLatencyBound(p: LatencyParams): LatencyBound {
  const ok = (x: unknown): x is number => typeof x === 'number' && Number.isFinite(x) && x >= 0;
  if (!ok(p?.maxHeadAgeMs) || !ok(p?.headIntervalMs) || (p.maxClockSkewMs !== undefined && !ok(p.maxClockSkewMs)) || (p.pinRefreshMs !== undefined && !ok(p.pinRefreshMs))) {
    return { published_ms: Infinity, unpinned_ms: Infinity, pinned_ms: Infinity, honest_provers_viable: false };
  }
  const skew = p.maxClockSkewMs ?? 0;
  const unpinned = p.maxHeadAgeMs + skew;
  return {
    published_ms: p.headIntervalMs,
    unpinned_ms: unpinned,
    pinned_ms: p.pinRefreshMs === undefined ? unpinned : Math.min(unpinned, p.pinRefreshMs),
    honest_provers_viable: p.headIntervalMs + skew < p.maxHeadAgeMs,
  };
}

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------

/**
 * Verify a cosigned head against the verifier's anchors. Returns a reason on failure; never throws.
 * Checks: shape, domain signature, k distinct pinned-witness cosignatures, freshness window (stale and
 * future-dated), and the pin rule (`checkHeadAdvance` from the pinned head, with `pinProof`).
 */
export function checkCosignedHead(ch: CosignedHead, expectedDomain: string, t: MeshTrust, pinProof?: ConsistencyProof): string | undefined {
  try {
    const h = ch?.head;
    if (!isRec(h) || h.domain !== expectedDomain) return 'head is for a different domain';
    if (!validHead(h) || !isStr(ch.sig)) return 'malformed head';
    if (!verifyB64u(h.domain, msg(HEAD_DOMAIN, h), ch.sig)) return 'head not signed by its domain key';
    if (!Array.isArray(ch.cosigs) || ch.cosigs.length > MAX_COSIGS) return 'malformed head';
    const pinned = new Set(t.witnesses);
    const good = new Set<string>();
    for (const c of ch.cosigs) {
      if (isRec(c) && isStr(c.witness) && isStr(c.sig) && pinned.has(c.witness) && !good.has(c.witness) && verifyB64u(c.witness, msg(COSIG_DOMAIN, h), c.sig)) {
        good.add(c.witness);
      }
    }
    if (good.size < t.threshold) return `head has ${good.size}/${t.threshold} trusted witness cosignatures`;
    const maxAge = t.maxHeadAgeMs ?? DEFAULT_MAX_HEAD_AGE_MS;
    const skew = t.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;
    if (h.timestamp > t.now + skew) return 'head timestamp is in the future';
    if (t.now - h.timestamp > maxAge) return 'head is stale';
    const pin = t.pinnedHeads && own(t.pinnedHeads, h.domain) ? t.pinnedHeads[h.domain] : undefined;
    if (pin) {
      const why = checkHeadAdvance(pin, h, pinProof);
      if (why) return `${why} (vs pinned head)`;
    }
    return undefined;
  } catch {
    return 'malformed head';
  }
}

function validTrust(t: MeshTrust): string | undefined {
  if (!isRec(t) || !isStr(t.humanPrincipal) || !Array.isArray(t.witnesses) || !t.witnesses.every(isStr)) return 'invalid trust configuration';
  const distinct = new Set(t.witnesses).size;
  if (!isNat(t.threshold) || t.threshold < 1 || t.threshold > distinct) return 'invalid trust configuration: threshold';
  if (!isNum(t.now)) return 'invalid trust configuration: now';
  for (const k of ['maxHeadAgeMs', 'maxClockSkewMs', 'maxActionAgeMs'] as const) {
    if (t[k] !== undefined && !(isNum(t[k]) && (t[k] as number) >= 0)) return `invalid trust configuration: ${k}`;
  }
  if (t.maxChainLength !== undefined && !(isNat(t.maxChainLength) && t.maxChainLength >= 1)) return 'invalid trust configuration: maxChainLength';
  if (t.allowedDomains !== undefined && !(Array.isArray(t.allowedDomains) && t.allowedDomains.every(isStr))) return 'invalid trust configuration: allowedDomains';
  if (t.pinnedHeads !== undefined && !isRec(t.pinnedHeads)) return 'invalid trust configuration: pinnedHeads';
  return undefined;
}

function expandNM(c: unknown, leaves: LeafProof[]): NonMembershipProof | undefined {
  if (!isRec(c) || !isNat(c.size)) return undefined;
  const out: NonMembershipProof = { size: c.size };
  for (const side of ['lo', 'hi'] as const) {
    const ix = c[side];
    if (ix === undefined) continue;
    if (!isNat(ix) || ix >= leaves.length) return undefined;
    out[side] = leaves[ix]!;
  }
  return out;
}

/**
 * Verify a mesh proof END TO END, OFFLINE. TOTAL: never throws, fails closed on any malformed input
 * (including an invalid `trust` configuration).
 *
 * 1. Shapes and bounds (chain length, table sizes), then the capability chain: signatures, hash links,
 *    holder continuity, caveats append-only, hop 0 is the expected human.
 * 2. Each referenced head is verified once: domain-signed, k distinct pinned witnesses, fresh, and
 *    (if pinned) a verified successor of the pin. Unreferenced heads are rejected.
 * 3. Per hop: head belongs to the hop's domain; the hop is included in that head's log; the issuer key
 *    is vouched by that domain (hops >= 1); neither the capability nor its issuer key is revoked as of
 *    that head.
 * 4. Monotone narrowing of effective authority hop over hop.
 * 5. The leaf action is well formed, fresh, signed by the tip holder and admitted by the final
 *    effective authority.
 */
export function verifyMeshProof(p: MeshProof, t: MeshTrust): MeshVerdict {
  const trace: HopTrace[] = [];
  const fail = (reason: string, hop?: number): MeshVerdict => ({ ok: false, reason, ...(hop !== undefined ? { hop } : {}), trace });
  try {
    const bad = validTrust(t);
    if (bad) return fail(bad);
    if (!isRec(p) || !Array.isArray(p.chain) || !Array.isArray(p.hops) || !Array.isArray(p.heads) || !Array.isArray(p.rev_leaves)) return fail('malformed proof');
    if (!isStr(p.action_sig) || !validAction(p.action)) return fail('malformed action');
    if (p.pin_proofs !== undefined && !(Array.isArray(p.pin_proofs) && p.pin_proofs.length <= MAX_COSIGS && p.pin_proofs.every((x) => isRec(x) && isStr(x.domain) && validConsistency(x.proof)))) {
      return fail('malformed pin proofs');
    }
    const chain = p.chain;
    if (chain.length < 1 || chain.length > (t.maxChainLength ?? DEFAULT_MAX_CHAIN_LENGTH)) return fail('chain length out of bounds');
    if (p.heads.length > chain.length || p.rev_leaves.length > 2 * chain.length) return fail('evidence tables exceed chain size');
    const chk = verifyChain(chain, t.humanPrincipal);
    if (!chk.ok) return fail(`chain: ${chk.reason}`);
    if (p.hops.length !== chain.length) return fail('hop evidence count does not match chain length');
    if (!p.rev_leaves.every((l) => isRec(l) && isStr(l.id) && validInclusion(l.proof))) return fail('malformed revocation leaves');

    const used = new Set<number>();
    for (const ev of p.hops) if (isRec(ev) && isNat(ev.head)) used.add(ev.head);
    if (used.size !== p.heads.length) return fail('unreferenced or missing head in evidence table');

    const headCache = new Map<number, string | undefined>();
    let prev: EffectiveAuthority | undefined;
    for (let i = 0; i < chain.length; i++) {
      const cap = chain[i]!;
      const ev = p.hops[i];
      if (!isRec(ev) || !isStr(ev.domain) || !isNat(ev.head) || ev.head >= p.heads.length || !isRec(ev.revocation)) return fail('malformed hop evidence', i);

      if (t.allowedDomains && !t.allowedDomains.includes(ev.domain)) return fail('issuing domain not allowed by policy', i);

      // (a) the issuing domain's witnessed head - the cross-org trust anchor
      const ch = p.heads[ev.head]!;
      if (!headCache.has(ev.head)) {
        const dom = isRec(ch?.head) && isStr(ch.head.domain) ? ch.head.domain : '';
        headCache.set(ev.head, checkCosignedHead(ch, dom, t, p.pin_proofs?.find((x) => x.domain === dom)?.proof));
      }
      if (ch.head.domain !== ev.domain) return fail('source-domain anchor: head is for a different domain', i);
      const headErr = headCache.get(ev.head);
      if (headErr) return fail(`source-domain anchor: ${headErr}`, i);
      const head = ch.head;

      // (b) the hop is in that domain's log
      if (!validInclusion(ev.inclusion) || ev.inclusion.size !== head.size || !verifyInclusion(head.root, ev.inclusion, capHash(cap))) {
        return fail('hop not included in the issuing domain log', i);
      }

      // (c) issuer key belongs to the issuing domain (hop 0 issuer is the human, anchored by trust)
      if (i > 0) {
        const b = ev.binding;
        if (!isRec(b) || !isStr(b.role) || !isStr(b.sig) || b.agent !== cap.issuer || b.domain !== ev.domain) return fail('missing or mismatched domain binding for issuer', i);
        if (!verifyB64u(ev.domain, msg(BINDING_DOMAIN, { agent: b.agent, domain: b.domain, role: b.role }), b.sig)) {
          return fail('domain binding signature invalid', i);
        }
      }

      // (d) revocation as of the witnessed head
      const nmCap = expandNM(ev.revocation.cap, p.rev_leaves);
      const nmKey = expandNM(ev.revocation.issuer_key, p.rev_leaves);
      if (!nmCap || !verifyNonMembership(head.rev_root, nmCap, cap.id)) return fail('capability revoked (or revocation proof invalid)', i);
      if (!nmKey || !verifyNonMembership(head.rev_root, nmKey, keyRevocationId(cap.issuer))) {
        return fail('issuer key revoked (or revocation proof invalid)', i);
      }

      // (e) monotone narrowing
      const eff = effectiveAuthority(cap.caveats);
      if ('error' in eff) return fail(eff.error, i);
      if (prev && !narrows(eff, prev)) return fail('hop widens authority', i);
      prev = eff;

      const next = p.hops[i + 1];
      trace.push({
        hop: i,
        domain: ev.domain,
        issuer: cap.issuer,
        holder: cap.holder,
        crosses_boundary: isRec(next) ? next.domain !== ev.domain : p.action.service_domain !== ev.domain,
        effective: eff,
      });
    }

    // (f) the leaf action
    const skew = t.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS;
    if (p.action.at > t.now + skew) return fail('action timestamp is in the future');
    if (t.maxActionAgeMs !== undefined && t.now - p.action.at > t.maxActionAgeMs) return fail('action is stale');
    const tip = chain[chain.length - 1]!;
    if (!verifyB64u(tip.holder, msg(ACTION_DOMAIN, { action: p.action, tip: capHash(tip) }), p.action_sig)) {
      return fail('action not signed by the chain tip holder');
    }
    const denied = admits(prev!, p.action, t.now, chain.length);
    if (denied) return fail(`action not admitted: ${denied}`);

    return { ok: true, trace, root_principal: chain[0]!.issuer, leaf: tip.holder };
  } catch {
    return fail('malformed proof');
  }
}

// ---------------------------------------------------------------------------------------------
// Worked example: human -> orchestrator (org A) -> tool agent (org B) -> service (org C)
// ---------------------------------------------------------------------------------------------

function seedKey(label: string): Uint8Array {
  return utf8(hashCanonical({ seed: `atlas-pca/mesh-example/${label}` })).slice(0, 32);
}

/** The worked example's parts, exposed so callers can build variants (revocation, widening, forks). */
export interface MeshExample {
  trust: MeshTrust;
  proof: MeshProof;
  /** Uncompacted evidence the proof was assembled from. */
  evidence: HopEvidenceInput[];
  domains: { A: MeshDomain; B: MeshDomain; C: MeshDomain };
  witnesses: MeshWitness[];
  keys: Record<'human' | 'orchestrator' | 'tool' | 'service' | 'leaf', Uint8Array>;
  chain: Capability[];
  /** A0 is A's earlier head (size 1); A its current head (size 2), cosigned only after a verified consistency proof. */
  heads: { A0: CosignedHead; A: CosignedHead; B: CosignedHead; C: CosignedHead };
  bindings: { orchestrator: DomainBinding; tool: DomainBinding; service: DomainBinding };
}

/**
 * 4 hops across 3 orgs (the human's home IdP is org A):
 *   hop 0  human        -> orchestrator  (issuer: human, logged in A)
 *   hop 1  orchestrator -> tool agent    (issuer in A, logged in A; crosses into B)
 *   hop 2  tool agent   -> service agent (issuer in B, logged in B; crosses into C)
 *   hop 3  service agent -> leaf worker  (issuer in C, logged in C)
 * The leaf then performs `payments.refund` for <= 50 under /orders/42.
 * Org A publishes two successive heads (size 1 then 2); every witness cosigns the second only after
 * verifying the RFC 9162 consistency proof between them. Hops 0 and 1 share one head in the proof.
 */
export function buildMeshExample(now = 1_800_000_000_000): MeshExample {
  const keys = {
    human: seedKey('human'),
    orchestrator: seedKey('orchestrator'),
    tool: seedKey('tool'),
    service: seedKey('service'),
    leaf: seedKey('leaf'),
  };
  const leafKey = keys.leaf;
  const pub = (s: Uint8Array) => encodeKey(publicKeyOf(s));
  const A = new MeshDomain('org-A', seedKey('domain-A'));
  const B = new MeshDomain('org-B', seedKey('domain-B'));
  const C = new MeshDomain('org-C', seedKey('domain-C'));
  const witnesses = [new MeshWitness(seedKey('witness-1')), new MeshWitness(seedKey('witness-2')), new MeshWitness(seedKey('witness-3'))];

  const root = mintRoot({
    principalSecret: keys.human,
    principalPublic: pub(keys.human),
    holder: pub(keys.orchestrator),
    caveats: [
      { type: 'scope', actions: ['payments.refund', 'payments.read', 'orders.read'] },
      { type: 'resource', prefix: '/orders/' },
      { type: 'max_amount', max: 500 },
      { type: 'expires', at: now + 3_600_000 },
      { type: 'audience', domains: [C.id] },
    ],
  });
  const c1 = delegate(root, pub(keys.tool), [{ type: 'scope', actions: ['payments.refund', 'payments.read'] }, { type: 'max_amount', max: 100 }], keys.orchestrator);
  const c2 = delegate(c1, pub(keys.service), [{ type: 'resource', prefix: '/orders/42' }, { type: 'max_hops', n: 4 }], keys.tool);
  const c3 = delegate(c2, pub(leafKey), [{ type: 'scope', actions: ['payments.refund'] }, { type: 'max_amount', max: 50 }], keys.service);
  const chain = [root, c1, c2, c3];

  A.record(root);
  const hA0 = A.publishHead(witnesses, now - 2_000);
  A.record(c1);
  const hA = A.publishHead(witnesses, now - 1_000); // size 1 -> 2: consistency-proven by every witness
  B.record(c2);
  C.record(c3);
  const hB = B.publishHead(witnesses, now - 1_000);
  const hC = C.publishHead(witnesses, now - 1_000);
  const bOrch = A.enroll(pub(keys.orchestrator), 'orchestrator');
  const bTool = B.enroll(pub(keys.tool), 'tool-agent');
  const bSvc = C.enroll(pub(keys.service), 'service-agent');

  const evidence = [A.evidence(root, hA), A.evidence(c1, hA, bOrch), B.evidence(c2, hB, bTool), C.evidence(c3, hC, bSvc)];
  const action: MeshAction = { type: 'payments.refund', resource: '/orders/42/line/1', amount: 25, service_domain: C.id, nonce: 'n-0001', at: now };
  const proof = assembleMeshProof({ chain, hops: evidence, action, leafSecret: leafKey });
  const trust: MeshTrust = {
    humanPrincipal: pub(keys.human),
    witnesses: witnesses.map((w) => w.id),
    threshold: 2,
    now,
  };
  return {
    trust,
    proof,
    evidence,
    domains: { A, B, C },
    witnesses,
    keys,
    chain,
    heads: { A0: hA0, A: hA, B: hB, C: hC },
    bindings: { orchestrator: bOrch, tool: bTool, service: bSvc },
  };
}

/** Outcome of `demonstrateForkRejection`. */
export interface ForkDemo {
  /** An honest append (consistent extension) was cosigned. */
  honest_extension_cosigned: boolean;
  /** The forked log (same key, rewritten history) was LARGER than the witness's last head... */
  fork_larger_than_prior: boolean;
  /** ...so a size-only check would have accepted it... */
  size_only_check_would_accept: boolean;
  /** ...but the real consistency proof made the witness refuse it. */
  fork_rejected: boolean;
  fork_reason: string;
}

/**
 * Worked demonstration that witnesses verify real RFC 9162 consistency: a malicious domain rewrites an
 * early log entry and grows the forked log PAST the size the witness last saw. Equal-size/size-monotone
 * checks pass; the consistency proof (necessarily computed over the forked log) does not.
 */
export function demonstrateForkRejection(): ForkDemo {
  const k = seedKey('fork-domain');
  const hk = seedKey('fork-human');
  const mk = (n: number) =>
    mintRoot({ principalSecret: hk, principalPublic: encodeKey(publicKeyOf(hk)), holder: encodeKey(publicKeyOf(hk)), caveats: [{ type: 'scope', actions: [`a${n}`] }] });
  const w = new MeshWitness(seedKey('fork-witness'));
  const honest = new MeshDomain('X', k);
  honest.record(mk(0));
  honest.record(mk(1));
  honest.publishHead([w], 100);
  honest.record(mk(2));
  let honest_ok = true;
  try {
    honest.publishHead([w], 200);
  } catch {
    honest_ok = false;
  }
  const prior = w.lastSeen(honest.id)!;
  const fork = new MeshDomain('X', k); // same key, rewritten history (entry 0 differs), grown past prior size
  for (const n of [100, 1, 2, 3]) fork.record(mk(n));
  let reason = '';
  let rejected = false;
  try {
    fork.publishHead([w], 300);
  } catch (e) {
    rejected = true;
    reason = (e as Error).message;
  }
  return {
    honest_extension_cosigned: honest_ok,
    fork_larger_than_prior: 4 > prior.size,
    size_only_check_would_accept: 4 >= prior.size,
    fork_rejected: rejected,
    fork_reason: reason,
  };
}

// =============================================================================================
// A2A FEDERATION (paradigm B5, multi-agent half): an agent from Guardian A acting on a resource
// governed by Guardian B. Three library-level, pure primitives, all fail-closed and deterministic:
//
//   1. translateCapability / verifyTranslatedCapability — cross-domain capability translation. A
//      capability chain rooted in Guardian A's grant is attenuated into a capability valid in
//      domain B. B (the bridging party) can ONLY NARROW A's authority: the translated caveat array
//      is an append-only extension of A's chain tip (verified by the SAME prefix rule as
//      `verifyChain`), the bridge signs it, and `verifyTranslatedCapability` additionally asserts
//      the translated effective authority NARROWS the source's (defence in depth, same `narrows`).
//
//   2. FederatedBudget — a consolidated trust-budget tree (risk.ts `subBudget` / `debitConsolidated`)
//      that SPANS domains. A cross-domain delegation allocates B_sub <= B_parent_remaining; a
//      sub-agent's spend debits every ancestor up to the root, so the whole delegation DAG draws on
//      ONE budget. `federatedSafetyBound` is the resulting Sigma_DAG r <= bMax/kappa bound.
//
//   3. CrossReference — a mutual-transparency linking commitment. Both Guardians anchor the SAME
//      cross-domain action digest in their own logs; the commitment binds {action, from, to} and
//      each Guardian signs its anchor, so neither can later claim a different action crossed.
// =============================================================================================

const XCAP_DOMAIN = 'atlas-pca/mesh-xcap/v1\0';
const XREF_DOMAIN = 'atlas-pca/mesh-xref/v1\0';
const XANCHOR_DOMAIN = 'atlas-pca/mesh-xanchor/v1\0';
const ACTION_DIGEST_DOMAIN = 'atlas-pca/mesh-action-digest/v1\0';

/** Deep clone a caveat array through the strict canonical form (rejects anything unhashable). */
function cloneCaveats(cs: Caveat[]): Caveat[] {
  return JSON.parse(new TextDecoder().decode(canonicalBytes(cs))) as Caveat[];
}

const isCaveatArray = (x: unknown): x is Caveat[] =>
  Array.isArray(x) && x.every((c) => isRec(c) && isStr((c as Caveat).type));

// ---------------------------------------------------------------------------------------------
// 1. Cross-domain capability translation
// ---------------------------------------------------------------------------------------------

/**
 * A capability minted in Guardian A's domain, attenuated for use in Guardian B's domain and signed
 * by the bridging party. Self-contained: carries the full source chain so it verifies offline.
 */
export interface TranslatedCapability {
  /** The source capability chain, rooted in Guardian A's grant (verified by `verifyChain`). */
  source: Capability[];
  /** Guardian A's domain id (the source authority / home domain). */
  fromGuardian: string;
  /** Guardian B's domain id (the domain this translation is valid in). */
  toGuardian: string;
  /** The bridging party's public key (b64u) — whoever signed this translation (typically B). */
  bridge: string;
  /** `capHash` of the source chain tip this translation attenuates (binds the whole source chain). */
  source_tip: string;
  /**
   * The translated caveats. APPEND-ONLY over the source tip: `source_tip.caveats` ++ B's narrowing
   * caveats. Monotone by construction (and re-checked on verify), so B can never widen A's authority.
   */
  caveats: Caveat[];
  /** epoch ms the translation was issued. */
  issued_at: number;
  /** The bridge's signature over the canonical translation body. */
  sig: string;
}

/** Arguments to {@link translateCapability}. */
export interface TranslateArgs {
  fromGuardian: string;
  toGuardian: string;
  /** Narrowing caveats B appends. Any append can only narrow (caveats are conjunctive). */
  additionalCaveats?: Caveat[];
  /** The bridging party's signing key (its public key becomes `tc.bridge`). */
  bridgeSecret: Uint8Array;
  /** epoch ms. */
  issued_at: number;
}

function xcapBody(tc: Pick<TranslatedCapability, 'fromGuardian' | 'toGuardian' | 'source_tip' | 'caveats' | 'issued_at'>) {
  return {
    v: 'atlas-pca/mesh-xcap/v1',
    from: tc.fromGuardian,
    to: tc.toGuardian,
    source_tip: tc.source_tip,
    caveats: tc.caveats,
    issued_at: tc.issued_at,
  };
}

/**
 * Translate a capability chain (rooted in Guardian A's grant) into a capability valid in Guardian
 * B's domain. The result's caveats are A's chain-tip caveats followed by B's `additionalCaveats`
 * (append-only, hence monotone narrowing), signed by `bridgeSecret`. THROWS on malformed input (an
 * invalid source chain or non-caveat `additionalCaveats`); the verification side ({@link
 * verifyTranslatedCapability}) is the total, fail-closed function.
 */
export function translateCapability(chain: Capability[], args: TranslateArgs): TranslatedCapability {
  const chk = verifyChain(chain);
  if (!chk.ok) throw new Error(`translateCapability: invalid source chain: ${chk.reason}`);
  if (args.additionalCaveats !== undefined && !isCaveatArray(args.additionalCaveats)) {
    throw new Error('translateCapability: additionalCaveats must be an array of caveats');
  }
  const tip = chain[chain.length - 1]!;
  const caveats = [...cloneCaveats(tip.caveats), ...cloneCaveats(args.additionalCaveats ?? [])];
  const source_tip = capHash(tip);
  const body = xcapBody({ fromGuardian: args.fromGuardian, toGuardian: args.toGuardian, source_tip, caveats, issued_at: args.issued_at });
  return {
    source: chain,
    fromGuardian: args.fromGuardian,
    toGuardian: args.toGuardian,
    bridge: encodeKey(publicKeyOf(args.bridgeSecret)),
    source_tip,
    caveats,
    issued_at: args.issued_at,
    sig: b64u(sign(args.bridgeSecret, msg(XCAP_DOMAIN, body))),
  };
}

/** Verifier-side expectations for a translated capability. All optional pins; omitted = unconstrained. */
export interface VerifyTranslateOptions {
  /** Require this source (Guardian A) domain id. */
  fromGuardian?: string;
  /** Require this target (Guardian B) domain id. */
  toGuardian?: string;
  /** Require this bridge key (e.g. pin the bridge to B's own key). */
  bridge?: string;
  /** Pin the source chain's root issuer (the human principal / A's grant principal). */
  rootIssuer?: string;
  /** If given, reject when the translated authority has expired by this time. */
  now?: number;
}

/** Result of {@link verifyTranslatedCapability}. Never thrown; `ok:false` always carries a `reason`. */
export interface TranslatedVerdict {
  ok: boolean;
  reason?: string;
  from?: string;
  to?: string;
  bridge?: string;
  /** The translated effective authority (on success). */
  effective?: EffectiveAuthority;
}

/**
 * The translated effective authority: conjunction of all translated caveats. Fail-closed `{error}`
 * on an unknown / malformed caveat. (Thin wrapper over `effectiveAuthority` for callers.)
 */
export function translatedEffectiveAuthority(tc: TranslatedCapability): EffectiveAuthority | { error: string } {
  if (!isRec(tc) || !isCaveatArray(tc.caveats)) return { error: 'malformed translated capability' };
  return effectiveAuthority(tc.caveats);
}

/**
 * Verify a translated capability END TO END, OFFLINE. TOTAL: never throws, fails closed on any
 * malformed input. Checks, in order:
 *  1. shape; the source chain verifies (`verifyChain`, with the optional root-issuer pin);
 *  2. the declared `fromGuardian` / `toGuardian` / `bridge` match the pins (when given), and the two
 *     guardians are distinct (a translation crosses a domain boundary);
 *  3. `source_tip` is the real `capHash` of the source chain tip (binds the whole source chain);
 *  4. APPEND-ONLY: the translated caveats start with the source tip's caveats byte-for-byte (no drop,
 *     edit or reorder) — the identical rule `verifyChain` uses for attenuation;
 *  5. the bridge signature is valid over the canonical body;
 *  6. MONOTONE: the translated effective authority narrows the source tip's (defence in depth — any
 *     loosening, even one that slipped past the prefix check, is rejected), and neither side has an
 *     unknown / malformed caveat;
 *  7. (optional) the translated authority has not expired as of `now`.
 */
export function verifyTranslatedCapability(tc: TranslatedCapability, opts: VerifyTranslateOptions = {}): TranslatedVerdict {
  const fail = (reason: string): TranslatedVerdict => ({ ok: false, reason });
  try {
    if (!isRec(tc) || !Array.isArray(tc.source) || !isStr(tc.fromGuardian) || !isStr(tc.toGuardian)) return fail('malformed translated capability');
    if (!isStr(tc.bridge) || !isStr(tc.source_tip) || !isStr(tc.sig) || !isNum(tc.issued_at) || !isCaveatArray(tc.caveats)) return fail('malformed translated capability');

    // (1) source chain
    const chk = verifyChain(tc.source, opts.rootIssuer);
    if (!chk.ok) return fail(`source chain: ${chk.reason}`);

    // (2) guardian / bridge pins
    if (opts.fromGuardian !== undefined && tc.fromGuardian !== opts.fromGuardian) return fail('source guardian mismatch');
    if (opts.toGuardian !== undefined && tc.toGuardian !== opts.toGuardian) return fail('target guardian mismatch');
    if (opts.bridge !== undefined && tc.bridge !== opts.bridge) return fail('bridge key mismatch');
    if (tc.fromGuardian === tc.toGuardian) return fail('translation does not cross a domain boundary');

    // (3) source tip binding
    const tip = tc.source[tc.source.length - 1]!;
    if (tc.source_tip !== capHash(tip)) return fail('source_tip does not match the source chain tip');

    // (4) append-only prefix over the source tip's caveats (same rule as verifyChain attenuation)
    if (tc.caveats.length < tip.caveats.length) return fail('translation drops a source caveat (widening)');
    for (let j = 0; j < tip.caveats.length; j++) {
      if (hashCanonical(tc.caveats[j]) !== hashCanonical(tip.caveats[j])) return fail(`translation altered or reordered source caveat ${j} (widening)`);
    }

    // (5) bridge signature
    const body = xcapBody({ fromGuardian: tc.fromGuardian, toGuardian: tc.toGuardian, source_tip: tc.source_tip, caveats: tc.caveats, issued_at: tc.issued_at });
    if (!verifyB64u(tc.bridge, msg(XCAP_DOMAIN, body), tc.sig)) return fail('translation not signed by the declared bridge key');

    // (6) monotone narrowing of effective authority (defence in depth; unknown caveats fail closed)
    const effS = effectiveAuthority(tip.caveats);
    if ('error' in effS) return fail(`source caveats: ${effS.error}`);
    const effT = effectiveAuthority(tc.caveats);
    if ('error' in effT) return fail(effT.error);
    if (!narrows(effT, effS)) return fail('translated authority widens the source authority');

    // (7) optional expiry
    if (opts.now !== undefined && effT.expiresAt !== undefined && opts.now > effT.expiresAt) return fail('translated capability expired');

    return { ok: true, from: tc.fromGuardian, to: tc.toGuardian, bridge: tc.bridge, effective: effT };
  } catch {
    return fail('malformed translated capability');
  }
}

// ---------------------------------------------------------------------------------------------
// 2. Consolidated cross-domain budget (the budget tree spans domains)
// ---------------------------------------------------------------------------------------------

/** One agent/hop in the federated budget tree. `B` is its CURRENT remaining budget (a local ceiling). */
export interface FederatedBudgetNode {
  domain: string;
  /** Parent node id; absent only for the root. */
  parent?: string;
  B: number;
}

/**
 * A trust-budget tree whose nodes may live in different domains. Immutable: every operation returns a
 * new state. The root holds the human-granted budget; each sub-agent holds a ceiling allocated from
 * its parent. The GLOBAL guarantee is that every spend, anywhere in the tree, also debits the root
 * (see {@link spendFederated} and {@link federatedSafetyBound}).
 */
export interface FederatedBudgetState {
  nodes: Record<string, FederatedBudgetNode>;
  root: string;
  kappa: number;
  bMax: number;
}

export type FederatedResult = { ok: true; state: FederatedBudgetState } | { ok: false; reason: string };

/** Max budget-tree depth processed (matches the chain-length DoS posture). */
const MAX_BUDGET_DEPTH = DEFAULT_MAX_CHAIN_LENGTH;

/**
 * Create a federated budget rooted at `rootId` (in `rootDomain`) with initial budget `B0 <= bMax`.
 * Fail-closed on a malformed policy or allocation.
 */
export function createFederatedBudget(args: { rootId: string; rootDomain: string; B0: number; kappa: number; bMax: number }): FederatedResult {
  if (!isRec(args) || !isStr(args.rootId) || !isStr(args.rootDomain)) return { ok: false, reason: 'malformed root' };
  if (!isNum(args.kappa) || args.kappa <= 0) return { ok: false, reason: 'kappa must be finite and > 0' };
  if (!isNum(args.bMax) || args.bMax < 0) return { ok: false, reason: 'bMax must be finite and >= 0' };
  if (!isNum(args.B0) || args.B0 < 0) return { ok: false, reason: 'B0 must be finite and >= 0' };
  if (args.B0 > args.bMax) return { ok: false, reason: 'B0 exceeds bMax' };
  return {
    ok: true,
    state: { nodes: { [args.rootId]: { domain: args.rootDomain, B: args.B0 } }, root: args.rootId, kappa: args.kappa, bMax: args.bMax },
  };
}

/**
 * Allocate a sub-agent budget: a new node `id` (in `domain`) under `parent`, with ceiling `alloc`.
 * Guarded by risk.ts `subBudget` (0 <= alloc <= parent's CURRENT remaining). The allocation is a
 * ceiling, not a reservation: it does not reduce the parent — the global bound is enforced by the
 * consolidated debit, not by the ceilings. Fail-closed on an unknown parent, a duplicate id, or an
 * allocation above the parent's remaining budget.
 */
export function allocateSub(state: FederatedBudgetState, args: { id: string; domain: string; parent: string; alloc: number }): FederatedResult {
  if (!validBudgetState(state)) return { ok: false, reason: 'malformed budget state' };
  if (!isRec(args) || !isStr(args.id) || !isStr(args.domain) || !isStr(args.parent)) return { ok: false, reason: 'malformed allocation' };
  if (own(state.nodes, args.id)) return { ok: false, reason: 'node id already exists' };
  if (!own(state.nodes, args.parent)) return { ok: false, reason: 'unknown parent' };
  const parent = state.nodes[args.parent]!;
  const sub = subBudget({ B: parent.B, tau: 0 }, args.alloc);
  if (!sub.ok) return { ok: false, reason: sub.reason };
  return { ok: true, state: { ...state, nodes: { ...state.nodes, [args.id]: { domain: args.domain, parent: args.parent, B: sub.sub.B } } } };
}

/** Path from `nodeId` up to (and including) the root, or an error. Guards against cycles / stray nodes. */
function budgetPath(state: FederatedBudgetState, nodeId: string): { ok: true; path: string[] } | { ok: false; reason: string } {
  const path: string[] = [];
  const seen = new Set<string>();
  let cur: string | undefined = nodeId;
  while (cur !== undefined) {
    if (!own(state.nodes, cur)) return { ok: false, reason: 'unknown node' };
    if (seen.has(cur)) return { ok: false, reason: 'cycle in budget tree' };
    if (path.length >= MAX_BUDGET_DEPTH) return { ok: false, reason: 'budget tree too deep' };
    seen.add(cur);
    path.push(cur);
    cur = state.nodes[cur]!.parent;
  }
  if (path[path.length - 1] !== state.root) return { ok: false, reason: 'node is not rooted at the budget root' };
  return { ok: true, path };
}

/**
 * Spend `c` at `nodeId`: debits that node AND every ancestor up to the root, each exactly once, ONLY
 * IF all of them can cover it (atomic; fail-closed with no state change otherwise). The root↔spender
 * pair is debited with risk.ts `debitConsolidated` (of which this is the DAG generalisation — for a
 * node that is a direct child of the root it IS exactly `debitConsolidated(root, node, c)`); any
 * strict-interior ancestors are debited with `debit`. Because every spend debits the root, the whole
 * delegation DAG draws on one budget: Sigma spend <= root's budget after the last recharge.
 */
export function spendFederated(state: FederatedBudgetState, nodeId: string, c: number): FederatedResult {
  if (!validBudgetState(state)) return { ok: false, reason: 'malformed budget state' };
  if (!isStr(nodeId)) return { ok: false, reason: 'malformed node id' };
  if (!isNum(c) || c < 0) return { ok: false, reason: 'spend must be finite and >= 0' };
  const p = budgetPath(state, nodeId);
  if (!p.ok) return { ok: false, reason: p.reason };
  const path = p.path;
  const rootId = state.root;
  const nodes = { ...state.nodes };

  if (nodeId === rootId) {
    const r = state.nodes[rootId]!;
    if (r.B < c) return { ok: false, reason: 'root budget insufficient' };
    nodes[rootId] = { ...r, B: debit({ B: r.B, tau: 0 }, c).B };
    return { ok: true, state: { ...state, nodes } };
  }

  // strict-interior ancestors (everything between the spender and the root)
  const interior = path.slice(1, -1);
  for (const id of interior) if (state.nodes[id]!.B < c) return { ok: false, reason: `ancestor "${id}" budget insufficient` };

  // root <-> spender: the consolidated debit (debits both iff both cover it)
  const dc = debitConsolidated({ B: state.nodes[rootId]!.B, tau: 0 }, { B: state.nodes[nodeId]!.B, tau: 0 }, c);
  if (!dc.ok) return { ok: false, reason: dc.reason };

  nodes[nodeId] = { ...state.nodes[nodeId]!, B: dc.sub.B };
  nodes[rootId] = { ...state.nodes[rootId]!, B: dc.parent.B };
  for (const id of interior) nodes[id] = { ...state.nodes[id]!, B: debit({ B: state.nodes[id]!.B, tau: 0 }, c).B };
  return { ok: true, state: { ...state, nodes } };
}

/**
 * The federated safety bound: whatever the shape of the delegation DAG and however many sub-agents
 * (across however many domains) it spans, the total risk of their collective spend between two human
 * recharges is at most `bMax / kappa`.
 *
 * Proof. Let B0 <= bMax be the ROOT budget right after a recharge. {@link spendFederated} admits a
 * spend of cost c_i = kappa·r_i only when every node on the spender→root path (the root included) has
 * budget >= c_i, and then subtracts c_i from each — in particular from the root — leaving it >= 0.
 * Nothing but a human recharge raises the root. Telescoping the root alone: Sigma c_i <= B0 <= bMax,
 * so kappa·Sigma r_i <= bMax, i.e. Sigma r_i <= bMax/kappa — the SAME guarantee as the single-agent
 * `safetyBound`, now covering the entire cross-domain swarm. (Equal to `safetyBound({bMax,kappa})`.)
 */
export function federatedSafetyBound(p: Pick<FederatedBudgetState, 'bMax' | 'kappa'>): number {
  if (!isRec(p) || !isNum(p.bMax) || !isNum(p.kappa)) return 0;
  return safetyBound(p);
}

function validBudgetState(s: unknown): s is FederatedBudgetState {
  if (!isRec(s) || !isRec(s.nodes) || !isStr(s.root) || !isNum(s.kappa) || !isNum(s.bMax)) return false;
  if (s.kappa <= 0 || s.bMax < 0) return false;
  if (!own(s.nodes, s.root)) return false;
  for (const k of Object.keys(s.nodes)) {
    const n = (s.nodes as Record<string, unknown>)[k];
    if (!isRec(n) || !isStr(n.domain) || !isNum(n.B) || n.B < 0) return false;
    if (n.parent !== undefined && !isStr(n.parent)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------------------------
// 3. Mutual transparency: the cross-reference linking commitment
// ---------------------------------------------------------------------------------------------

/** The cross-domain action both Guardians commit to in their own (separate) logs. */
export interface CrossReference {
  /** Digest of the action that crossed (e.g. {@link meshActionDigest} of a `MeshAction`, or a translated-cap id). */
  action_digest: string;
  /** Guardian A (source) domain id. */
  fromGuardian: string;
  /** Guardian B (target) domain id. */
  toGuardian: string;
  /** Replay-distinguishing nonce. */
  nonce: string;
  /** epoch ms. */
  at: number;
}

/** One Guardian's signed anchor of a cross-reference commitment into its own log. */
export interface DomainAnchor {
  /** The anchoring Guardian's domain id (public key). */
  domain: string;
  /** The cross-reference commitment this Guardian bound into its log. */
  commit: string;
  /** Opaque position in the Guardian's own log (verifier records it; does not interpret it). */
  seq: number;
  /** The Guardian's signature over {commit, seq}. */
  sig: string;
}

/** The two anchors that must agree for a cross-reference to verify. */
export interface CrossAnchors {
  from: DomainAnchor;
  to: DomainAnchor;
}

/** Result of {@link verifyCrossReference}. Never throws. */
export interface CrossRefVerdict {
  ok: boolean;
  reason?: string;
  /** The agreed commitment, on success. */
  commit?: string;
}

/** Digest of a `MeshAction` for anchoring (domain-separated, strict-canonical). */
export function meshActionDigest(action: MeshAction): string {
  return hashCanonical({ v: ACTION_DIGEST_DOMAIN, action });
}

/**
 * The cross-reference commitment: a deterministic digest of {action, from, to, nonce, at}. Both
 * Guardians anchor THIS value, so their logs provably reference the same cross-domain action.
 */
export function crossReferenceCommit(x: CrossReference): string {
  return hashCanonical({
    v: 'atlas-pca/mesh-xref/v1',
    action_digest: x.action_digest,
    from: x.fromGuardian,
    to: x.toGuardian,
    nonce: x.nonce,
    at: x.at,
  });
}

/** A Guardian signs an anchor binding `commit` at log position `seq`. */
export function anchorCrossReference(domainSecret: Uint8Array, commit: string, seq: number): DomainAnchor {
  return {
    domain: encodeKey(publicKeyOf(domainSecret)),
    commit,
    seq,
    sig: b64u(sign(domainSecret, msg(XANCHOR_DOMAIN, { commit, seq }))),
  };
}

function validAnchor(a: unknown): a is DomainAnchor {
  return isRec(a) && isStr(a.domain) && isStr(a.commit) && isNat(a.seq) && isStr(a.sig);
}

/**
 * Verify a cross-reference: both Guardians' anchors commit to the SAME action digest and are each
 * validly signed. TOTAL, fail-closed. Checks:
 *  - both guardians named in the cross-reference are distinct (it crosses a boundary);
 *  - the two anchors come from exactly those two guardians;
 *  - both anchors' `commit` equal the commitment recomputed from the cross-reference (so a mismatched
 *    link — an anchor that commits a DIFFERENT action — is rejected);
 *  - both anchor signatures verify against their guardian keys over {commit, seq}.
 */
export function verifyCrossReference(x: CrossReference, anchors: CrossAnchors): CrossRefVerdict {
  const fail = (reason: string): CrossRefVerdict => ({ ok: false, reason });
  try {
    if (!isRec(x) || !isStr(x.action_digest) || !isStr(x.fromGuardian) || !isStr(x.toGuardian) || !isStr(x.nonce) || !isNum(x.at)) return fail('malformed cross-reference');
    if (!isRec(anchors) || !validAnchor(anchors.from) || !validAnchor(anchors.to)) return fail('malformed anchors');
    if (x.fromGuardian === x.toGuardian) return fail('cross-reference must span two distinct domains');

    const expected = crossReferenceCommit(x);
    if (anchors.from.domain !== x.fromGuardian) return fail('source anchor domain does not match the cross-reference');
    if (anchors.to.domain !== x.toGuardian) return fail('target anchor domain does not match the cross-reference');
    if (anchors.from.commit !== expected) return fail('source anchor commits a different action');
    if (anchors.to.commit !== expected) return fail('target anchor commits a different action');
    if (!verifyB64u(anchors.from.domain, msg(XANCHOR_DOMAIN, { commit: anchors.from.commit, seq: anchors.from.seq }), anchors.from.sig)) return fail('source anchor signature invalid');
    if (!verifyB64u(anchors.to.domain, msg(XANCHOR_DOMAIN, { commit: anchors.to.commit, seq: anchors.to.seq }), anchors.to.sig)) return fail('target anchor signature invalid');

    return { ok: true, commit: expected };
  } catch {
    return fail('malformed cross-reference');
  }
}
