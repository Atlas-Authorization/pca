import { hashCanonical, merkleProof, merkleRoot, verifyInclusion, type InclusionProof } from '@atlasauth/pca';
import { isObj, isSafeInt, isStr, signBody, signerOf, verifyBody } from './sig';

/**
 * SIGNED POLICY BUNDLES + DECISION RECORDS (the OPA bundle / decision-log idea, with Merkle-committed records).
 *
 * A {@link PolicyBundle} pins everything a decision depends on under one monotone `revision`: the grant digests, the
 * action schema, the constitution, templates, flow rules and the minimum verifier version. It is signed k-of-n by pinned
 * keys (a FROST group key is simply a 1-of-1 signer). Every {@link DecisionRecord} cites the bundle revision AND digest,
 * is hash-chained to its predecessor and committed to a Merkle log, so an auditor can verify offline that "this denial
 * happened under revision R". Records are masked by data class before they enter the log.
 */
export const BUNDLE_DOMAIN = 'atlas-pca/policy-bundle/v1\0';
export const BUNDLE_REF_DOMAIN = 'atlas-pca/policy-bundle-ref/v1';
export const RECORD_DOMAIN = 'atlas-pca/decision-record/v1';
export const LOG_HEAD_DOMAIN = 'atlas-pca/decision-log-head/v1\0';

export interface PolicyBundleBody {
  v: 1;
  kind: 'pca-policy-bundle';
  revision: number;
  /** Digest of the previous revision's bundle (absent only for revision 1). */
  prev?: string;
  grants: string[];
  schema_digest?: string;
  constitution_digest?: string;
  template_digests: string[];
  flow_rules_digest?: string;
  /** Dotted numeric version (`0.5.0`): a verifier older than this refuses the bundle. */
  min_verifier_version: string;
  /**
   * SHADOW candidates: digests (`bundleDigest`) of candidate bundles run beside this one. This revision alone decides; each
   * candidate's answer and any divergence are recorded in the decision record (see shadow.ts). Absent: no shadow.
   */
  shadow?: string[];
  issued_at: number;
}
export interface BundleSig {
  signer: string;
  sig: string;
}
export interface PolicyBundle extends PolicyBundleBody {
  sigs: BundleSig[];
}
const MAX_LIST = 4096;
export const bundleDigest = (b: PolicyBundleBody | PolicyBundle): string => {
  const { sigs: _s, ...body } = b as PolicyBundle;
  return hashCanonical({ d: BUNDLE_REF_DOMAIN, b: body });
};
const bodyOf = (b: PolicyBundleBody | PolicyBundle): PolicyBundleBody => {
  const { sigs: _s, ...body } = b as PolicyBundle;
  return body;
};
const VERSION_RE = /^\d{1,6}(\.\d{1,6}){0,3}$/;
export function compareVersion(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}
function shapeError(b: unknown): string | null {
  if (!isObj(b) || b.v !== 1 || b.kind !== 'pca-policy-bundle') return 'not a policy bundle';
  if (!isSafeInt(b.revision) || b.revision < 1 || !isSafeInt(b.issued_at)) return 'bad revision or time';
  if (b.revision === 1 ? b.prev !== undefined : !isStr(b.prev, 128)) return 'prev must be absent at revision 1 and present after';
  if (!Array.isArray(b.grants) || b.grants.length > MAX_LIST || !b.grants.every((g) => isStr(g, 128))) return 'bad grants';
  if (!Array.isArray(b.template_digests) || b.template_digests.length > MAX_LIST || !b.template_digests.every((g) => isStr(g, 128))) return 'bad template_digests';
  for (const k of ['schema_digest', 'constitution_digest', 'flow_rules_digest']) if (b[k] !== undefined && !isStr(b[k], 128)) return `bad ${k}`;
  if (typeof b.min_verifier_version !== 'string' || !VERSION_RE.test(b.min_verifier_version)) return 'bad min_verifier_version';
  if (b.shadow !== undefined && (!Array.isArray(b.shadow) || b.shadow.length === 0 || b.shadow.length > 16 || !b.shadow.every((g) => isStr(g, 128)) || new Set(b.shadow).size !== b.shadow.length)) return 'bad shadow';
  return null;
}

/** One signer's signature over the bundle body. Collect k of them and call {@link assembleBundle}. */
export function signBundle(body: PolicyBundleBody, secret: Uint8Array): BundleSig {
  const e = shapeError(body);
  if (e) throw new RangeError(`signBundle: ${e}`);
  return { signer: signerOf(secret), sig: signBody(BUNDLE_DOMAIN, bodyOf(body), secret) };
}
export const assembleBundle = (body: PolicyBundleBody, sigs: BundleSig[]): PolicyBundle => ({ ...bodyOf(body), sigs });

export type BundleCode = 'malformed' | 'below_threshold' | 'rollback' | 'broken_chain' | 'verifier_too_old';
export type BundleVerdict = { ok: true; revision: number; digest: string; signers: string[] } | { ok: false; code: BundleCode; reason: string };
export interface VerifyBundleOptions {
  /** The pinned signer set (b64u public keys). Signatures by anyone else are ignored. */
  signers: string[];
  threshold: number;
  /** This verifier's own version, checked against `min_verifier_version`. */
  verifierVersion: string;
  /** Newest accepted revision + digest so far: a lower revision is a rollback; the next one must chain by `prev`. */
  last?: { revision: number; digest: string };
}
export function verifyBundle(b: unknown, o: VerifyBundleOptions): BundleVerdict {
  const e = shapeError(b);
  if (e) return { ok: false, code: 'malformed', reason: e };
  const bundle = b as PolicyBundle;
  if (!Array.isArray(bundle.sigs) || bundle.sigs.length > 64 || !Number.isSafeInteger(o.threshold) || o.threshold < 1) return { ok: false, code: 'malformed', reason: 'bad sigs or threshold' };
  const pinned = new Set(o.signers);
  const good = new Set<string>();
  for (const s of bundle.sigs) if (isObj(s) && pinned.has(s.signer as string) && verifyBody(BUNDLE_DOMAIN, bodyOf(bundle), s.signer as string, s.sig)) good.add(s.signer as string);
  if (good.size < o.threshold) return { ok: false, code: 'below_threshold', reason: `${good.size} valid pinned signature(s), need ${o.threshold}` };
  if (typeof o.verifierVersion !== 'string' || !VERSION_RE.test(o.verifierVersion) || compareVersion(o.verifierVersion, bundle.min_verifier_version) < 0) return { ok: false, code: 'verifier_too_old', reason: `needs verifier >= ${bundle.min_verifier_version}` };
  if (o.last) {
    if (bundle.revision < o.last.revision) return { ok: false, code: 'rollback', reason: `revision ${bundle.revision} < accepted ${o.last.revision}` };
    if (bundle.revision === o.last.revision && bundleDigest(bundle) !== o.last.digest) return { ok: false, code: 'broken_chain', reason: 'same revision, different content' };
    if (bundle.revision === o.last.revision + 1 && bundle.prev !== o.last.digest) return { ok: false, code: 'broken_chain', reason: 'prev does not chain to the accepted revision' };
  }
  return { ok: true, revision: bundle.revision, digest: bundleDigest(bundle), signers: [...good] };
}

// ---- decision records ---------------------------------------------------------------------------------------------------

export type DecisionKind = 'allow' | 'deny' | 'escalate';
export interface DecisionRecord {
  v: 1;
  seq: number;
  /** Commit of the previous record (`''` for seq 0): the hash chain. */
  prev: string;
  bundle_revision: number;
  bundle_digest: string;
  action_digest: string;
  decision: DecisionKind;
  /** The clause or witness digest that decided (item: forbid/permit witnesses). */
  witness?: string;
  assurance?: string;
  /** Digest of the consistency token the decision was made under. */
  fresh_at?: string;
  at: number;
  /** Obligations the allow carried (the PEP performs them or the allow is a deny; see `obligations` in @atlasauth/pca). */
  obligations?: { kind: string; params?: Record<string, unknown>; due?: number }[];
  /** The policy classes consulted (constitution, regulatory, org, blueprint, user) with their revisions and answers: who said no. */
  policy_classes?: { class: string; revision: number; digest: string; decision: DecisionKind }[];
  /** What each shadow candidate would have decided. Never part of the enforced decision. */
  shadow?: { digest: string; decision: DecisionKind | 'error'; diverged: boolean }[];
  /** Free fields, after masking. `classes` maps a field to its data class. */
  detail?: Record<string, unknown>;
  classes?: Record<string, string>;
}
export const recordCommit = (r: DecisionRecord): string => hashCanonical({ d: RECORD_DOMAIN, r });

/** Mask by data CLASS, not by ad-hoc path: every detail field whose class is in `maskClasses` becomes a salted-free commitment. */
export function maskRecord<T extends Omit<DecisionRecord, 'v' | 'seq' | 'prev'>>(r: T, maskClasses: string[]): T {
  if (!r.detail || !r.classes) return r;
  const detail: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(r.detail)) {
    const cls = r.classes[k];
    detail[k] = cls !== undefined && maskClasses.includes(cls) ? `masked:${cls}:${hashCanonical({ d: 'atlas-pca/mask/v1', k, v })}` : v;
  }
  return { ...r, detail };
}

export interface SignedLogHead {
  v: 1;
  size: number;
  root: string;
  last_commit: string;
  issued_at: number;
  signer: string;
  sig: string;
}
const headBody = (h: Omit<SignedLogHead, 'sig'>) => ({ ...h });
export function verifyLogHead(h: unknown, signer: string): h is SignedLogHead {
  if (!isObj(h) || h.v !== 1 || h.signer !== signer || !isSafeInt(h.size) || !isSafeInt(h.issued_at) || typeof h.root !== 'string' || typeof h.last_commit !== 'string') return false;
  const { sig, ...base } = h as unknown as SignedLogHead;
  return verifyBody(LOG_HEAD_DOMAIN, headBody(base), signer, sig);
}

/** Append-only decision log: hash-chained, Merkle-committed, with signed heads and inclusion proofs. */
export class DecisionLog {
  private readonly recs: DecisionRecord[] = [];
  constructor(private readonly secret: Uint8Array, private readonly maskClasses: string[] = []) {}
  get size(): number {
    return this.recs.length;
  }
  append(r: Omit<DecisionRecord, 'seq' | 'prev' | 'v'>): DecisionRecord {
    const masked = maskRecord(r, this.maskClasses);
    const last = this.recs[this.recs.length - 1];
    const rec: DecisionRecord = { v: 1, ...masked, seq: this.recs.length, prev: last ? recordCommit(last) : '' };
    this.recs.push(rec);
    return rec;
  }
  head(now: number): SignedLogHead {
    const last = this.recs[this.recs.length - 1];
    const base = { v: 1 as const, size: this.recs.length, root: merkleRoot(this.recs.map(recordCommit)), last_commit: last ? recordCommit(last) : '', issued_at: now, signer: signerOf(this.secret) };
    return { ...base, sig: signBody(LOG_HEAD_DOMAIN, headBody(base), this.secret) };
  }
  proof(seq: number): InclusionProof {
    return merkleProof(this.recs.map(recordCommit), seq);
  }
  slice(from: number, to: number): DecisionRecord[] {
    return this.recs.slice(from, to);
  }
}

/** Offline: this record is in the log the signed head commits to, and the head is by the pinned signer. */
export function verifyRecordInclusion(rec: DecisionRecord, proof: InclusionProof, head: unknown, signer: string): boolean {
  return verifyLogHead(head, signer) && verifyInclusion(head.root, proof, recordCommit(rec));
}

export interface DecisionBatch {
  from: number;
  records: DecisionRecord[];
  head: SignedLogHead;
}
/** Pull the next batch of at most `max` records starting at `from` (the stream cursor) with a freshly signed head. */
export function nextBatch(log: DecisionLog, from: number, max: number, now: number): DecisionBatch {
  if (!Number.isSafeInteger(from) || from < 0 || !Number.isSafeInteger(max) || max < 1) throw new RangeError('nextBatch: bad cursor or size');
  return { from, records: log.slice(from, from + max), head: log.head(now) };
}

export type BatchVerdict = { ok: true; next: number; lastCommit: string } | { ok: false; reason: string };
/**
 * Receiver side of the stream: contiguous sequence, intact hash chain from the receiver's `state`, and (when the batch
 * reaches the head) the head's last commit and size match. Returns the new cursor. Never throws.
 */
export function verifyBatch(b: DecisionBatch, state: { next: number; lastCommit: string }, signer: string): BatchVerdict {
  try {
    if (b.from !== state.next) return { ok: false, reason: `gap or replay: batch starts at ${b.from}, expected ${state.next}` };
    if (!verifyLogHead(b.head, signer)) return { ok: false, reason: 'head not signed by the pinned log signer' };
    let last = state.lastCommit;
    let n = state.next;
    for (const r of b.records) {
      if (r.seq !== n || r.prev !== last) return { ok: false, reason: `chain broken at seq ${r.seq}` };
      last = recordCommit(r);
      n++;
    }
    if (n > b.head.size) return { ok: false, reason: 'batch is longer than the signed head' };
    if (n === b.head.size && last !== b.head.last_commit) return { ok: false, reason: 'batch end does not match the signed head' };
    return { ok: true, next: n, lastCommit: last };
  } catch {
    return { ok: false, reason: 'malformed batch' };
  }
}

// ---- replay ---------------------------------------------------------------------------------------------------------------

export interface ReplayCase<I> {
  action_digest: string;
  input: I;
}
export interface ReplayChange {
  action_digest: string;
  before: DecisionKind;
  after: DecisionKind;
  direction: 'tightened' | 'widened';
}
const RANK: Record<DecisionKind, number> = { deny: 0, escalate: 1, allow: 2 };
/**
 * "What would have changed": re-run the pure decision function over recorded traffic under two bundle revisions.
 * `widened` entries are the ones to review first. Analysis tooling: it runs OUTSIDE the trusted core.
 */
export function semanticDiff<I>(cases: ReplayCase<I>[], oldDecide: (i: I) => DecisionKind, newDecide: (i: I) => DecisionKind): ReplayChange[] {
  const out: ReplayChange[] = [];
  for (const c of cases) {
    const before = oldDecide(c.input);
    const after = newDecide(c.input);
    if (before !== after) out.push({ action_digest: c.action_digest, before, after, direction: RANK[after] > RANK[before] ? 'widened' : 'tightened' });
  }
  return out;
}
/** Records whose logged decision differs from a replay under their own revision's decide function (tamper or drift). */
export function auditReplay<I>(records: DecisionRecord[], cases: ReplayCase<I>[], decide: (i: I, rev: number) => DecisionKind): DecisionRecord[] {
  const byAction = new Map(cases.map((c) => [c.action_digest, c.input] as const));
  return records.filter((r) => byAction.has(r.action_digest) && decide(byAction.get(r.action_digest) as I, r.bundle_revision) !== r.decision);
}
