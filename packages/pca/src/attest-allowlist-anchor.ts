/**
 * Transparency-anchored rollback detection for signed allowlist manifests.
 *
 * PROBLEM: `verifyAllowlistManifest` rejects a manifest older than `lastSeenVersion`, but a fresh machine (or an
 * attacker who deletes the local state file) has no `lastSeenVersion`, so an old, still-unexpired manifest -
 * possibly one that allowlists a since-revoked measurement - verifies. This module moves the "highest version
 * ever issued" out of the local disk and into an append-only Merkle log (the repo's `ledger` module: RFC 6962
 * tree, RFC 9162 consistency, signed tree heads, optional C2SP-style witness cosignatures).
 *
 * OPERATOR: after signing a manifest, `anchorAllowlistHead` appends {issuer, version, manifest digest} to the log
 * and re-signs the tree head. It also refuses to anchor a version lower than one already anchored, or a second
 * digest for an already-anchored version.
 *
 * VERIFIER: `verifyAllowlistAnchored` takes the (already signature-verified) manifest plus log evidence and
 * requires ALL of: a tree head signed by the pinned log key (and, when configured, by k-of-n trusted witnesses);
 * the head is fresh (`maxHeadAgeMs`); the head extends the verifier's cached head by a valid consistency proof
 * (never shrinks, never forks at the same size); the supplied log content reproduces the signed root exactly (so
 * nothing can be omitted); an inclusion proof of THIS manifest's anchor under that root; and
 * `manifest.version >= the highest version anchored for that issuer` (equal only with the identical digest). All
 * of this works with EMPTY local state: the cached head only tightens it.
 *
 * WHAT IS GUARANTEED
 *   - Replay of an old manifest is rejected as soon as the verifier sees ANY log head newer than that manifest's
 *     anchor, even with local state deleted.
 *   - A log operator that shows different logs to different verifiers (split view) is caught when the verifier has
 *     a cached head (consistency/equal-size-root check) or when witnesses cosign (a threshold of honest witnesses
 *     never cosigns two roots at one size).
 *   - A manifest with no inclusion proof, a proof under a different root, or a head signed by a different key
 *     fails closed.
 *
 * WHAT IS NOT GUARANTEED
 *   - The log needs honest witnesses. A single log operator that is ALSO the attacker can serve a verifier with
 *     no cached head and no witness policy an old head (within `maxHeadAgeMs`) and an old feed. The freshness
 *     window bounds that replay; witnesses (`trust.witnesses`) and a persisted `cachedHead` remove it.
 *   - Freshness depends on the log operator re-signing the head periodically (`refreshAnchorHead`), and on the
 *     verifier's clock.
 *   - This binds ordering, not truth: an anchored manifest is "the operator issued this", not "this is secure".
 *   - Feed size grows with the number of manifests ever issued (small; one leaf per release).
 */
import { hashCanonical } from './hash';
import {
  TransparencyLedger,
  signTreeHead,
  verifyHeadConsistency,
  verifyLedgerInclusion,
  verifyTreeHead,
  ledgerRootOf,
  type ConsistencyProof,
  type LedgerSuiteOpts,
  type SignedTreeHead,
  type WitnessPolicy,
} from './ledger';
import type { InclusionProof } from './merkle';
import type { VerifyAllowlistResult } from './attest-allowlist';

const DOMAIN = 'pca-attest-allowlist-anchor/v1';
const B64U_DIGEST = /^[A-Za-z0-9_-]{43}$/;
const MAX_FEED = 100_000;
const DAY = 86_400_000;

/** What the operator publishes per manifest. */
export interface AllowlistAnchorEntry {
  /** The manifest issuer key id (same string as `SignedAllowlistManifest.issuer`). */
  issuer: string;
  version: number;
  /** `hashCanonical(body)` of the manifest body (the `digest` of an `ok` verification). */
  digest: string;
}

/** The leaf the log stores for an entry. Deterministic and public (nothing secret to salt). */
export function allowlistAnchorCommit(e: AllowlistAnchorEntry): string {
  return hashCanonical({ domain: DOMAIN, issuer: e.issuer, version: e.version, digest: e.digest });
}

function validEntry(e: unknown): e is AllowlistAnchorEntry {
  if (typeof e !== 'object' || e === null) return false;
  const r = e as Record<string, unknown>;
  return (
    Object.keys(r).length === 3 &&
    typeof r['issuer'] === 'string' && r['issuer'].length > 0 && r['issuer'].length <= 200 &&
    typeof r['version'] === 'number' && Number.isSafeInteger(r['version']) && r['version'] >= 1 &&
    typeof r['digest'] === 'string' && B64U_DIGEST.test(r['digest'])
  );
}

// ───────────────────────────── operator side ─────────────────────────────

/** The operator's anchor log: a TransparencyLedger of anchor commitments plus the plaintext entries behind them. */
export interface AllowlistAnchorLog {
  readonly ledger: TransparencyLedger;
  readonly instanceId: string;
  readonly principal: string;
  entries(): AllowlistAnchorEntry[];
  /** Latest signed head, if any entry was ever anchored. */
  latest(): SignedTreeHead | undefined;
}

interface MutableLog extends AllowlistAnchorLog {
  _entries: AllowlistAnchorEntry[];
  _latest: SignedTreeHead | undefined;
}

/** Create an empty anchor log. `principal` is the log id the verifier pins; `instanceId` the deployment. */
export function createAllowlistAnchorLog(init: { instanceId: string; principal: string }): AllowlistAnchorLog {
  const ledger = new TransparencyLedger(init.principal);
  const log: MutableLog = {
    ledger,
    instanceId: init.instanceId,
    principal: init.principal,
    _entries: [],
    _latest: undefined,
    entries: () => log._entries.map((e) => ({ ...e })),
    latest: () => log._latest,
  };
  return log;
}

/** Evidence a verifier needs, produced by the operator (or any mirror of the log). */
export interface AllowlistAnchorEvidence {
  head: SignedTreeHead;
  /** The complete log content up to `head` (so the verifier can recompute the signed root and the per-issuer maximum). */
  entries: AllowlistAnchorEntry[];
  /** Inclusion proof of the manifest's own anchor under `head.root`. */
  proof: InclusionProof;
  /** Consistency proof from the verifier's cached head to `head` (required when sizes differ). */
  consistency?: ConsistencyProof;
}

export interface AnchorSignOpts {
  guardianSecret: Uint8Array;
  nowMs: number;
  suite?: LedgerSuiteOpts;
}

function signHead(log: MutableLog, o: AnchorSignOpts): SignedTreeHead {
  const { size, root } = log.ledger.head();
  const sth = signTreeHead(
    o.guardianSecret,
    { instance_id: log.instanceId, principal: log.principal, size, root, prev_root: log._latest?.root ?? '', timestamp: o.nowMs },
    o.suite,
  );
  log._latest = sth;
  return sth;
}

/**
 * Anchor a verified manifest (or a bare entry) in the log and re-sign the head. THROWS if it would lower the
 * issuer's highest anchored version or give an anchored version a second digest (the operator-side mirror of the
 * verifier's checks); re-anchoring the identical entry is idempotent and returns evidence for the existing leaf.
 */
export function anchorAllowlistHead(
  log: AllowlistAnchorLog,
  what: AllowlistAnchorEntry | Extract<VerifyAllowlistResult, { ok: true }>,
  opts: AnchorSignOpts,
): AllowlistAnchorEvidence {
  const l = log as MutableLog;
  const entry: AllowlistAnchorEntry = 'body' in what ? { issuer: what.issuer, version: what.version, digest: what.digest } : { ...what };
  if (!validEntry(entry)) throw new TypeError('anchorAllowlistHead: malformed entry');
  const same = l._entries.findIndex((e) => e.issuer === entry.issuer && e.version === entry.version);
  let index: number;
  if (same >= 0) {
    if (l._entries[same]!.digest !== entry.digest) throw new Error('anchorAllowlistHead: this version is already anchored with a different digest');
    index = same;
  } else {
    const max = l._entries.filter((e) => e.issuer === entry.issuer).reduce((m, e) => Math.max(m, e.version), 0);
    if (entry.version < max) throw new Error(`anchorAllowlistHead: version ${entry.version} is lower than the anchored ${max}`);
    index = l.ledger.appendCommitment(allowlistAnchorCommit(entry)).index;
    l._entries.push(entry);
    signHead(l, opts);
  }
  if (l._latest === undefined) signHead(l, opts);
  return evidenceFor(l, index);
}

/** Re-sign the current head with a fresh timestamp (liveness heartbeat; no new entry). THROWS on an empty log. */
export function refreshAnchorHead(log: AllowlistAnchorLog, opts: AnchorSignOpts): SignedTreeHead {
  const l = log as MutableLog;
  if (l.ledger.size === 0) throw new Error('refreshAnchorHead: nothing anchored yet');
  return signHead(l, opts);
}

/** Evidence for the leaf at `index` under the log's latest head (optionally with a consistency proof from `cached`). */
export function evidenceFor(log: AllowlistAnchorLog, index: number, cached?: { size: number }): AllowlistAnchorEvidence {
  const l = log as MutableLog;
  if (l._latest === undefined) throw new Error('evidenceFor: log has no signed head');
  return {
    head: l._latest,
    entries: l.entries(),
    proof: l.ledger.inclusionProof(index),
    ...(cached !== undefined && cached.size > 0 && cached.size < l._latest.size ? { consistency: l.ledger.consistencyProof(cached.size, l._latest.size) } : {}),
  };
}

// ───────────────────────────── verifier side ─────────────────────────────

export interface AnchorTrust {
  /** b64u Ed25519 identity of the log guardian that signs tree heads. */
  logKey: string;
  instanceId: string;
  /** The log id (`principal`) the manifests are anchored in. */
  principal: string;
  /** Optional k-of-n witness cosignature requirement on the head (the anti-split-view backstop). */
  witnesses?: WitnessPolicy;
}

export interface VerifyAnchoredOptions {
  trust: AnchorTrust;
  nowMs: number;
  /** Reject heads older than this (default 24 h). Bounds replay of an old head when no cached head/witness exists. */
  maxHeadAgeMs?: number;
  clockSkewMs?: number;
  /** The head this verifier last accepted (persist `result.head`). Tightens everything; absent == first contact. */
  cachedHead?: SignedTreeHead;
}

export type AnchorErrorCode =
  | 'missing-proof'
  | 'bad-head'
  | 'stale-head'
  | 'bad-cache'
  | 'log-rollback'
  | 'split-view'
  | 'inconsistent-with-cache'
  | 'feed-mismatch'
  | 'bad-proof'
  | 'not-anchored'
  | 'anchored-rollback'
  | 'log-conflict';

export type AnchoredResult =
  | { ok: true; issuer: string; version: number; digest: string; highestAnchoredVersion: number; head: SignedTreeHead }
  | { ok: false; code: AnchorErrorCode; reason: string };

/**
 * Check a signature-verified manifest against transparency-log evidence. Never throws. `verified` must come from
 * {@link verifyAllowlistManifest}. See the module header for the exact guarantees.
 */
export function verifyAllowlistAnchored(
  verified: Extract<VerifyAllowlistResult, { ok: true }>,
  evidence: AllowlistAnchorEvidence | undefined,
  opts: VerifyAnchoredOptions,
): AnchoredResult {
  const no = (code: AnchorErrorCode, reason: string): AnchoredResult => ({ ok: false, code, reason });
  try {
    if (evidence === undefined || evidence === null || typeof evidence !== 'object' || evidence.proof === undefined || evidence.head === undefined || !Array.isArray(evidence.entries)) {
      return no('missing-proof', 'no anchor evidence (head + entries + inclusion proof) supplied');
    }
    const { trust } = opts;
    if (!Number.isSafeInteger(opts.nowMs)) return no('bad-head', 'nowMs must be an integer');
    const head = evidence.head;
    if (!verifyTreeHead(head, trust.logKey, trust.witnesses)) return no('bad-head', 'tree head is not signed by the pinned log key (or lacks the required witness cosignatures)');
    if (head.instance_id !== trust.instanceId || head.principal !== trust.principal) return no('bad-head', 'tree head is for a different log');
    const skew = Math.max(0, opts.clockSkewMs ?? 60_000);
    const maxAge = opts.maxHeadAgeMs ?? DAY;
    if (!Number.isSafeInteger(head.timestamp) || head.timestamp > opts.nowMs + skew) return no('stale-head', 'tree head is timestamped in the future');
    if (opts.nowMs - head.timestamp > maxAge) return no('stale-head', `tree head is older than maxHeadAgeMs (${maxAge})`);

    const cached = opts.cachedHead;
    if (cached !== undefined) {
      if (!verifyTreeHead(cached, trust.logKey, trust.witnesses) || cached.instance_id !== trust.instanceId || cached.principal !== trust.principal) {
        return no('bad-cache', 'the cached head does not verify under the pinned log key');
      }
      if (head.size < cached.size) return no('log-rollback', `head size ${head.size} < cached ${cached.size}: the log shrank`);
      if (head.size === cached.size) {
        if (head.root !== cached.root) return no('split-view', 'two different roots at the same size: split view / fork');
      } else {
        const c = evidence.consistency;
        if (c === undefined || !verifyHeadConsistency(cached, head, c, trust.logKey, trust.witnesses)) {
          return no('inconsistent-with-cache', 'no valid consistency proof from the cached head: forked or truncated log');
        }
      }
    }

    // The supplied content must reproduce the SIGNED root exactly: nothing omitted, nothing added.
    const entries = evidence.entries;
    if (entries.length > MAX_FEED || entries.length !== head.size || !entries.every(validEntry)) return no('feed-mismatch', 'entries do not match the signed tree size');
    const commits = entries.map(allowlistAnchorCommit);
    if (ledgerRootOf(commits) !== head.root) return no('feed-mismatch', 'entries do not reproduce the signed root');

    // Operator-equivocation scan + highest anchored version for this issuer.
    const byVersion = new Map<number, string>();
    let highest = 0;
    for (const e of entries) {
      if (e.issuer !== verified.issuer) continue;
      const prior = byVersion.get(e.version);
      if (prior !== undefined && prior !== e.digest) return no('log-conflict', `log anchors two different digests for version ${e.version}`);
      byVersion.set(e.version, e.digest);
      highest = Math.max(highest, e.version);
    }
    const mine: AllowlistAnchorEntry = { issuer: verified.issuer, version: verified.version, digest: verified.digest };
    const myCommit = allowlistAnchorCommit(mine);
    if (!verifyLedgerInclusion(head.root, evidence.proof, myCommit)) return no('bad-proof', 'inclusion proof does not place this manifest under the signed root');
    if (verified.version < highest) return no('anchored-rollback', `manifest version ${verified.version} < highest anchored ${highest} for '${verified.issuer}'`);
    if (byVersion.get(verified.version) !== verified.digest) return no('not-anchored', 'this manifest digest is not the one anchored for its version');
    return { ok: true, issuer: verified.issuer, version: verified.version, digest: verified.digest, highestAnchoredVersion: highest, head };
  } catch (e) {
    return no('bad-head', e instanceof Error ? e.message : 'anchor verification error');
  }
}

/** Convenience: the digest/hex helpers re-exported for callers that build entries by hand. */
export const anchorEntryOf = (v: Extract<VerifyAllowlistResult, { ok: true }>): AllowlistAnchorEntry => ({ issuer: v.issuer, version: v.version, digest: v.digest });
