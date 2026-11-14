/**
 * Builder for the allowlist-anchor conformance vectors (conformance/allowlist-anchor-vectors.json). TEST/TOOLING ONLY.
 *
 * Every vector is `{ manifest, evidence, cachedHead?, now, maxHeadAgeMs?, clockSkewMs?, expect }` where `expect` is what the
 * TypeScript reference (`verifyAllowlistAnchored`) answers: `{ ok: true, highestAnchoredVersion }` or `{ ok: false, code }`.
 * The wire level is what a native verifier must reproduce: an Ed25519-signed tree head (domain-separated canonical JSON), an
 * RFC 6962 Merkle root over the anchor commitments of the supplied entries, an inclusion proof, an RFC 9162 consistency proof
 * from a cached head, head freshness, and the per-issuer version rules. Reason strings are NOT part of the contract; the
 * `code` is. Deterministic: fixed keys, fixed clock, Ed25519 signatures.
 */
import { b64u, sha256, utf8 } from '../hash';
import { publicKeyOf } from '../keys';
import { TransparencyLedger, signTreeHead, type SignedTreeHead } from '../ledger';
import { allowlistAnchorCommit, verifyAllowlistAnchored, type AllowlistAnchorEntry, type AllowlistAnchorEvidence } from '../attest-allowlist-anchor';
import type { VerifyAllowlistResult } from '../attest-allowlist';

const seed = (n: number) => new Uint8Array(32).fill(n);
const LOG = seed(7);
const OTHER_LOG = seed(9);
export const ANCHOR_TRUST = { logKey: b64u(publicKeyOf(LOG)), instanceId: 'inst-anchor-a', principal: 'allowlist-anchor-log' };
export const ANCHOR_NOW = 1_790_000_000_000;
const MIN = 60_000;
const DAY = 86_400_000;
const dg = (n: number) => b64u(sha256(utf8(`anchor-digest-${n}`)));
const E = (issuer: string, version: number, n = version): AllowlistAnchorEntry => ({ issuer, version, digest: dg(n) });

type Json = Record<string, unknown>;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

interface Built { head: SignedTreeHead; entries: AllowlistAnchorEntry[]; ledger: TransparencyLedger }
/** A log holding exactly `entries` (as raw commitments, so conflicting/odd logs can be built), head signed at `ts`. */
function buildLog(entries: AllowlistAnchorEntry[], o: { ts?: number; secret?: Uint8Array; instanceId?: string; principal?: string; prevRoot?: string } = {}): Built {
  const ledger = new TransparencyLedger(ANCHOR_TRUST.principal);
  for (const e of entries) ledger.appendCommitment(allowlistAnchorCommit(e));
  const { size, root } = ledger.head();
  const head = signTreeHead(o.secret ?? LOG, { instance_id: o.instanceId ?? ANCHOR_TRUST.instanceId, principal: o.principal ?? ANCHOR_TRUST.principal, size, root, prev_root: o.prevRoot ?? '', timestamp: o.ts ?? ANCHOR_NOW - MIN }, undefined);
  return { head, entries, ledger };
}
const evidenceFor = (b: Built, index: number): AllowlistAnchorEvidence => ({ head: b.head, entries: b.entries, proof: b.ledger.inclusionProof(index) });

export interface AnchorVector {
  name: string;
  now: number;
  maxHeadAgeMs?: number;
  clockSkewMs?: number;
  manifest: AllowlistAnchorEntry;
  evidence: unknown;
  cachedHead?: SignedTreeHead;
  expect: { ok: true; highestAnchoredVersion: number } | { ok: false; code: string };
}

export function buildAnchorVectors(): { format: 1; suite: string; layer: 'proof'; description: string; trust: typeof ANCHOR_TRUST; allowlist_anchor: AnchorVector[] } {
  const out: AnchorVector[] = [];
  const add = (name: string, manifest: AllowlistAnchorEntry, evidence: unknown, o: { cachedHead?: SignedTreeHead; now?: number; maxHeadAgeMs?: number; clockSkewMs?: number } = {}) => {
    const now = o.now ?? ANCHOR_NOW;
    const verified = { ok: true, body: {}, issuer: manifest.issuer, alg: 'ed25519', version: manifest.version, digest: manifest.digest } as unknown as Extract<VerifyAllowlistResult, { ok: true }>;
    const r = verifyAllowlistAnchored(verified, evidence as AllowlistAnchorEvidence | undefined, {
      trust: ANCHOR_TRUST, nowMs: now,
      ...(o.maxHeadAgeMs !== undefined ? { maxHeadAgeMs: o.maxHeadAgeMs } : {}), ...(o.clockSkewMs !== undefined ? { clockSkewMs: o.clockSkewMs } : {}), ...(o.cachedHead ? { cachedHead: o.cachedHead } : {}),
    });
    out.push({
      name, now, ...(o.maxHeadAgeMs !== undefined ? { maxHeadAgeMs: o.maxHeadAgeMs } : {}), ...(o.clockSkewMs !== undefined ? { clockSkewMs: o.clockSkewMs } : {}),
      manifest, evidence: evidence === undefined ? null : clone(evidence), ...(o.cachedHead ? { cachedHead: clone(o.cachedHead) } : {}),
      expect: r.ok ? { ok: true, highestAnchoredVersion: r.highestAnchoredVersion } : { ok: false, code: r.code },
    });
  };

  const A1 = E('ops', 1), A2 = E('ops', 2), A3 = E('ops', 3), B1 = E('other-issuer', 1, 11);
  const log3 = buildLog([A1, A2, A3]);
  const log1 = buildLog([A1]);

  // ── accepted
  add('ok-single-entry', A1, evidenceFor(log1, 0));
  add('ok-latest-of-three', A3, evidenceFor(log3, 2));
  for (const n of [2, 3, 4, 5, 7, 8, 9]) {
    const es = Array.from({ length: n }, (_x, i) => E('ops', i + 1));
    const b = buildLog(es);
    add(`anchored-rollback-tree-size-${n}-first`, es[0]!, evidenceFor(b, 0));
    add(`ok-tree-size-${n}-last`, es[n - 1]!, evidenceFor(b, n - 1));
  }
  const mixed = buildLog([A1, B1, A2, E('other-issuer', 2, 12)]);
  add('ok-two-issuers-first-issuer-latest', A2, evidenceFor(mixed, 2));
  add('ok-two-issuers-second-issuer-latest', E('other-issuer', 2, 12), evidenceFor(mixed, 3));
  add('anchored-rollback-other-issuer-oldest', B1, evidenceFor(mixed, 1));
  add('ok-head-at-exact-max-age', A1, evidenceFor(buildLog([A1], { ts: ANCHOR_NOW - DAY }), 0));
  add('ok-head-exactly-skew-in-the-future', A1, evidenceFor(buildLog([A1], { ts: ANCHOR_NOW + MIN }), 0));
  add('ok-custom-max-age', A1, evidenceFor(buildLog([A1], { ts: ANCHOR_NOW - 5 * MIN }), 0), { maxHeadAgeMs: 5 * MIN });
  add('ok-zero-skew-head-at-now', A1, evidenceFor(buildLog([A1], { ts: ANCHOR_NOW }), 0), { clockSkewMs: 0 });

  // ── evidence missing / malformed
  add('missing-evidence', A1, undefined);
  const ev1 = evidenceFor(log1, 0) as unknown as Json;
  add('missing-head', A1, { ...ev1, head: undefined });
  add('missing-proof-field', A1, { ...ev1, proof: undefined });
  add('entries-not-an-array', A1, { ...ev1, entries: 'x' });

  // ── head
  const wrongKey = buildLog([A1], { secret: OTHER_LOG });
  add('bad-head-signed-by-another-key', A1, evidenceFor(wrongKey, 0));
  const tamperedRoot = clone(evidenceFor(log1, 0)); tamperedRoot.head.root = dg(99);
  add('bad-head-root-edited-after-signing', A1, tamperedRoot);
  const tamperedTs = clone(evidenceFor(log1, 0)); tamperedTs.head.timestamp += 1;
  add('bad-head-timestamp-edited-after-signing', A1, tamperedTs);
  const tamperedSize = clone(evidenceFor(log3, 2)); tamperedSize.head.size = 2;
  add('bad-head-size-edited-after-signing', A3, tamperedSize);
  add('bad-head-other-instance', A1, evidenceFor(buildLog([A1], { instanceId: 'inst-other' }), 0));
  add('bad-head-other-log-principal', A1, evidenceFor(buildLog([A1], { principal: 'other-log' }), 0));
  add('bad-head-wrong-guardian-field', A1, { ...clone(evidenceFor(log1, 0)), head: { ...clone(log1.head), guardian: b64u(publicKeyOf(OTHER_LOG)) } });
  add('bad-head-unsigned', A1, { ...clone(evidenceFor(log1, 0)), head: { ...clone(log1.head), sig: '' } });

  // ── freshness
  add('stale-head-one-ms-past-max-age', A1, evidenceFor(buildLog([A1], { ts: ANCHOR_NOW - DAY - 1 }), 0));
  add('stale-head-custom-max-age', A1, evidenceFor(buildLog([A1], { ts: ANCHOR_NOW - 5 * MIN - 1 }), 0), { maxHeadAgeMs: 5 * MIN });
  add('stale-head-future-beyond-skew', A1, evidenceFor(buildLog([A1], { ts: ANCHOR_NOW + MIN + 1 }), 0));
  add('stale-head-future-beyond-custom-skew', A1, evidenceFor(buildLog([A1], { ts: ANCHOR_NOW + 1 }), 0), { clockSkewMs: 0 });

  // ── cached head
  const h2 = buildLog([A1, A2]);
  const log4 = buildLog([A1, A2, A3, E('ops', 4)], { ts: ANCHOR_NOW - 30_000 });
  const ev4 = (idx: number, cachedSize: number): AllowlistAnchorEvidence => ({ ...evidenceFor(log4, idx), consistency: log4.ledger.consistencyProof(cachedSize, 4) });
  add('ok-cached-head-extended-by-consistency-proof', E('ops', 4), ev4(3, 2), { cachedHead: h2.head });
  add('ok-cached-head-equal', A2, evidenceFor(h2, 1), { cachedHead: h2.head });
  add('inconsistent-with-cache-no-consistency-proof', E('ops', 4), evidenceFor(log4, 3), { cachedHead: h2.head });
  const badPath = ev4(3, 2); badPath.consistency = { ...badPath.consistency!, path: [dg(70), ...badPath.consistency!.path.slice(1)] };
  add('inconsistent-with-cache-tampered-proof', E('ops', 4), badPath, { cachedHead: h2.head });
  add('bad-cache-signed-by-another-key', E('ops', 4), ev4(3, 2), { cachedHead: buildLog([A1, A2], { secret: OTHER_LOG }).head });
  add('bad-cache-other-instance', E('ops', 4), ev4(3, 2), { cachedHead: buildLog([A1, A2], { instanceId: 'inst-other' }).head });
  add('log-rollback-cached-head-is-larger', A1, evidenceFor(log1, 0), { cachedHead: h2.head });
  const fork = buildLog([A1, E('ops', 2, 222)]);
  add('split-view-same-size-different-root', A2, evidenceFor(h2, 1), { cachedHead: fork.head });
  // adjacent heads: the signed prev_root must chain
  const log3b = buildLog([A1, A2, A3], { prevRoot: h2.head.root });
  const log3bad = buildLog([A1, A2, A3], { prevRoot: dg(71) });
  const ev3 = (b: Built): AllowlistAnchorEvidence => ({ ...evidenceFor(b, 2), consistency: b.ledger.consistencyProof(2, 3) });
  add('ok-adjacent-heads-prev-root-chains', A3, ev3(log3b), { cachedHead: h2.head });
  add('inconsistent-with-cache-adjacent-heads-prev-root-does-not-chain', A3, ev3(log3bad), { cachedHead: h2.head });

  // ── the feed
  const cut = clone(evidenceFor(log3, 2)); cut.entries = cut.entries.slice(0, 2);
  add('feed-mismatch-fewer-entries-than-size', A3, cut);
  const extra = clone(evidenceFor(log3, 2)); extra.entries.push(E('ops', 4));
  add('feed-mismatch-more-entries-than-size', A3, extra);
  const altered = clone(evidenceFor(log3, 2)); altered.entries[0] = { ...altered.entries[0]!, digest: dg(55) };
  add('feed-mismatch-entry-digest-altered', A3, altered);
  const swapped = clone(evidenceFor(log3, 2)); swapped.entries = [swapped.entries[1]!, swapped.entries[0]!, swapped.entries[2]!];
  add('feed-mismatch-entries-reordered', A3, swapped);
  for (const [n, mut] of [
    ['extra-key', (e: Json) => ({ ...e, extra: 1 })], ['version-zero', (e: Json) => ({ ...e, version: 0 })], ['fractional-version', (e: Json) => ({ ...e, version: 1.5 })],
    ['short-digest', (e: Json) => ({ ...e, digest: 'abc' })], ['empty-issuer', (e: Json) => ({ ...e, issuer: '' })], ['non-string-issuer', (e: Json) => ({ ...e, issuer: 5 })],
  ] as const) {
    const bad = clone(evidenceFor(log1, 0)) as unknown as { entries: Json[] }; bad.entries[0] = mut(bad.entries[0]!);
    add(`feed-mismatch-malformed-entry-${n}`, A1, bad);
  }

  // ── inclusion proof
  const wrongSize = clone(evidenceFor(log3, 2)); wrongSize.proof.size = 4;
  add('bad-proof-size-differs-from-head', A3, wrongSize);
  const otherIdx = clone(evidenceFor(log3, 2)); otherIdx.proof = log3.ledger.inclusionProof(0);
  add('bad-proof-for-another-leaf', A3, otherIdx);
  const flipped = clone(evidenceFor(log3, 2)); flipped.proof.path[0]!.hash = dg(80);
  add('bad-proof-path-hash-edited', A3, flipped);
  const sideFlipped = clone(evidenceFor(log3, 0)); sideFlipped.proof.path[0]!.side = sideFlipped.proof.path[0]!.side === 'L' ? 'R' : 'L';
  add('bad-proof-side-flipped', A1, sideFlipped);
  const idxEdited = clone(evidenceFor(log3, 1)); idxEdited.proof.index = 0;
  add('bad-proof-index-edited', A2, idxEdited);

  // ── an empty log (size 0): nothing can be included in it
  const empty = buildLog([]);
  add('bad-proof-empty-log', A1, { head: empty.head, entries: [], proof: { index: 0, size: 1, path: [] } });
  add('feed-mismatch-entries-supplied-for-an-empty-head', A1, { head: empty.head, entries: [A1], proof: { index: 0, size: 1, path: [] } });

  // ── version rules over an authentic log
  add('anchored-rollback-older-than-highest', A1, evidenceFor(log3, 0));
  add('anchored-rollback-middle-version', A2, evidenceFor(log3, 1));
  add('bad-proof-manifest-digest-is-not-in-the-log', E('ops', 3, 333), evidenceFor(log3, 2));
  add('bad-proof-manifest-version-is-not-in-the-log', E('ops', 9), evidenceFor(log3, 2));
  add('bad-proof-manifest-issuer-is-not-in-the-log', E('stranger', 1), evidenceFor(log3, 2));
  const conflicting = buildLog([A1, E('ops', 1, 777), A2]);
  add('log-conflict-two-digests-for-one-version', A2, evidenceFor(conflicting, 2));
  add('log-conflict-the-manifest-itself-is-one-of-them', A1, evidenceFor(conflicting, 0));
  const dup = buildLog([A1, A1]);
  add('ok-identical-entry-anchored-twice-is-not-a-conflict', A1, evidenceFor(dup, 0));

  return {
    format: 1, suite: 'allowlist-anchor', layer: 'proof',
    description: 'Wire-level vectors for transparency-anchored allowlist verification: an Ed25519-signed tree head, RFC 6962 root over the anchor commitments, inclusion and RFC 9162 consistency proofs, head freshness and the per-issuer version rules. Native verifiers must reproduce `expect.ok`, `expect.code` and `expect.highestAnchoredVersion`; reason text is not part of the contract.',
    trust: ANCHOR_TRUST,
    allowlist_anchor: out,
  };
}
