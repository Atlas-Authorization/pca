/** Mutation-kill suite for attest-allowlist-anchor.ts: entry validation, operator-side bookkeeping, every verifier refusal with its code and text. */
import { describe, expect, it } from 'vitest';
import {
  allowlistAnchorCommit,
  anchorAllowlistHead,
  anchorEntryOf,
  createAllowlistAnchorLog,
  evidenceFor,
  refreshAnchorHead,
  verifyAllowlistAnchored,
  type AllowlistAnchorEntry,
  type AllowlistAnchorEvidence,
  type AnchorTrust,
} from './attest-allowlist-anchor';
import type { VerifyAllowlistResult } from './attest-allowlist';
import { signTreeHead, TransparencyLedger, ledgerRootOf } from './ledger';
import { generateKeyPair } from './keys';
import { b64u } from './hash';

type Ok = Extract<VerifyAllowlistResult, { ok: true }>;
const NOW = Date.parse('2026-10-09T00:00:00Z');
const DAY = 86_400_000;
const guardian = generateKeyPair();
const other = generateKeyPair();
const trust: AnchorTrust = { logKey: b64u(guardian.publicKey), instanceId: 'inst-1', principal: 'allowlist-log' };
const D = (c: string) => c.repeat(43);
const ent = (version: number, d = D('A'), issuer = 'ops'): AllowlistAnchorEntry => ({ issuer, version, digest: d });
const ver = (e: AllowlistAnchorEntry): Ok => ({ ok: true, issuer: e.issuer, version: e.version, digest: e.digest }) as unknown as Ok;
const sign = (t = NOW) => ({ guardianSecret: guardian.secretKey, nowMs: t });
const newLog = () => createAllowlistAnchorLog({ instanceId: trust.instanceId, principal: trust.principal });
const head = (size: number, root: string, ts = NOW, over: Record<string, unknown> = {}, key = guardian) =>
  signTreeHead(key.secretKey, { instance_id: trust.instanceId, principal: trust.principal, size, root, prev_root: '', timestamp: ts, ...over } as never);

/** Hand-built evidence for `entries`, proving `idx`, head signed at `ts`. */
function evid(entries: AllowlistAnchorEntry[], idx: number, ts = NOW, over: Record<string, unknown> = {}): AllowlistAnchorEvidence {
  const lg = new TransparencyLedger(trust.principal);
  for (const e of entries) lg.appendCommitment(allowlistAnchorCommit(e));
  const h = lg.head();
  return { head: head(h.size, h.root, ts, over), entries, proof: lg.inclusionProof(idx) };
}
const run = (e: AnchorTrust | undefined, v: Ok, ev: unknown, o: Partial<Parameters<typeof verifyAllowlistAnchored>[2]> = {}) =>
  verifyAllowlistAnchored(v, ev as never, { trust: e ?? trust, nowMs: NOW, ...o });
const fails = (r: ReturnType<typeof run>, code: string, reason: string | RegExp) => {
  expect(r.ok).toBe(false);
  if (r.ok) return;
  expect(r.code).toBe(code);
  if (typeof reason === 'string') expect(r.reason).toBe(reason);
  else expect(r.reason).toMatch(reason);
};

describe('anchorEntryOf / allowlistAnchorCommit', () => {
  it('projects exactly issuer/version/digest', () => {
    expect(anchorEntryOf({ ok: true, issuer: 'i', version: 4, digest: D('B'), body: {}, extra: 1 } as unknown as Ok)).toStrictEqual({ issuer: 'i', version: 4, digest: D('B') });
  });
  it('commit binds domain, issuer, version and digest', () => {
    const base = allowlistAnchorCommit(ent(1));
    expect(allowlistAnchorCommit(ent(1))).toBe(base);
    expect(allowlistAnchorCommit(ent(2))).not.toBe(base);
    expect(allowlistAnchorCommit(ent(1, D('B')))).not.toBe(base);
    expect(allowlistAnchorCommit(ent(1, D('A'), 'x'))).not.toBe(base);
  });
});

describe('operator: entry validation (anchorAllowlistHead)', () => {
  const bad = (e: unknown) => expect(() => anchorAllowlistHead(newLog(), e as never, sign())).toThrow(new TypeError('anchorAllowlistHead: malformed entry'));
  const good = (e: unknown) => expect(() => anchorAllowlistHead(newLog(), e as never, sign())).not.toThrow();
  it('accepts boundary values', () => {
    good(ent(1));
    good(ent(Number.MAX_SAFE_INTEGER));
    good({ issuer: 'x'.repeat(200), version: 1, digest: D('A') });
    good({ issuer: 'x', version: 1, digest: 'AZaz09_-'.repeat(5) + 'abc' });
  });
  it('refuses malformed entries', () => {
    bad({ ...ent(1), extra: 1 });
    bad({ issuer: 'ops', version: 1 });
    bad({ issuer: '', version: 1, digest: D('A') });
    bad({ issuer: 'x'.repeat(201), version: 1, digest: D('A') });
    bad({ issuer: 5, version: 1, digest: D('A') });
    bad({ issuer: ['ops'], version: 1, digest: D('A') });
    bad({ issuer: 'ops', version: 0, digest: D('A') });
    bad({ issuer: 'ops', version: -3, digest: D('A') });
    bad({ issuer: 'ops', version: 1.5, digest: D('A') });
    bad({ issuer: 'ops', version: '1', digest: D('A') });
    bad({ issuer: 'ops', version: Number.MAX_SAFE_INTEGER + 1, digest: D('A') });
    bad({ issuer: 'ops', version: 1, digest: 'A'.repeat(42) });
    bad({ issuer: 'ops', version: 1, digest: 'A'.repeat(44) });
    bad({ issuer: 'ops', version: 1, digest: 'A'.repeat(42) + '+' });
    bad({ issuer: 'ops', version: 1, digest: [D('A')] });
    bad({ issuer: 'ops', version: 1, digest: 5 });
  });
  it('per-issuer monotonicity; issuers are independent; idempotent re-anchor', () => {
    const log = newLog();
    anchorAllowlistHead(log, ent(5, D('A'), 'a'), sign());
    anchorAllowlistHead(log, ent(1, D('B'), 'b'), sign()); // lower than a's max, fine for b
    anchorAllowlistHead(log, ent(6, D('C'), 'a'), sign());
    expect(() => anchorAllowlistHead(log, ent(4, D('D'), 'a'), sign())).toThrow(new Error('anchorAllowlistHead: version 4 is lower than the anchored 6'));
    expect(() => anchorAllowlistHead(log, ent(6, D('E'), 'a'), sign())).toThrow(new Error('anchorAllowlistHead: this version is already anchored with a different digest'));
    expect(log.entries()).toEqual([ent(5, D('A'), 'a'), ent(1, D('B'), 'b'), ent(6, D('C'), 'a')]);
    const before = log.ledger.size;
    const ev = anchorAllowlistHead(log, ent(5, D('A'), 'a'), sign());
    expect(log.ledger.size).toBe(before);
    expect(ev.proof.index).toBe(0);
    expect(ev.entries.length).toBe(3);
    // entries() returns copies
    log.entries()[0]!.version = 99;
    expect(log.entries()[0]!.version).toBe(5);
  });
  it('accepts a verified-manifest-shaped argument (has body)', () => {
    const log = newLog();
    anchorAllowlistHead(log, { ...ver(ent(2)), body: {} } as unknown as Ok, sign());
    expect(log.entries()).toEqual([ent(2)]);
  });
  it('heads chain via prev_root and carry instance/principal/timestamp/size', () => {
    const log = newLog();
    expect(log.latest()).toBeUndefined();
    anchorAllowlistHead(log, ent(1), sign(NOW));
    const h1 = log.latest()!;
    expect(h1).toMatchObject({ instance_id: 'inst-1', principal: 'allowlist-log', size: 1, prev_root: '', timestamp: NOW });
    anchorAllowlistHead(log, ent(2), sign(NOW + 5));
    const h2 = log.latest()!;
    expect(h2).toMatchObject({ size: 2, prev_root: h1.root, timestamp: NOW + 5 });
    refreshAnchorHead(log, sign(NOW + 9));
    expect(log.latest()).toMatchObject({ size: 2, prev_root: h2.root, root: h2.root, timestamp: NOW + 9 });
  });
  it('refresh / evidence on an empty log', () => {
    expect(() => refreshAnchorHead(newLog(), sign())).toThrow(new Error('refreshAnchorHead: nothing anchored yet'));
    expect(() => evidenceFor(newLog(), 0)).toThrow(new Error('evidenceFor: log has no signed head'));
  });
  it('evidenceFor attaches a consistency proof only for 0 < cached.size < latest.size', () => {
    const log = newLog();
    for (const v of [1, 2, 3]) anchorAllowlistHead(log, ent(v), sign());
    expect('consistency' in evidenceFor(log, 0)).toBe(false);
    expect('consistency' in evidenceFor(log, 0, { size: 0 })).toBe(false);
    expect('consistency' in evidenceFor(log, 0, { size: 3 })).toBe(false);
    expect('consistency' in evidenceFor(log, 0, { size: 4 })).toBe(false);
    const c = evidenceFor(log, 0, { size: 1 }).consistency!;
    expect(c).toMatchObject({ oldSize: 1, newSize: 3 });
    expect(evidenceFor(log, 2, { size: 2 }).consistency).toMatchObject({ oldSize: 2, newSize: 3 });
  });
});

describe('verifier: evidence shape and head checks', () => {
  const v1 = ver(ent(1));
  const good = () => evid([ent(1)], 0);
  it('accepts the good path with exact result fields', () => {
    const ev = good();
    const r = run(undefined, v1, ev);
    expect(r).toEqual({ ok: true, issuer: 'ops', version: 1, digest: D('A'), highestAnchoredVersion: 1, head: ev.head });
  });
  it('missing evidence variants', () => {
    const m = 'no anchor evidence (head + entries + inclusion proof) supplied';
    const g = good();
    for (const ev of [undefined, null, {}, { ...g, proof: undefined }, { ...g, head: undefined }, { ...g, entries: 'x' }, { ...g, entries: undefined }]) fails(run(undefined, v1, ev), 'missing-proof', m);
    fails(run(undefined, v1, 5), 'missing-proof', m);
  });
  it('nowMs must be an integer', () => {
    for (const nowMs of [NOW + 0.5, NaN, Infinity]) fails(run(undefined, v1, good(), { nowMs }), 'bad-head', 'nowMs must be an integer');
  });
  it('head signature / log identity', () => {
    const sigMsg = 'tree head is not signed by the pinned log key (or lacks the required witness cosignatures)';
    const e = good();
    fails(run(undefined, v1, { ...e, head: head(1, e.head.root, NOW, {}, other) }), 'bad-head', sigMsg);
    fails(run(undefined, v1, { ...e, head: { ...e.head, size: 2 } }), 'bad-head', sigMsg);
    fails(run(undefined, v1, evid([ent(1)], 0, NOW, { instance_id: 'inst-2' })), 'bad-head', 'tree head is for a different log');
    fails(run(undefined, v1, evid([ent(1)], 0, NOW, { principal: 'other-log' })), 'bad-head', 'tree head is for a different log');
    fails(run({ ...trust, instanceId: 'x' }, v1, good()), 'bad-head', 'tree head is for a different log');
    fails(run({ ...trust, principal: 'x' }, v1, good()), 'bad-head', 'tree head is for a different log');
  });
  it('clock skew boundaries (default 60 s, custom, negative clamps to 0)', () => {
    const fut = 'tree head is timestamped in the future';
    expect(run(undefined, v1, evid([ent(1)], 0, NOW + 60_000)).ok).toBe(true);
    fails(run(undefined, v1, evid([ent(1)], 0, NOW + 60_001)), 'stale-head', fut);
    expect(run(undefined, v1, evid([ent(1)], 0, NOW + 5), { clockSkewMs: 5 }).ok).toBe(true);
    fails(run(undefined, v1, evid([ent(1)], 0, NOW + 6), { clockSkewMs: 5 }), 'stale-head', fut);
    expect(run(undefined, v1, evid([ent(1)], 0, NOW), { clockSkewMs: -100 }).ok).toBe(true);
    fails(run(undefined, v1, evid([ent(1)], 0, NOW + 1), { clockSkewMs: -100 }), 'stale-head', fut);
    expect(run(undefined, v1, evid([ent(1)], 0, NOW), { clockSkewMs: 0 }).ok).toBe(true);
    fails(run(undefined, v1, evid([ent(1)], 0, 1.5)), 'stale-head', fut);
  });
  it('head age boundary (default 24 h, custom)', () => {
    expect(run(undefined, v1, evid([ent(1)], 0, NOW - DAY)).ok).toBe(true);
    fails(run(undefined, v1, evid([ent(1)], 0, NOW - DAY - 1)), 'stale-head', `tree head is older than maxHeadAgeMs (${DAY})`);
    expect(run(undefined, v1, evid([ent(1)], 0, NOW - 1000), { maxHeadAgeMs: 1000 }).ok).toBe(true);
    fails(run(undefined, v1, evid([ent(1)], 0, NOW - 1001), { maxHeadAgeMs: 1000 }), 'stale-head', 'tree head is older than maxHeadAgeMs (1000)');
  });
});

describe('verifier: cached head', () => {
  const v1 = ver(ent(1));
  const e2 = [ent(1), ent(2)];
  it('equal size + equal root passes; different root is a split view', () => {
    const ev = evid([ent(1)], 0);
    expect(run(undefined, v1, ev, { cachedHead: ev.head }).ok).toBe(true);
    const fork = evid([ent(1, D('B'))], 0);
    fails(run(undefined, v1, ev, { cachedHead: fork.head }), 'split-view', 'two different roots at the same size: split view / fork');
  });
  it('a cached head must verify under the pinned key and name this log', () => {
    const ev = evid([ent(1)], 0);
    const m = 'the cached head does not verify under the pinned log key';
    fails(run(undefined, v1, ev, { cachedHead: head(1, ev.head.root, NOW, {}, other) }), 'bad-cache', m);
    fails(run(undefined, v1, ev, { cachedHead: head(1, ev.head.root, NOW, { instance_id: 'nope' }) }), 'bad-cache', m);
    fails(run(undefined, v1, ev, { cachedHead: head(1, ev.head.root, NOW, { principal: 'nope' }) }), 'bad-cache', m);
  });
  it('shrinking log', () => {
    const big = evid(e2, 1);
    const small = evid([ent(1)], 0);
    fails(run(undefined, v1, small, { cachedHead: big.head }), 'log-rollback', 'head size 1 < cached 2: the log shrank');
  });
  it('growth needs a valid consistency proof', () => {
    const log = newLog();
    anchorAllowlistHead(log, ent(1), sign());
    const cached = log.latest()!;
    const ev2 = anchorAllowlistHead(log, ent(2), sign());
    const m = 'no valid consistency proof from the cached head: forked or truncated log';
    const v2 = ver(ent(2));
    fails(run(undefined, v2, ev2, { cachedHead: cached }), 'inconsistent-with-cache', m);
    const withProof = evidenceFor(log, 1, { size: 1 });
    expect(run(undefined, v2, withProof, { cachedHead: cached }).ok).toBe(true);
    // a proof between the wrong sizes / a forked cache is refused
    const fork = newLog();
    anchorAllowlistHead(fork, ent(1, D('Z')), sign());
    fails(run(undefined, v2, withProof, { cachedHead: fork.latest()! }), 'inconsistent-with-cache', m);
  });
});

describe('verifier: feed, conflicts, inclusion', () => {
  it('entries must match the signed size and be valid', () => {
    const m = 'entries do not match the signed tree size';
    const ev = evid([ent(1), ent(2)], 1);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(1)] }), 'feed-mismatch', m);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(1), ent(2), ent(3)] }), 'feed-mismatch', m);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(1), { ...ent(2), extra: 1 }] }), 'feed-mismatch', m);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(1), null] }), 'feed-mismatch', m);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(1), 7] }), 'feed-mismatch', m);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [{ issuer: ['ops'], version: 2, digest: D('A') }, ent(1)] }), 'feed-mismatch', m);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(1), { issuer: 'ops', version: 0, digest: D('A') }] }), 'feed-mismatch', m);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(1), { issuer: 'ops', version: 2, digest: [D('A')] }] }), 'feed-mismatch', m);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(1), { issuer: '', version: 2, digest: D('A') }] }), 'feed-mismatch', m);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(1), { issuer: 'x'.repeat(201), version: 2, digest: D('A') }] }), 'feed-mismatch', m);
  });
  it('entries must reproduce the signed root', () => {
    const ev = evid([ent(1), ent(2)], 1);
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(1), ent(2, D('B'))] }), 'feed-mismatch', 'entries do not reproduce the signed root');
    fails(run(undefined, ver(ent(2)), { ...ev, entries: [ent(2), ent(1)] }), 'feed-mismatch', 'entries do not reproduce the signed root');
  });
  it('MAX_FEED = 100000: 100000 entries are processed, 100001 refused', () => {
    const mk = (n: number) => Array.from({ length: n }, (_, i) => ({ issuer: `i${i}`, version: 1, digest: D('A') }));
    const big = mk(100_001);
    const root = ledgerRootOf(big.map(allowlistAnchorCommit));
    const ev = { head: head(100_001, root), entries: big, proof: { index: 0, size: 100_001, path: [] } };
    fails(run(undefined, ver(big[0]!), ev), 'feed-mismatch', 'entries do not match the signed tree size');
    const ok = mk(100_000);
    const lg = new TransparencyLedger(trust.principal);
    for (const e of ok) lg.appendCommitment(allowlistAnchorCommit(e));
    const h = lg.head();
    const r = run(undefined, ver(ok[7]!), { head: head(h.size, h.root), entries: ok, proof: lg.inclusionProof(7) });
    expect(r.ok).toBe(true);
  }, 120_000);
  it('operator equivocation within a version is a log-conflict; an identical duplicate is not', () => {
    const entries = [ent(1, D('A')), ent(1, D('B'))];
    fails(run(undefined, ver(entries[0]!), evid(entries, 0)), 'log-conflict', 'log anchors two different digests for version 1');
    const dup = [ent(1), ent(1)];
    expect(run(undefined, ver(ent(1)), evid(dup, 0)).ok).toBe(true);
    // other issuers' entries do not conflict
    expect(run(undefined, ver(ent(1)), evid([ent(1), ent(1, D('B'), 'zzz')], 0)).ok).toBe(true);
  });
  it('proof size is bound to the head; the proof must place THIS manifest', () => {
    const ev = evid([ent(1), ent(2)], 1);
    fails(run(undefined, ver(ent(2)), { ...ev, proof: { ...ev.proof, size: 3 } }), 'bad-proof', 'inclusion proof size does not match the signed head size');
    fails(run(undefined, ver(ent(2)), { ...ev, proof: evid([ent(1), ent(2)], 0).proof }), 'bad-proof', 'inclusion proof does not place this manifest under the signed root');
    fails(run(undefined, ver(ent(2, D('B'))), ev), 'bad-proof', 'inclusion proof does not place this manifest under the signed root');
  });
  it('rollback against the highest anchored version of the same issuer', () => {
    const ev = evid([ent(1), ent(2)], 0);
    fails(run(undefined, ver(ent(1)), ev), 'anchored-rollback', "manifest version 1 < highest anchored 2 for 'ops'");
    // a higher version of ANOTHER issuer does not affect this issuer
    expect(run(undefined, ver(ent(1)), evid([ent(1), ent(9, D('B'), 'other')], 0))).toMatchObject({ ok: true, highestAnchoredVersion: 1 });
    expect(run(undefined, ver(ent(2)), evid([ent(1), ent(2)], 1))).toMatchObject({ ok: true, highestAnchoredVersion: 2 });
  });
  it('an internal failure is reported as bad-head with the error text', () => {
    const ev = evid([ent(1)], 0);
    const r = run(undefined, ver(ent(1)), { ...ev, proof: null });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe('bad-head');
      expect(r.reason).toMatch(/null/);
    }
  });
});
