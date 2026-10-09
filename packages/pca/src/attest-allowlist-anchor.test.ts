import { describe, it, expect } from 'vitest';
import {
  allowlistAnchorCommit,
  anchorAllowlistHead,
  createAllowlistAnchorLog,
  evidenceFor,
  refreshAnchorHead,
  verifyAllowlistAnchored,
  type AllowlistAnchorEntry,
  type AllowlistAnchorEvidence,
  type AnchorTrust,
} from './attest-allowlist-anchor';
import { signAllowlistManifest, verifyAllowlistManifest, type AllowlistIssuerKey, type VerifyAllowlistResult } from './attest-allowlist';
import { cosignTreeHead, signTreeHead, TransparencyLedger, ledgerRootOf, type SignedTreeHead } from './ledger';
import { generateKeyPair } from './keys';
import { b64u } from './hash';

type Ok = Extract<VerifyAllowlistResult, { ok: true }>;
const NOW = Date.parse('2026-10-09T00:00:00Z');
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

const ops = generateKeyPair();
const issuerKeys: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(ops.publicKey) } } };
const guardian = generateKeyPair();
const witnessA = generateKeyPair();
const witnessB = generateKeyPair();
const trust: AnchorTrust = { logKey: b64u(guardian.publicKey), instanceId: 'inst-1', principal: 'allowlist-log' };

function manifest(version: number, label = 'boot'): Ok {
  const m = signAllowlistManifest(
    { version, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, entries: [{ kind: 'tdx-mrtd', value: 'ab'.repeat(48), label: `${label} v${version}` }] },
    { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: ops.secretKey } },
  );
  const v = verifyAllowlistManifest(m, { issuerKeys, nowMs: NOW });
  if (!v.ok) throw new Error('setup');
  return v;
}
const newLog = () => createAllowlistAnchorLog({ instanceId: trust.instanceId, principal: trust.principal });
const sign = (t = NOW) => ({ guardianSecret: guardian.secretKey, nowMs: t });
const entryOf = (v: Ok): AllowlistAnchorEntry => ({ issuer: v.issuer, version: v.version, digest: v.digest });

describe('allowlist transparency anchor: operator + verifier happy path', () => {
  it('anchors v1..v3; a verifier with EMPTY local state accepts the latest and learns the highest anchored version', () => {
    const log = newLog();
    const [v1, v2, v3] = [manifest(1), manifest(2), manifest(3)] as [Ok, Ok, Ok];
    anchorAllowlistHead(log, v1, sign());
    anchorAllowlistHead(log, v2, sign());
    const ev3 = anchorAllowlistHead(log, v3, sign());
    const r = verifyAllowlistAnchored(v3, ev3, { trust, nowMs: NOW + HOUR });
    expect(r).toMatchObject({ ok: true, version: 3, highestAnchoredVersion: 3 });
    expect(r.ok && r.head.size).toBe(3);
  });

  it('re-anchoring the identical manifest is idempotent; the operator cannot lower a version or fork a digest', () => {
    const log = newLog();
    const v2 = manifest(2);
    anchorAllowlistHead(log, v2, sign());
    anchorAllowlistHead(log, v2, sign());
    expect(log.ledger.size).toBe(1);
    expect(() => anchorAllowlistHead(log, manifest(1), sign())).toThrow(/lower/);
    expect(() => anchorAllowlistHead(log, { ...entryOf(v2), digest: 'A'.repeat(43) }, sign())).toThrow(/different digest/);
  });

  it('a heartbeat refresh keeps an idle log fresh', () => {
    const log = newLog();
    const v1 = manifest(1);
    anchorAllowlistHead(log, v1, sign(NOW));
    const later = NOW + 3 * DAY;
    expect(verifyAllowlistAnchored(v1, evidenceFor(log, 0), { trust, nowMs: later })).toMatchObject({ ok: false, code: 'stale-head' });
    refreshAnchorHead(log, sign(later));
    expect(verifyAllowlistAnchored(v1, evidenceFor(log, 0), { trust, nowMs: later })).toMatchObject({ ok: true });
  });
});

describe('allowlist transparency anchor: rollback is rejected even with empty local state', () => {
  it('deleted local state + replay of an OLD manifest with its (still valid) proof from the current log is rejected', () => {
    const log = newLog();
    const [v1, v2] = [manifest(1), manifest(2)] as [Ok, Ok];
    anchorAllowlistHead(log, v1, sign());
    anchorAllowlistHead(log, v2, sign());
    // attacker replays manifest v1 (signature valid, unexpired) with a genuine inclusion proof under the CURRENT head
    const replay = evidenceFor(log, 0);
    const r = verifyAllowlistAnchored(v1, replay, { trust, nowMs: NOW + HOUR });
    expect(r).toMatchObject({ ok: false, code: 'anchored-rollback' });
    expect(!r.ok && r.reason).toMatch(/highest anchored 2/);
  });

  it('replaying an OLD head + old feed (hiding v2) is rejected: by freshness without state, by size with a cached head', () => {
    const log = newLog();
    const [v1, v2] = [manifest(1), manifest(2)] as [Ok, Ok];
    const ev1 = anchorAllowlistHead(log, v1, sign(NOW));
    const ev2 = anchorAllowlistHead(log, v2, sign(NOW + 2 * DAY));
    // no local state at all: the stale head is refused
    expect(verifyAllowlistAnchored(v1, ev1, { trust, nowMs: NOW + 2 * DAY + HOUR })).toMatchObject({ ok: false, code: 'stale-head' });
    // within the freshness window and still no local state: ACCEPTED - this is the documented residual window
    expect(verifyAllowlistAnchored(v1, ev1, { trust, nowMs: NOW + HOUR })).toMatchObject({ ok: true });
    // ...closed the moment the verifier has seen the newer head
    const first = verifyAllowlistAnchored(v2, ev2, { trust, nowMs: NOW + 2 * DAY + HOUR });
    if (!first.ok) throw new Error('setup');
    expect(verifyAllowlistAnchored(v1, ev1, { trust, nowMs: NOW + 2 * DAY + HOUR, maxHeadAgeMs: 10 * DAY, cachedHead: first.head })).toMatchObject({ ok: false, code: 'log-rollback' });
  });

  it('a manifest that was never anchored is rejected (including an unanchored NEWER one)', () => {
    const log = newLog();
    anchorAllowlistHead(log, manifest(1), sign());
    const v2 = manifest(2);
    const ev = evidenceFor(log, 0);
    const r = verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW + HOUR });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.code).toBe('bad-proof');
    // same version, different body (digest) than the anchored one
    const twin = manifest(1, 'twin');
    expect(verifyAllowlistAnchored(twin, ev, { trust, nowMs: NOW + HOUR })).toMatchObject({ ok: false });
  });
});

describe('allowlist transparency anchor: fail closed', () => {
  const setup = () => {
    const log = newLog();
    const [v1, v2] = [manifest(1), manifest(2)] as [Ok, Ok];
    anchorAllowlistHead(log, v1, sign());
    const ev = anchorAllowlistHead(log, v2, sign());
    return { log, v1, v2, ev };
  };

  it('missing evidence / missing proof fails closed', () => {
    const { v2, ev } = setup();
    expect(verifyAllowlistAnchored(v2, undefined, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'missing-proof' });
    const { proof: _p, ...noProof } = ev;
    expect(verifyAllowlistAnchored(v2, noProof as unknown as AllowlistAnchorEvidence, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'missing-proof' });
    expect(verifyAllowlistAnchored(v2, { ...ev, entries: undefined } as unknown as AllowlistAnchorEvidence, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'missing-proof' });
  });

  it('a proof for a different leaf / under a different root is rejected', () => {
    const { log, v2, ev } = setup();
    const wrongLeaf = { ...ev, proof: log.ledger.inclusionProof(0) };
    expect(verifyAllowlistAnchored(v2, wrongLeaf, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'bad-proof' });
    const other = newLog();
    anchorAllowlistHead(other, manifest(5), sign());
    anchorAllowlistHead(other, manifest(6), sign());
    expect(verifyAllowlistAnchored(v2, { ...ev, proof: other.ledger.inclusionProof(1) }, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'bad-proof' });
  });

  it('a head signed by another key, for another log, or timestamped in the future is rejected', () => {
    const { v2, ev } = setup();
    const evil = generateKeyPair();
    const forged = signTreeHead(evil.secretKey, { instance_id: trust.instanceId, principal: trust.principal, size: ev.head.size, root: ev.head.root, prev_root: ev.head.prev_root, timestamp: NOW });
    expect(verifyAllowlistAnchored(v2, { ...ev, head: forged }, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'bad-head' });
    expect(verifyAllowlistAnchored(v2, ev, { trust: { ...trust, principal: 'someone-else' }, nowMs: NOW })).toMatchObject({ ok: false, code: 'bad-head' });
    expect(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW - 5 * DAY })).toMatchObject({ ok: false, code: 'stale-head' });
    const tampered: SignedTreeHead = { ...ev.head, size: ev.head.size + 1 };
    expect(verifyAllowlistAnchored(v2, { ...ev, head: tampered }, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'bad-head' });
  });

  it('OMITTING an entry from the feed (hide v2 while keeping the signed head) is detected', () => {
    const { v2, ev } = setup();
    const hidden = { ...ev, entries: ev.entries.slice(0, 1) };
    expect(verifyAllowlistAnchored(v2, hidden, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'feed-mismatch' });
    const swapped = { ...ev, entries: [ev.entries[0]!, { ...ev.entries[1]!, digest: 'B'.repeat(43) }] };
    expect(verifyAllowlistAnchored(v2, swapped, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'feed-mismatch' });
  });

  it('a log that anchors two digests for one version (operator equivocation) is rejected', () => {
    const v2 = manifest(2);
    const a = entryOf(v2);
    const b: AllowlistAnchorEntry = { ...a, digest: 'C'.repeat(43) };
    const l = TransparencyLedger.fromEntries([{ commit: allowlistAnchorCommit(a) }, { commit: allowlistAnchorCommit(b) }], trust.principal);
    const head = signTreeHead(guardian.secretKey, { instance_id: trust.instanceId, principal: trust.principal, size: 2, root: l.head().root, prev_root: '', timestamp: NOW });
    expect(ledgerRootOf(l.commits())).toBe(head.root);
    const r = verifyAllowlistAnchored(v2, { head, entries: [a, b], proof: l.inclusionProof(0) }, { trust, nowMs: NOW });
    expect(r).toMatchObject({ ok: false, code: 'log-conflict' });
  });
});

describe('allowlist transparency anchor: split view / forked log', () => {
  it('two different logs signed with the same key at the same size are rejected against a cached head', () => {
    const logA = newLog();
    const logB = newLog();
    const [v1, v2] = [manifest(1), manifest(2)] as [Ok, Ok];
    anchorAllowlistHead(logA, v1, sign());
    const evA = anchorAllowlistHead(logA, v2, sign());
    // the operator shows another verifier a fork: v1' (different body, same version) then v2
    const v1x = manifest(1, 'forked');
    anchorAllowlistHead(logB, v1x, sign());
    const evB = anchorAllowlistHead(logB, v2, sign());
    expect(evA.head.size).toBe(evB.head.size);
    expect(evA.head.root).not.toBe(evB.head.root);
    const a = verifyAllowlistAnchored(v2, evA, { trust, nowMs: NOW + HOUR });
    if (!a.ok) throw new Error('setup');
    expect(verifyAllowlistAnchored(v2, evB, { trust, nowMs: NOW + HOUR, cachedHead: a.head })).toMatchObject({ ok: false, code: 'split-view' });
  });

  it('a longer log that is NOT an extension of the cached head is rejected; a valid extension is accepted', () => {
    const logA = newLog();
    const [v1, v2, v3] = [manifest(1), manifest(2), manifest(3)] as [Ok, Ok, Ok];
    anchorAllowlistHead(logA, v1, sign());
    const evA1 = anchorAllowlistHead(logA, v2, sign());
    const a = verifyAllowlistAnchored(v2, evA1, { trust, nowMs: NOW + HOUR });
    if (!a.ok) throw new Error('setup');
    // honest extension
    const evA3 = anchorAllowlistHead(logA, v3, sign());
    const withProof = evidenceFor(logA, 2, { size: a.head.size });
    expect(withProof.consistency).toBeDefined();
    expect(verifyAllowlistAnchored(v3, { ...evA3, consistency: withProof.consistency }, { trust, nowMs: NOW + HOUR, cachedHead: a.head })).toMatchObject({ ok: true, version: 3 });
    // missing consistency proof when sizes differ => fail closed
    expect(verifyAllowlistAnchored(v3, evA3, { trust, nowMs: NOW + HOUR, cachedHead: a.head })).toMatchObject({ ok: false, code: 'inconsistent-with-cache' });
    // fork: log B diverges from the first entry, then grows past the cached size
    const logB = newLog();
    anchorAllowlistHead(logB, manifest(1, 'fork'), sign());
    anchorAllowlistHead(logB, v2, sign());
    const evB3 = anchorAllowlistHead(logB, v3, sign());
    const forkProof = evidenceFor(logB, 2, { size: a.head.size }).consistency; // a consistency proof for B's own prefix
    expect(verifyAllowlistAnchored(v3, { ...evB3, consistency: forkProof }, { trust, nowMs: NOW + HOUR, cachedHead: a.head })).toMatchObject({ ok: false, code: 'inconsistent-with-cache' });
    // and a forged proof lifted from the honest log does not help against the forked head either
    expect(verifyAllowlistAnchored(v3, { ...evB3, consistency: withProof.consistency }, { trust, nowMs: NOW + HOUR, cachedHead: a.head })).toMatchObject({ ok: false, code: 'inconsistent-with-cache' });
  });

  it('a corrupt / foreign cached head is refused rather than trusted', () => {
    const log = newLog();
    const v1 = manifest(1);
    const ev = anchorAllowlistHead(log, v1, sign());
    const evil = generateKeyPair();
    const foreign = signTreeHead(evil.secretKey, { instance_id: trust.instanceId, principal: trust.principal, size: 1, root: ev.head.root, prev_root: '', timestamp: NOW });
    expect(verifyAllowlistAnchored(v1, ev, { trust, nowMs: NOW, cachedHead: foreign })).toMatchObject({ ok: false, code: 'bad-cache' });
  });

  it('witness cosignatures: a head the operator signed alone is refused when k-of-n witnesses are required', () => {
    const log = newLog();
    const v1 = manifest(1);
    const ev = anchorAllowlistHead(log, v1, sign());
    const wtrust: AnchorTrust = { ...trust, witnesses: { witnessKeys: [b64u(witnessA.publicKey), b64u(witnessB.publicKey)], threshold: 2 } };
    expect(verifyAllowlistAnchored(v1, ev, { trust: wtrust, nowMs: NOW })).toMatchObject({ ok: false, code: 'bad-head' });
    const one = { ...ev, head: { ...ev.head, witnesses: [cosignTreeHead(ev.head, witnessA.secretKey)] } };
    expect(verifyAllowlistAnchored(v1, one, { trust: wtrust, nowMs: NOW })).toMatchObject({ ok: false, code: 'bad-head' });
    const two = { ...ev, head: { ...ev.head, witnesses: [cosignTreeHead(ev.head, witnessA.secretKey), cosignTreeHead(ev.head, witnessB.secretKey)] } };
    expect(verifyAllowlistAnchored(v1, two, { trust: wtrust, nowMs: NOW })).toMatchObject({ ok: true });
    // a cosignature minted for a DIFFERENT head does not count
    const other = newLog();
    anchorAllowlistHead(other, manifest(9), sign());
    const mis = { ...ev, head: { ...ev.head, witnesses: [cosignTreeHead(other.latest()!, witnessA.secretKey), cosignTreeHead(other.latest()!, witnessB.secretKey)] } };
    expect(verifyAllowlistAnchored(v1, mis, { trust: wtrust, nowMs: NOW })).toMatchObject({ ok: false, code: 'bad-head' });
  });
});
