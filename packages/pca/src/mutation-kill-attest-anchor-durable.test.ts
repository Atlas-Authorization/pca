/** 0.4.2 mutation kills: verifyAllowlistAnchored (exact reasons, option validation, fractional freshness, feed checks) and verifyAllowlistDurable (corrupt / concurrent state). */
import { describe, expect, it } from 'vitest';
import {
  allowlistAnchorCommit, anchorAllowlistHead, createAllowlistAnchorLog, evidenceFor, verifyAllowlistAnchored,
  type AllowlistAnchorEntry, type AnchorTrust,
} from './attest-allowlist-anchor';
import { signAllowlistManifest, verifyAllowlistDurable, verifyAllowlistManifest, type AllowlistIssuerKey, type VerifyAllowlistResult } from './attest-allowlist';
import { createMemoryDurableKv } from './durable-state';
import { b64u } from './hash';
import { generateKeyPair } from './keys';
import { ledgerRootOf, signTreeHead, TransparencyLedger } from './ledger';

type Ok = Extract<VerifyAllowlistResult, { ok: true }>;
const NOW = Date.parse('2026-10-09T00:00:00Z');
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const ops = generateKeyPair();
const keys: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(ops.publicKey) } } };
const guardian = generateKeyPair();
const trust: AnchorTrust = { logKey: b64u(guardian.publicKey), instanceId: 'inst-1', principal: 'allowlist-log' };
const signed = (version: number, label = 'boot') =>
  signAllowlistManifest({ version, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, entries: [{ kind: 'tdx-mrtd', value: 'ab'.repeat(48), label: `${label} v${version}` }] }, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: ops.secretKey } });
const manifest = (version: number, label?: string): Ok => {
  const v = verifyAllowlistManifest(signed(version, label), { issuerKeys: keys, nowMs: NOW });
  if (!v.ok) throw new Error('setup');
  return v;
};
const newLog = () => createAllowlistAnchorLog({ instanceId: trust.instanceId, principal: trust.principal });
const sg = (t = NOW) => ({ guardianSecret: guardian.secretKey, nowMs: t });
const why = (r: ReturnType<typeof verifyAllowlistAnchored>) => (r.ok ? 'ok' : `${r.code}: ${r.reason}`);

describe('anchored verification: exact reasons', () => {
  const setup = () => {
    const log = newLog();
    const v1 = manifest(1), v2 = manifest(2);
    anchorAllowlistHead(log, v1, sg());
    const ev = anchorAllowlistHead(log, v2, sg());
    return { log, v1, v2, ev };
  };
  it('missing evidence, wrong nowMs type', () => {
    const { v2, ev } = setup();
    expect(why(verifyAllowlistAnchored(v2, undefined, { trust, nowMs: NOW }))).toBe('missing-proof: no anchor evidence (head + entries + inclusion proof) supplied');
    expect(why(verifyAllowlistAnchored(v2, null as never, { trust, nowMs: NOW }))).toBe('missing-proof: no anchor evidence (head + entries + inclusion proof) supplied');
    expect(why(verifyAllowlistAnchored(v2, { ...ev, head: undefined } as never, { trust, nowMs: NOW }))).toBe('missing-proof: no anchor evidence (head + entries + inclusion proof) supplied');
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW + 0.5 }))).toBe('bad-head: nowMs must be an integer');
  });
  it('head problems', () => {
    const { v2, ev } = setup();
    expect(why(verifyAllowlistAnchored(v2, ev, { trust: { ...trust, principal: 'x' }, nowMs: NOW }))).toBe('bad-head: tree head is for a different log');
  });
  it('option validation: a non-finite skew or max age is refused (never silently disabling a check), with the right message', () => {
    const { v2, ev } = setup();
    for (const x of [Number.NaN, Infinity, '1']) expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW, clockSkewMs: x as never }))).toBe('bad-head: clockSkewMs must be a finite number');
    for (const x of [Number.NaN, Infinity, '1']) expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW, maxHeadAgeMs: x as never }))).toBe('bad-head: maxHeadAgeMs must be a finite number');
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW, clockSkewMs: 0, maxHeadAgeMs: DAY }))).toBe('ok');
  });
  it('head freshness boundaries, integer clock: future beyond skew, stale beyond max age (equal is fine), with the exact reasons', () => {
    const { v2, ev } = setup(); // head timestamp NOW
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW - 60_000 }))).toBe('ok'); // default skew 60 s
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW - 60_001 }))).toBe('stale-head: tree head is timestamped in the future');
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW - 1, clockSkewMs: 0 }))).toBe('stale-head: tree head is timestamped in the future');
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW + DAY }))).toBe('ok');
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW + DAY + 1 }))).toBe(`stale-head: tree head is older than maxHeadAgeMs (${DAY})`);
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW + 1001, maxHeadAgeMs: 1000 }))).toBe('stale-head: tree head is older than maxHeadAgeMs (1000)');
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW + 1000, maxHeadAgeMs: 1000 }))).toBe('ok');
  });
  it('head freshness with a fractional configuration uses the same boundaries (double arithmetic)', () => {
    const { v2, ev } = setup();
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW - 1, clockSkewMs: 1.5 }))).toBe('ok');
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW - 2, clockSkewMs: 1.5 }))).toBe('stale-head: tree head is timestamped in the future');
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW + 1000, maxHeadAgeMs: 1000.5 }))).toBe('ok');
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW + 1001, maxHeadAgeMs: 1000.5 }))).toBe('stale-head: tree head is older than maxHeadAgeMs (1000.5)');
  });
  it('a head with a non-integer timestamp is refused', () => {
    const { v2, ev } = setup();
    const head = signTreeHead(guardian.secretKey, { instance_id: trust.instanceId, principal: trust.principal, size: ev.head.size, root: ev.head.root, prev_root: ev.head.prev_root, timestamp: NOW + 0.5 });
    expect(why(verifyAllowlistAnchored(v2, { ...ev, head }, { trust, nowMs: NOW }))).toBe('stale-head: tree head is timestamped in the future');
  });
  it('cache: rollback and bad-cache reasons', () => {
    const { log, v1, v2, ev } = setup();
    const first = verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW + HOUR });
    if (!first.ok) throw new Error('setup');
    const old = evidenceFor(log, 0);
    const small = newLog();
    const sev = anchorAllowlistHead(small, v1, sg());
    expect(why(verifyAllowlistAnchored(v1, sev, { trust, nowMs: NOW + HOUR, cachedHead: first.head }))).toBe('log-rollback: head size 1 < cached 2: the log shrank');
    void old;
    const evil = generateKeyPair();
    const foreign = signTreeHead(evil.secretKey, { instance_id: trust.instanceId, principal: trust.principal, size: 2, root: ev.head.root, prev_root: '', timestamp: NOW });
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW, cachedHead: foreign }))).toBe('bad-cache: the cached head does not verify under the pinned log key');
    const otherLogCache = signTreeHead(guardian.secretKey, { instance_id: 'other', principal: trust.principal, size: 2, root: ev.head.root, prev_root: '', timestamp: NOW });
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW, cachedHead: otherLogCache }))).toBe('bad-cache: the cached head does not verify under the pinned log key');
    const otherPrincipal = signTreeHead(guardian.secretKey, { instance_id: trust.instanceId, principal: 'p2', size: 2, root: ev.head.root, prev_root: '', timestamp: NOW });
    expect(why(verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW, cachedHead: otherPrincipal }))).toBe('bad-cache: the cached head does not verify under the pinned log key');
  });
  it('split view and missing consistency proofs, exact reasons', () => {
    const { v2, ev } = setup();
    const a = verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW + HOUR });
    if (!a.ok) throw new Error('setup');
    const logB = newLog();
    anchorAllowlistHead(logB, manifest(1, 'forked'), sg());
    const evB = anchorAllowlistHead(logB, v2, sg());
    expect(why(verifyAllowlistAnchored(v2, evB, { trust, nowMs: NOW + HOUR, cachedHead: a.head }))).toBe('split-view: two different roots at the same size: split view / fork');
    const log3 = newLog();
    anchorAllowlistHead(log3, manifest(1), sg());
    anchorAllowlistHead(log3, v2, sg());
    const ev3 = anchorAllowlistHead(log3, manifest(3), sg());
    expect(why(verifyAllowlistAnchored(manifest(3), ev3, { trust, nowMs: NOW + HOUR, cachedHead: a.head }))).toBe('inconsistent-with-cache: no valid consistency proof from the cached head: forked or truncated log');
  });
  it('feed checks: size, malformed entries, root', () => {
    const { v2, ev } = setup();
    const msg = 'feed-mismatch: entries do not match the signed tree size';
    expect(why(verifyAllowlistAnchored(v2, { ...ev, entries: ev.entries.slice(0, 1) }, { trust, nowMs: NOW }))).toBe(msg);
    expect(why(verifyAllowlistAnchored(v2, { ...ev, entries: [...ev.entries, ev.entries[0]!] }, { trust, nowMs: NOW }))).toBe(msg);
    for (const bad of [null, 5, { ...ev.entries[1]!, issuer: '' }, { ...ev.entries[1]!, version: 0 }, { ...ev.entries[1]!, version: 1.5 }, { ...ev.entries[1]!, digest: 'short' }, { ...ev.entries[1]!, issuer: 'x'.repeat(201) }]) {
      expect(why(verifyAllowlistAnchored(v2, { ...ev, entries: [ev.entries[0]!, bad as never] }, { trust, nowMs: NOW })), JSON.stringify(bad)).toBe(msg);
    }
    expect(why(verifyAllowlistAnchored(v2, { ...ev, entries: [ev.entries[0]!, { ...ev.entries[1]!, digest: 'B'.repeat(43) }] }, { trust, nowMs: NOW }))).toBe('feed-mismatch: entries do not reproduce the signed root');
  });
  it('proof checks and policy results, exact reasons', () => {
    const { log, v1, v2, ev } = setup();
    expect(why(verifyAllowlistAnchored(v2, { ...ev, proof: { ...ev.proof, size: 5 } }, { trust, nowMs: NOW }))).toBe('bad-proof: inclusion proof size does not match the signed head size');
    expect(why(verifyAllowlistAnchored(v2, { ...ev, proof: log.ledger.inclusionProof(0) }, { trust, nowMs: NOW }))).toBe('bad-proof: inclusion proof does not place this manifest under the signed root');
    expect(why(verifyAllowlistAnchored(v1, evidenceFor(log, 0), { trust, nowMs: NOW }))).toBe("anchored-rollback: manifest version 1 < highest anchored 2 for 'ops'");
    const never = manifest(2, 'never anchored'); // same version as the anchored v2, different digest
    expect(why(verifyAllowlistAnchored(never, ev, { trust, nowMs: NOW }))).toMatch(/^bad-proof|^not-anchored/);
    const ok = verifyAllowlistAnchored(v2, ev, { trust, nowMs: NOW });
    expect(ok).toMatchObject({ ok: true, issuer: 'ops', version: 2, highestAnchoredVersion: 2, digest: v2.digest });
  });
  it('equivocation in the feed is a log-conflict naming the version; a conflict among OTHER issuers is not this manifest\'s problem', () => {
    const v2 = manifest(2);
    const a = entryOf(v2);
    const b: AllowlistAnchorEntry = { ...a, digest: 'C'.repeat(43) };
    const other: AllowlistAnchorEntry = { issuer: 'someone', version: 9, digest: 'D'.repeat(43) };
    const mk = (es: AllowlistAnchorEntry[], at: number) => {
      const l = TransparencyLedger.fromEntries(es.map((e) => ({ commit: allowlistAnchorCommit(e) })), trust.principal);
      const head = signTreeHead(guardian.secretKey, { instance_id: trust.instanceId, principal: trust.principal, size: es.length, root: l.head().root, prev_root: '', timestamp: NOW });
      expect(ledgerRootOf(l.commits())).toBe(head.root);
      return { head, entries: es, proof: l.inclusionProof(at) };
    };
    expect(why(verifyAllowlistAnchored(v2, mk([a, b], 0), { trust, nowMs: NOW }))).toBe('log-conflict: log anchors two different digests for version 2');
    expect(why(verifyAllowlistAnchored(v2, mk([b, a], 1), { trust, nowMs: NOW }))).toBe('log-conflict: log anchors two different digests for version 2');
    expect(why(verifyAllowlistAnchored(v2, mk([other, { ...other, digest: 'E'.repeat(43) }, a], 2), { trust, nowMs: NOW }))).toBe('ok');
  });
});
const entryOf = (v: Ok): AllowlistAnchorEntry => ({ issuer: v.issuer, version: v.version, digest: v.digest });

describe('durable verification', () => {
  const opts = { issuerKeys: keys, nowMs: NOW };
  it('a manifest with a non-string or oversized issuer is malformed before touching the store', async () => {
    const kv = createMemoryDurableKv();
    const r = await verifyAllowlistDurable({ ...signed(1), issuer: 5 }, opts, kv);
    expect(r).toEqual({ ok: false, code: 'malformed', reason: 'issuer must be a string' });
    const r2 = await verifyAllowlistDurable({ ...signed(1), issuer: 'x'.repeat(201) }, opts, kv);
    expect(r2).toMatchObject({ ok: false, code: 'malformed', reason: 'issuer must be a string' });
    expect(await verifyAllowlistDurable(null, opts, kv)).toMatchObject({ ok: false, code: 'malformed' });
    expect(await kv.keys()).toEqual([]);
  });
  it('corrupt stored state fails closed, whatever is wrong with it', async () => {
    const bads = [5, 'x', null, [], {}, { version: 1 }, { version: '1', digest: 'A'.repeat(43) }, { version: 1.5, digest: 'A'.repeat(43) }, { version: 1, digest: 5 }, { version: 1, digest: 'short' }, { version: 1, digest: 'A'.repeat(44) }];
    for (const bad of bads) {
      const kv = createMemoryDurableKv();
      await kv.set('allowlist/ops', bad);
      const r = await verifyAllowlistDurable(signed(2), opts, kv);
      expect(r, JSON.stringify(bad)).toEqual({ ok: false, code: 'malformed', reason: 'persisted allowlist high-water mark is corrupt' });
    }
  });
  it('accept advances the mark; the same body again is accepted; an older version is a rollback; same version, other body, a conflict', async () => {
    const kv = createMemoryDurableKv();
    const v3 = signed(3);
    const a = await verifyAllowlistDurable(v3, opts, kv);
    expect(a).toMatchObject({ ok: true, version: 3 });
    const stored = kv.snapshot().get('allowlist/ops') as { version: number; digest: string };
    expect(stored).toEqual({ version: 3, digest: (a as Ok).digest });
    expect(await verifyAllowlistDurable(v3, opts, kv)).toMatchObject({ ok: true, version: 3 });
    expect(await verifyAllowlistDurable(signed(2), opts, kv)).toMatchObject({ ok: false, code: 'rollback' });
    const other = await verifyAllowlistDurable(signed(3, 'other body'), opts, kv);
    expect(other).toMatchObject({ ok: false, code: 'conflict' });
    expect(await verifyAllowlistDurable(signed(4), opts, kv)).toMatchObject({ ok: true, version: 4 });
    expect((kv.snapshot().get('allowlist/ops') as { version: number }).version).toBe(4);
  });
  it('a store that answers without running the updater: the answer decides; nothing parseable stored is a concurrent-acceptance rollback', async () => {
    const mkKv = (answer: unknown) => ({ ...createMemoryDurableKv(), update: async () => answer }) as never;
    const v5 = signed(5);
    expect(await verifyAllowlistDurable(v5, opts, mkKv(undefined))).toEqual({ ok: false, code: 'rollback', reason: 'a newer manifest was accepted concurrently' });
    expect(await verifyAllowlistDurable(v5, opts, mkKv('garbage'))).toEqual({ ok: false, code: 'rollback', reason: 'a newer manifest was accepted concurrently' });
    expect(await verifyAllowlistDurable(v5, opts, mkKv({ version: 9, digest: 'A'.repeat(43) }))).toEqual({ ok: false, code: 'rollback', reason: 'a newer manifest was accepted concurrently' });
    const d = verifyAllowlistManifest(v5, { issuerKeys: keys, nowMs: NOW }) as Ok;
    expect(await verifyAllowlistDurable(v5, opts, mkKv({ version: 5, digest: d.digest }))).toMatchObject({ ok: true });
    expect(await verifyAllowlistDurable(v5, opts, mkKv({ version: 5, digest: 'B'.repeat(43) }))).toEqual({ ok: false, code: 'conflict', reason: 'same version as the stored high-water mark but a different body' });
  });
});
