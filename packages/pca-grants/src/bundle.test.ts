import { describe, expect, it } from 'vitest';
import { generateKeyPair, verifyInclusion } from '@atlasauth/pca';
import {
  DecisionLog, assembleBundle, auditReplay, bundleDigest, compareVersion, maskRecord, nextBatch, recordCommit, semanticDiff, signBundle, verifyBatch,
  verifyBundle, verifyLogHead, verifyRecordInclusion, type DecisionRecord, type PolicyBundleBody,
} from './bundle';
import { signerOf } from './sig';

const [a, b, c] = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
const pins = [a, b, c].map((k) => signerOf(k.secretKey));
const body = (over: Partial<PolicyBundleBody> = {}): PolicyBundleBody => ({
  v: 1, kind: 'pca-policy-bundle', revision: 1, grants: ['g1'], template_digests: [], min_verifier_version: '0.5.0', issued_at: 1, ...over,
});
const opt = (over = {}) => ({ signers: pins, threshold: 2, verifierVersion: '0.5.0', ...over });

describe('policy bundles', () => {
  it('accepts k-of-n distinct pinned signatures and reports who signed', () => {
    const bd = body();
    const bun = assembleBundle(bd, [signBundle(bd, a.secretKey), signBundle(bd, c.secretKey)]);
    expect(verifyBundle(bun, opt())).toEqual({ ok: true, revision: 1, digest: bundleDigest(bun), signers: [pins[0], pins[2]] });
  });
  it('one signer twice, an unpinned signer, or a signature over other content do not count', () => {
    const bd = body();
    const s = signBundle(bd, a.secretKey);
    expect(verifyBundle(assembleBundle(bd, [s, s]), opt())).toMatchObject({ ok: false, code: 'below_threshold' });
    expect(verifyBundle(assembleBundle(bd, [s, signBundle(bd, generateKeyPair().secretKey)]), opt())).toMatchObject({ ok: false, code: 'below_threshold' });
    const other = signBundle(body({ grants: ['evil'] }), b.secretKey);
    expect(verifyBundle(assembleBundle(bd, [s, other]), opt())).toMatchObject({ ok: false, code: 'below_threshold' });
    expect(verifyBundle(assembleBundle(bd, [s]), opt({ threshold: 1 }))).toMatchObject({ ok: true });
  });
  it('rollback, broken chain, an old verifier and malformed bundles are refused', () => {
    const b1 = body();
    const d1 = bundleDigest(b1);
    const b2 = body({ revision: 2, prev: d1 });
    const sig2 = assembleBundle(b2, [signBundle(b2, a.secretKey), signBundle(b2, b.secretKey)]);
    expect(verifyBundle(sig2, opt({ last: { revision: 1, digest: d1 } }))).toMatchObject({ ok: true, revision: 2 });
    expect(verifyBundle(sig2, opt({ last: { revision: 3, digest: 'x' } }))).toMatchObject({ ok: false, code: 'rollback' });
    expect(verifyBundle(sig2, opt({ last: { revision: 1, digest: 'not-d1' } }))).toMatchObject({ ok: false, code: 'broken_chain' });
    expect(verifyBundle(sig2, opt({ last: { revision: 2, digest: 'other' } }))).toMatchObject({ ok: false, code: 'broken_chain' });
    const b3 = body({ min_verifier_version: '0.6.0' });
    expect(verifyBundle(assembleBundle(b3, [signBundle(b3, a.secretKey), signBundle(b3, b.secretKey)]), opt())).toMatchObject({ ok: false, code: 'verifier_too_old' });
    expect(verifyBundle({ ...b1, revision: 2 }, opt())).toMatchObject({ ok: false, code: 'malformed' });
    expect(verifyBundle(null, opt())).toMatchObject({ ok: false, code: 'malformed' });
    expect(() => signBundle(body({ min_verifier_version: 'v1' }), a.secretKey)).toThrow(RangeError);
  });
  it('compares dotted versions numerically', () => {
    expect(compareVersion('0.10.0', '0.9.9')).toBe(1);
    expect(compareVersion('1.0', '1.0.0')).toBe(0);
    expect(compareVersion('0.5.0', '0.5.1')).toBe(-1);
  });
});

const rec = (over: Partial<Omit<DecisionRecord, 'seq' | 'prev' | 'v'>> = {}) => ({ bundle_revision: 1, bundle_digest: 'bd', action_digest: 'a1', decision: 'deny' as const, at: 5, ...over });

describe('decision log', () => {
  it('records are hash-chained and inclusion-provable against a signed head, offline', () => {
    const log = new DecisionLog(a.secretKey);
    const r0 = log.append(rec({ witness: 'clause:7' }));
    const r1 = log.append(rec({ action_digest: 'a2', decision: 'allow' }));
    log.append(rec({ action_digest: 'a3', decision: 'escalate' }));
    expect(r0.prev).toBe('');
    expect(r1.prev).toBe(recordCommit(r0));
    const head = log.head(9);
    expect(verifyLogHead(head, pins[0]!)).toBe(true);
    expect(verifyLogHead(head, pins[1]!)).toBe(false);
    expect(head.size).toBe(3);
    for (const r of [r0, r1]) expect(verifyRecordInclusion(r, log.proof(r.seq), head, pins[0]!)).toBe(true);
    expect(verifyRecordInclusion({ ...r0, decision: 'allow' }, log.proof(0), head, pins[0]!)).toBe(false);
    expect(verifyRecordInclusion(r0, log.proof(1), head, pins[0]!)).toBe(false);
    expect(verifyInclusion(head.root, log.proof(0), recordCommit(r0))).toBe(true);
  });
  it('masks by data class, not by path', () => {
    const log = new DecisionLog(a.secretKey, ['pii']);
    const r = log.append(rec({ detail: { email: 'x@y.z', amount: 5 }, classes: { email: 'pii', amount: 'financial' } }));
    expect(r.detail!.amount).toBe(5);
    expect(String(r.detail!.email)).toMatch(/^masked:pii:/);
    expect(JSON.stringify(r)).not.toContain('x@y.z');
    // pure function: same input twice masks identically, different values differ
    expect(maskRecord(rec({ detail: { k: 'v1' }, classes: { k: 'pii' } }), ['pii']).detail!.k).not.toBe(maskRecord(rec({ detail: { k: 'v2' }, classes: { k: 'pii' } }), ['pii']).detail!.k);
  });
  it('the stream is gap-free, replay-proof and tamper-evident', () => {
    const log = new DecisionLog(a.secretKey);
    for (let i = 0; i < 5; i++) log.append(rec({ action_digest: `a${i}` }));
    const s0 = { next: 0, lastCommit: '' };
    const b1 = nextBatch(log, 0, 2, 10);
    const v1 = verifyBatch(b1, s0, pins[0]!);
    expect(v1).toMatchObject({ ok: true, next: 2 });
    if (!v1.ok) throw new Error();
    const s1 = { next: v1.next, lastCommit: v1.lastCommit };
    expect(verifyBatch(b1, s1, pins[0]!)).toMatchObject({ ok: false, reason: expect.stringContaining('gap or replay') });
    expect(verifyBatch(nextBatch(log, 3, 2, 10), s1, pins[0]!)).toMatchObject({ ok: false });
    const b2 = nextBatch(log, 2, 10, 11);
    expect(verifyBatch(b2, s1, pins[0]!)).toMatchObject({ ok: true, next: 5 });
    const tampered = { ...b2, records: b2.records.map((r, i) => (i === 1 ? { ...r, decision: 'allow' as const } : r)) };
    expect(verifyBatch(tampered, s1, pins[0]!)).toMatchObject({ ok: false, reason: expect.stringContaining('chain broken') });
    expect(verifyBatch(b2, s1, pins[1]!)).toMatchObject({ ok: false, reason: expect.stringContaining('pinned') });
    expect(() => nextBatch(log, -1, 2, 1)).toThrow(RangeError);
    // a truncated final record is caught against the signed head
    const short = { ...b2, records: b2.records.slice(0, 2) };
    expect(verifyBatch(short, s1, pins[0]!)).toMatchObject({ ok: true, next: 4 });
    const longer = { ...b2, head: { ...b2.head, size: 4 } };
    expect(verifyBatch(longer, s1, pins[0]!)).toMatchObject({ ok: false });
  });
});

describe('replay tools', () => {
  type In = { amount: number };
  const cases = [{ action_digest: 'x1', input: { amount: 10 } }, { action_digest: 'x2', input: { amount: 60 } }, { action_digest: 'x3', input: { amount: 200 } }];
  const oldD = (i: In) => (i.amount > 50 ? 'deny' as const : 'allow' as const);
  const newD = (i: In) => (i.amount > 150 ? 'deny' as const : i.amount > 50 ? 'escalate' as const : 'allow' as const);
  it('semantic diff lists exactly the changed decisions and their direction', () => {
    expect(semanticDiff(cases, oldD, newD)).toEqual([{ action_digest: 'x2', before: 'deny', after: 'escalate', direction: 'widened' }]);
    expect(semanticDiff(cases, newD, oldD)).toEqual([{ action_digest: 'x2', before: 'escalate', after: 'deny', direction: 'tightened' }]);
  });
  it('audit replay finds a logged decision the pure core would not have made', () => {
    const records = [
      { v: 1, seq: 0, prev: '', ...rec({ action_digest: 'x1', decision: 'allow' }) },
      { v: 1, seq: 1, prev: 'p', ...rec({ action_digest: 'x2', decision: 'allow' }) },
      { v: 1, seq: 2, prev: 'p', ...rec({ action_digest: 'unknown', decision: 'allow' }) },
    ] as DecisionRecord[];
    expect(auditReplay(records, cases, (i) => oldD(i)).map((r) => r.action_digest)).toEqual(['x2']);
  });
});
