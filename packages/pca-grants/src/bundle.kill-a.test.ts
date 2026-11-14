import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import {
  DecisionLog, LOG_HEAD_DOMAIN, assembleBundle, bundleDigest, compareVersion, maskRecord, nextBatch, recordCommit, signBundle, verifyBatch, verifyBundle, verifyLogHead,
  type DecisionRecord, type PolicyBundleBody,
} from './bundle';
import { signBody, signerOf } from './sig';

const k = generateKeyPair();
const S = signerOf(k.secretKey);
const body = (over: Record<string, unknown> = {}): PolicyBundleBody =>
  ({ v: 1, kind: 'pca-policy-bundle', revision: 1, grants: ['g1'], template_digests: [], min_verifier_version: '0.5.0', issued_at: 1, ...over }) as PolicyBundleBody;
const vo = (over = {}) => ({ signers: [S], threshold: 1, verifierVersion: '1.0.0', ...over });
const malformed = (over: Record<string, unknown>) => verifyBundle({ ...body(over), sigs: [] }, vo());
const bad = (reason: string) => ({ ok: false, code: 'malformed', reason });
const many = (n: number, p = 'x') => Array.from({ length: n }, (_, i) => `${p}${i}`);

describe('compareVersion', () => {
  it('a missing component counts as zero and decides when the other is non-zero', () => {
    expect(compareVersion('1.2', '1.2.3')).toBe(-1);
    expect(compareVersion('1.2.3', '1.2')).toBe(1);
    expect(compareVersion('1.2', '1.2.0')).toBe(0);
    expect(compareVersion('1.10', '1.9')).toBe(1);
  });
});

describe('bundle shape errors name the exact problem', () => {
  it('not a bundle', () => {
    expect(malformed({ v: 2 })).toEqual(bad('not a policy bundle'));
    expect(malformed({ kind: 'other' })).toEqual(bad('not a policy bundle'));
    expect(verifyBundle(null, vo())).toEqual(bad('not a policy bundle'));
  });
  it('revision and time', () => {
    for (const over of [{ revision: 0 }, { revision: -1 }, { revision: 1.5 }, { revision: '1' }, { issued_at: -1 }, { issued_at: 'x' }]) {
      expect(malformed(over), JSON.stringify(over)).toEqual(bad('bad revision or time'));
    }
  });
  it('prev is absent at revision 1 and present after', () => {
    const r = 'prev must be absent at revision 1 and present after';
    expect(malformed({ prev: 'x' })).toEqual(bad(r));
    expect(malformed({ revision: 2 })).toEqual(bad(r));
    expect(malformed({ revision: 2, prev: '' })).toEqual(bad(r));
  });
  it('grants and template digests are bounded lists of bounded strings', () => {
    expect(malformed({ grants: many(4097) })).toEqual(bad('bad grants'));
    expect(malformed({ grants: 'g' })).toEqual(bad('bad grants'));
    expect(malformed({ grants: ['a', 5] })).toEqual(bad('bad grants'));
    expect(malformed({ template_digests: many(4097) })).toEqual(bad('bad template_digests'));
    expect(malformed({ template_digests: 't' })).toEqual(bad('bad template_digests'));
    expect(malformed({ template_digests: ['a', 5] })).toEqual(bad('bad template_digests'));
    expect(() => signBundle(body({ grants: many(4096), template_digests: many(4096) }), k.secretKey)).not.toThrow();
  });
  it('each optional digest is checked by name', () => {
    for (const key of ['schema_digest', 'constitution_digest', 'flow_rules_digest']) {
      expect(malformed({ [key]: 5 })).toEqual(bad(`bad ${key}`));
      expect(malformed({ [key]: '' })).toEqual(bad(`bad ${key}`));
    }
  });
  it('the minimum verifier version is a dotted string', () => {
    expect(malformed({ min_verifier_version: 5 })).toEqual(bad('bad min_verifier_version'));
    expect(malformed({ min_verifier_version: 'v1' })).toEqual(bad('bad min_verifier_version'));
  });
  it('shadow lists are non-empty, unique, bounded strings', () => {
    expect(malformed({ shadow: [] })).toEqual(bad('bad shadow'));
    expect(malformed({ shadow: many(17) })).toEqual(bad('bad shadow'));
    expect(malformed({ shadow: ['a', 5] })).toEqual(bad('bad shadow'));
    expect(malformed({ shadow: ['a', 'a'] })).toEqual(bad('bad shadow'));
    expect(malformed({ shadow: 'a' })).toEqual(bad('bad shadow'));
    expect(() => signBundle(body({ shadow: many(16) }), k.secretKey)).not.toThrow();
  });
  it('signBundle refuses with the shape reason', () => {
    expect(() => signBundle(body({ v: 2 }), k.secretKey)).toThrow(new RangeError('signBundle: not a policy bundle'));
  });
});

describe('verifyBundle signatures and chain', () => {
  const bad2 = bad('bad sigs or threshold');
  it('refuses a malformed signature list or threshold without throwing', () => {
    expect(verifyBundle(body(), vo())).toEqual(bad2);
    expect(verifyBundle({ ...body(), sigs: 'x' }, vo())).toEqual(bad2);
    expect(verifyBundle({ ...body(), sigs: [] }, vo({ threshold: 0 }))).toEqual(bad2);
    expect(verifyBundle({ ...body(), sigs: [] }, vo({ threshold: 1.5 }))).toEqual(bad2);
    expect(verifyBundle({ ...body(), sigs: Array.from({ length: 65 }, () => ({ signer: 'x', sig: 'y' })) }, vo())).toEqual(bad2);
  });
  it('64 signatures are allowed', () => {
    const real = signBundle(body(), k.secretKey);
    const sigs = [real, ...Array.from({ length: 63 }, () => ({ signer: 'x', sig: 'y' }))];
    expect(verifyBundle({ ...body(), sigs }, vo())).toMatchObject({ ok: true });
  });
  it('a verifier version that is not a string is too old', () => {
    const b = assembleBundle(body(), [signBundle(body(), k.secretKey)]);
    expect(verifyBundle(b, vo({ verifierVersion: 5 }))).toEqual({ ok: false, code: 'verifier_too_old', reason: 'needs verifier >= 0.5.0' });
  });
  it('the same revision with the same content, and a skipped revision, are accepted', () => {
    const b = assembleBundle(body(), [signBundle(body(), k.secretKey)]);
    expect(verifyBundle(b, vo({ last: { revision: 1, digest: bundleDigest(b) } }))).toMatchObject({ ok: true });
    const b3 = body({ revision: 3, prev: 'whatever' });
    const s3 = assembleBundle(b3, [signBundle(b3, k.secretKey)]);
    expect(verifyBundle(s3, vo({ last: { revision: 1, digest: 'd1' } }))).toMatchObject({ ok: true, revision: 3 });
  });
});

describe('maskRecord', () => {
  const rec = { bundle_revision: 1, bundle_digest: 'b', action_digest: 'a', decision: 'allow' as const, at: 1 };
  it('returns the record untouched when either detail or classes is missing', () => {
    const onlyDetail = { ...rec, detail: { a: 1 } };
    const onlyClasses = { ...rec, classes: { a: 'pii' } };
    expect(maskRecord(onlyDetail, ['pii'])).toBe(onlyDetail);
    expect(maskRecord(onlyClasses, ['pii'])).toBe(onlyClasses);
  });
  it('leaves fields without a class in the clear', () => {
    const out = maskRecord({ ...rec, detail: { a: 1, b: 2 }, classes: { a: 'pii' } }, ['pii']);
    expect(out.detail!.b).toBe(2);
    expect(String(out.detail!.a)).toMatch(/^masked:pii:/);
  });
});

describe('verifyLogHead rejects each malformed field even when the signature is valid', () => {
  const base = { v: 1, size: 1, root: 'r', last_commit: 'c', issued_at: 1, signer: S };
  const sealed = (over: Record<string, unknown>, signWith = k.secretKey) => {
    const h = { ...base, ...over };
    return { ...h, sig: signBody(LOG_HEAD_DOMAIN, h, signWith) };
  };
  it('accepts the well-formed head', () => {
    expect(verifyLogHead(sealed({}), S)).toBe(true);
  });
  it('refuses each bad field', () => {
    for (const over of [{ v: 2 }, { signer: 'someone-else' }, { size: -1 }, { issued_at: -1 }, { issued_at: 'x' }, { root: 5 }, { last_commit: 5 }]) {
      expect(verifyLogHead(sealed(over), S), JSON.stringify(over)).toBe(false);
    }
  });
  it('refuses non-objects without throwing', () => {
    for (const h of [null, undefined, [], 'x', 5]) expect(verifyLogHead(h, S)).toBe(false);
  });
});

describe('DecisionLog and batches', () => {
  const rec = (n: number): Omit<DecisionRecord, 'seq' | 'prev' | 'v'> => ({ bundle_revision: 1, bundle_digest: 'b', action_digest: `a${n}`, decision: 'allow', at: n });
  it('size counts the records', () => {
    const log = new DecisionLog(k.secretKey);
    expect(log.size).toBe(0);
    log.append(rec(1));
    log.append(rec(2));
    expect(log.size).toBe(2);
  });
  it('no mask class is configured by default', () => {
    const sentinel = ['Stry', 'ker was here'].join('');
    const out = new DecisionLog(k.secretKey).append({ ...rec(1), detail: { f: 'v' }, classes: { f: sentinel } });
    expect(out.detail).toEqual({ f: 'v' });
  });
  it('nextBatch validates its cursor and size', () => {
    const log = new DecisionLog(k.secretKey);
    log.append(rec(1));
    const msg = new RangeError('nextBatch: bad cursor or size');
    expect(() => nextBatch(log, 0, 0, 1)).toThrow(msg);
    expect(() => nextBatch(log, -1, 1, 1)).toThrow(msg);
    expect(nextBatch(log, 0, 1, 1).records).toHaveLength(1);
  });
  function logOf(n: number) {
    const log = new DecisionLog(k.secretKey);
    for (let i = 0; i < n; i++) log.append(rec(i));
    return log;
  }
  const fresh = { next: 0, lastCommit: '' };
  it('verifies a contiguous batch and returns the new cursor', () => {
    const log = logOf(3);
    const b = nextBatch(log, 0, 10, 5);
    expect(verifyBatch(b, fresh, S)).toEqual({ ok: true, next: 3, lastCommit: recordCommit(b.records[2]!) });
  });
  it('a record with the wrong sequence number breaks the chain, naming it', () => {
    const b = nextBatch(logOf(1), 0, 10, 5);
    const tampered = { ...b, records: [{ ...b.records[0]!, seq: 5 }] };
    expect(verifyBatch(tampered, fresh, S)).toEqual({ ok: false, reason: 'chain broken at seq 5' });
  });
  it('a batch longer than the signed head is refused', () => {
    const log = logOf(2);
    const shortHead = log.head(5);
    log.append(rec(9));
    const b = { from: 0, records: log.slice(0, 3), head: shortHead };
    expect(verifyBatch(b, fresh, S)).toEqual({ ok: false, reason: 'batch is longer than the signed head' });
  });
  it('a batch that reaches the head must end on the head last commit', () => {
    const b = nextBatch(logOf(2), 0, 10, 5);
    const h = { v: 1 as const, size: b.head.size, root: b.head.root, last_commit: 'not-the-last', issued_at: 5, signer: S };
    const head = { ...h, sig: signBody(LOG_HEAD_DOMAIN, h, k.secretKey) };
    expect(verifyBatch({ ...b, head }, fresh, S)).toEqual({ ok: false, reason: 'batch end does not match the signed head' });
  });
  it('a partial batch short of the head is fine and anything that throws is malformed', () => {
    const b = nextBatch(logOf(3), 0, 2, 5);
    expect(verifyBatch(b, fresh, S)).toMatchObject({ ok: true, next: 2 });
    expect(verifyBatch(null as never, fresh, S)).toEqual({ ok: false, reason: 'malformed batch' });
  });
});
