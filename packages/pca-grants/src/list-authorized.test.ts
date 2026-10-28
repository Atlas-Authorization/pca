import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { ListError, WindowReadAccumulator, candidatesFromRelation, listAuthorized, objectsDigest, verifyListReceipt, type CandidateSource, type ListAuthorizedArgs, type RelationSource } from './list-authorized';
import { signerOf } from './sig';

const kp = generateKeyPair();
const ALL = Array.from({ length: 20 }, (_, i) => `doc:${String(i).padStart(2, '0')}`);
const source = (objs = ALL): CandidateSource => ({
  async page({ cursor, limit }) {
    const start = cursor === undefined ? 0 : Number(cursor);
    const objects = objs.slice(start, start + limit);
    return { objects, ...(start + limit < objs.length ? { next: String(start + limit) } : {}) };
  },
});
const base = (over: Partial<ListAuthorizedArgs> = {}): ListAuthorizedArgs => ({
  subject: 'agent:a', resourceType: 'doc', permits: (o) => Number(o.slice(4)) % 2 === 0, candidates: source(), filterId: 'f1', policyDigest: 'pd', freshAtDigest: 'fa',
  page: { limit: 3 }, reads: new WindowReadAccumulator(1000, 60_000), now: 1000, signingSecret: kp.secretKey, ...over,
});
async function all(over: Partial<ListAuthorizedArgs> = {}) {
  const out: string[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < 50; i++) {
    const r = await listAuthorized(base({ ...over, page: { limit: over.page?.limit ?? 3, ...(cursor ? { cursor } : {}) } }));
    out.push(...r.objects);
    if (!r.next_cursor) return out;
    cursor = r.next_cursor;
  }
  throw new Error('did not terminate');
}

describe('listAuthorized', () => {
  it('returns exactly the capability-permitted objects across pages, each once and in order', async () => {
    expect(await all()).toEqual(ALL.filter((_, i) => i % 2 === 0));
    expect(await all({ page: { limit: 1 } })).toEqual(ALL.filter((_, i) => i % 2 === 0));
    expect(await all({ page: { limit: 7 } })).toEqual(ALL.filter((_, i) => i % 2 === 0));
  });
  it('the relationship can only narrow the capability', async () => {
    const rel: RelationSource = { check: async ({ object }) => object === 'doc:04' || object === 'doc:05' };
    expect(await all({ relation: { source: rel, relation: 'viewer' } })).toEqual(['doc:04']);
  });
  it('an empty permit set yields an empty, receipted page', async () => {
    const r = await listAuthorized(base({ permits: () => false, page: { limit: 5 }, maxScan: 1000 }));
    expect(r.objects).toEqual([]);
    expect(r.receipt.count).toBe(0);
  });
  it('the receipt binds policy, freshness, filter and the exact objects', async () => {
    const r = await listAuthorized(base());
    const signer = signerOf(kp.secretKey);
    expect(r.receipt).toMatchObject({ policy_digest: 'pd', fresh_at: 'fa', filter_digest: 'f1', subject: 'agent:a', resource_type: 'doc', count: 3 });
    expect(r.receipt.objects_digest).toBe(objectsDigest(r.objects));
    expect(verifyListReceipt(r.receipt, signer, r.objects)).toBe(true);
    expect(verifyListReceipt(r.receipt, signer, [...r.objects.slice(1), 'doc:99'])).toBe(false);
    expect(verifyListReceipt({ ...r.receipt, policy_digest: 'x' }, signer)).toBe(false);
    expect(verifyListReceipt(r.receipt, signerOf(generateKeyPair().secretKey))).toBe(false);
  });
  it('a cursor cannot be reused with a different subject, filter, policy or limit, or forged', async () => {
    const first = await listAuthorized(base());
    const cursor = first.next_cursor!;
    for (const over of [{ subject: 'agent:b' }, { filterId: 'f2' }, { policyDigest: 'p2' }, { resourceType: 'img' }] as Partial<ListAuthorizedArgs>[]) {
      await expect(listAuthorized(base({ ...over, page: { limit: 3, cursor } }))).rejects.toMatchObject({ code: 'bad_cursor' });
    }
    await expect(listAuthorized(base({ page: { limit: 4, cursor } }))).rejects.toMatchObject({ code: 'bad_cursor' });
    await expect(listAuthorized(base({ page: { limit: 3, cursor: cursor.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A')) } }))).rejects.toBeInstanceOf(ListError);
    await expect(listAuthorized(base({ page: { limit: 3, cursor: 'garbage' } }))).rejects.toMatchObject({ code: 'bad_cursor' });
  });
  it('enumeration by scraping is stopped by the read accumulator, counting scanned objects not returned ones', async () => {
    const reads = new WindowReadAccumulator(8, 60_000);
    // permits nothing: returns 0 objects but scans; the budget still drains
    await listAuthorized(base({ reads, permits: () => false, page: { limit: 4 }, maxScan: 4 }));
    await listAuthorized(base({ reads, permits: () => false, page: { limit: 4 }, maxScan: 4 }));
    await expect(listAuthorized(base({ reads, permits: () => false, page: { limit: 4 }, maxScan: 4 }))).rejects.toMatchObject({ code: 'read_budget_exhausted' });
    // the window rolls
    const r = await listAuthorized(base({ reads, now: 1000 + 60_000, permits: () => false, page: { limit: 4 }, maxScan: 4 }));
    expect(r.objects).toEqual([]);
  });
  it('bad limits are refused', async () => {
    for (const limit of [0, -1, 501, 1.5]) await expect(listAuthorized(base({ page: { limit } }))).rejects.toMatchObject({ code: 'bad_limit' });
  });
  it('candidatesFromRelation adapts list-objects and refuses a source without it', async () => {
    const rel: RelationSource = {
      check: async () => true,
      listObjects: async ({ subject, relation, type, limit }) => ({ objects: [`${type}:${subject}:${relation}`].slice(0, limit) }),
    };
    expect(await candidatesFromRelation(rel, 'agent:a', 'viewer').page({ type: 'doc', limit: 5 })).toEqual({ objects: ['doc:agent:a:viewer'] });
    expect(() => candidatesFromRelation({ check: async () => true }, 'a', 'r')).toThrow(TypeError);
  });
});
