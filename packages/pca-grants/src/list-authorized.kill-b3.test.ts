import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, hashCanonical, utf8 } from '@atlasauth/pca';
import {
  LIST_CURSOR_DOMAIN,
  LIST_RECEIPT_DOMAIN,
  ListError,
  WindowReadAccumulator,
  candidatesFromRelation,
  listAuthorized,
  listBind,
  objectsDigest,
  verifyListCursor,
  verifyListReceipt,
  type CandidateSource,
  type ListAuthorizedArgs,
  type RelationSource,
} from './list-authorized';
import { signBody, signerOf } from './sig';

const kp = generateKeyPair();
const signer = signerOf(kp.secretKey);
const ALL = Array.from({ length: 20 }, (_, i) => `doc:${String(i).padStart(2, '0')}`);
const source = (objs = ALL): CandidateSource => ({
  async page({ cursor, limit }) {
    const start = cursor === undefined ? 0 : Number(cursor);
    return { objects: objs.slice(start, start + limit), ...(start + limit < objs.length ? { next: String(start + limit) } : {}) };
  },
});
const base = (over: Partial<ListAuthorizedArgs> = {}): ListAuthorizedArgs => ({
  subject: 'agent:a', resourceType: 'doc', permits: () => true, candidates: source(), filterId: 'f1', policyDigest: 'pd', freshAtDigest: 'fa',
  page: { limit: 3 }, reads: new WindowReadAccumulator(1000, 60_000), now: 1000, signingSecret: kp.secretKey, ...over,
});
const cursorTok = (c: Record<string, unknown>, sigBody: Record<string, unknown> = c): string =>
  `${b64u(utf8(JSON.stringify(c)))}.${signBody(LIST_CURSOR_DOMAIN, sigBody, kp.secretKey)}`;
const goodCursor = { v: 1, skip: 0, bind: 'b', signer };

describe('candidatesFromRelation', () => {
  it('refuses a source without listObjects with the exact message', () => {
    expect(() => candidatesFromRelation({ check: async () => true }, 's', 'r')).toThrow(new TypeError('candidatesFromRelation: the relation source has no listObjects'));
  });
  it('calls listObjects bound to the source with subject, relation and the query', async () => {
    const seen: unknown[] = [];
    const rel = {
      tag: 't',
      check: async () => true,
      async listObjects(this: { tag: string }, q: unknown) {
        seen.push([this.tag, q]);
        return { objects: [] };
      },
    } as unknown as RelationSource;
    await candidatesFromRelation(rel, 's', 'r').page({ type: 'doc', limit: 2 });
    expect(seen).toEqual([['t', { subject: 's', relation: 'r', type: 'doc', limit: 2 }]]);
  });
});

describe('WindowReadAccumulator', () => {
  it('a window starts at its first charge and rolls exactly windowMs later', () => {
    const a = new WindowReadAccumulator(5, 100);
    expect(a.charge('k', 5, 1000)).toBe(true);
    expect(a.charge('k', 1, 1050)).toBe(false);
    expect(a.charge('k', 1, 1099)).toBe(false);
    expect(a.charge('k', 5, 1100)).toBe(true);
  });
});

describe('verifyListReceipt shape checks on signed receipts', () => {
  const good = {
    v: 1, subject: 's', resource_type: 'doc', policy_digest: 'p', fresh_at: 'f', filter_digest: 'x', count: 2, objects_digest: objectsDigest(['a', 'b']), issued_at: 5, signer,
  };
  const signed = (over: Record<string, unknown>) => {
    const body = { ...good, ...over };
    return { ...body, sig: signBody(LIST_RECEIPT_DOMAIN, body, kp.secretKey) };
  };
  it('accepts the well-formed receipt', () => {
    expect(verifyListReceipt(signed({}), signer, ['a', 'b'])).toBe(true);
  });
  it('each shape defect is refused even when the signature is genuine', () => {
    for (const over of [{ v: 2 }, { signer: 'someone-else' }, { subject: '' }, { resource_type: '' }, { count: -1 }, { issued_at: -1 }]) {
      expect(verifyListReceipt(signed(over), signer), JSON.stringify(over)).toBe(false);
    }
  });
  it('non-objects are refused without throwing', () => {
    for (const r of [null, undefined, 5, 'x', []]) expect(verifyListReceipt(r, signer)).toBe(false);
  });
  it('the object count is checked separately from the digest', () => {
    expect(verifyListReceipt(signed({ count: 3 }), signer, ['a', 'b'])).toBe(false);
  });
});

describe('ListError', () => {
  it('carries code, message and name', () => {
    const e = new ListError('bad_limit', 'm');
    expect([e.name, e.code, e.message]).toEqual(['ListError', 'bad_limit', 'm']);
  });
});

describe('verifyListCursor', () => {
  it('refuses non-strings and undecodable payloads as malformed', () => {
    for (const t of [undefined, 5, '', 'x', 'a$$.b']) expect(verifyListCursor(t, signer)).toStrictEqual({ ok: false, reason: 'malformed' });
    expect(verifyListCursor(`${b64u(utf8('not json'))}.sig`, signer)).toStrictEqual({ ok: false, reason: 'malformed' });
    expect(verifyListCursor(`${b64u(utf8('null'))}.sig`, signer)).toStrictEqual({ ok: false, reason: 'malformed' });
  });
  it('each structural defect is malformed even when genuinely signed', () => {
    const malformed = { ok: false, reason: 'malformed' };
    expect(verifyListCursor(`${cursorTok(goodCursor)}.extra`, signer)).toStrictEqual(malformed);
    expect(verifyListCursor(b64u(utf8(JSON.stringify(goodCursor))), signer)).toStrictEqual(malformed);
    for (const over of [{ v: 2 }, { bind: 5 }, { skip: -1 }, { skip: '0' }, { inner: 5 }]) {
      expect(verifyListCursor(cursorTok({ ...goodCursor, ...over }), signer), JSON.stringify(over)).toStrictEqual(malformed);
    }
    for (const j of ['5', '"x"', '[]']) expect(verifyListCursor(`${b64u(utf8(j))}.sig`, signer)).toStrictEqual(malformed);
  });
  it('a cursor naming another signer fails the signature check even if the key matches', () => {
    expect(verifyListCursor(cursorTok({ ...goodCursor, signer: 'other' }), signer)).toStrictEqual({ ok: false, reason: 'signature' });
    expect(verifyListCursor(cursorTok(goodCursor, { ...goodCursor, skip: 1 }), signer)).toStrictEqual({ ok: false, reason: 'signature' });
  });
  it('returns inner only when present', () => {
    expect(verifyListCursor(cursorTok(goodCursor), signer)).toStrictEqual({ ok: true, skip: 0 });
    expect(verifyListCursor(cursorTok({ ...goodCursor, inner: 'n', skip: 2 }), signer)).toStrictEqual({ ok: true, inner: 'n', skip: 2 });
  });
});

describe('listAuthorized', () => {
  it('limit bounds: 1 and 500 are allowed, others refused with the exact message', async () => {
    await expect(listAuthorized(base({ page: { limit: 500 } }))).resolves.toBeDefined();
    await expect(listAuthorized(base({ page: { limit: 1 } }))).resolves.toBeDefined();
    for (const limit of [0, 501, 1.5]) {
      await expect(listAuthorized(base({ page: { limit } }))).rejects.toMatchObject({ code: 'bad_limit', message: 'limit must be 1..500' });
    }
  });
  it('cursor refusals carry distinct messages and the relation is bound into the cursor', async () => {
    const rel: RelationSource = { check: async () => true };
    const first = await listAuthorized(base({ relation: { source: rel, relation: 'viewer' } }));
    const cursor = first.next_cursor!;
    await expect(listAuthorized(base({ relation: { source: rel, relation: 'editor' }, page: { limit: 3, cursor } }))).rejects.toMatchObject({
      code: 'bad_cursor',
      message: 'subject, type, filter, policy or limit changed between pages',
    });
    await expect(listAuthorized(base({ page: { limit: 3, cursor } }))).rejects.toMatchObject({ code: 'bad_cursor' });
    await expect(listAuthorized(base({ page: { limit: 3, cursor: 'garbage' } }))).rejects.toMatchObject({
      code: 'bad_cursor',
      message: 'the page cursor is malformed, forged or from another signer',
    });
    await expect(listAuthorized(base({ relation: { source: rel, relation: 'viewer' }, page: { limit: 3, cursor } }))).resolves.toBeDefined();
  });
  it('charges the read budget under a key derived from subject and type, by scanned count, minimum one', async () => {
    const charges: Array<[string, number]> = [];
    const reads = { charge: (k: string, n: number) => (charges.push([k, n]), true) };
    const first = await listAuthorized(base({ reads, permits: (o) => o === 'doc:00' }));
    await listAuthorized(base({ reads, page: { limit: 3, cursor: first.next_cursor! }, permits: () => false }));
    expect(charges[0]).toEqual([hashCanonical({ s: 'agent:a', t: 'doc' }), 3]);
    expect(charges[1]![1]).toBe(3);
    // a resume partway into a page charges only the unread remainder
    const half = await listAuthorized(base({ reads, page: { limit: 3 }, permits: () => true, candidates: source(ALL.slice(0, 3)) }));
    expect(half.objects).toHaveLength(3);
    const empty = await listAuthorized(base({ reads, candidates: source([]) }));
    expect(empty.objects).toEqual([]);
    expect(charges[charges.length - 1]![1]).toBe(1);
  });
  it('a page resumed with a signed skip charges only the unread remainder', async () => {
    const charges: number[] = [];
    const reads = { charge: (_k: string, n: number) => (charges.push(n), true) };
    const bind = listBind({ subject: 'agent:a', resourceType: 'doc', filterId: 'f1', policyDigest: 'pd', limit: 4 });
    const cursor = cursorTok({ v: 1, skip: 3, bind, signer });
    const r = await listAuthorized(base({ reads, page: { limit: 4, cursor }, candidates: source(ALL.slice(0, 4)) }));
    expect(r.objects).toEqual(['doc:03']);
    expect(charges).toEqual([1]);
    const bind2 = listBind({ subject: 'agent:a', resourceType: 'doc', filterId: 'f1', policyDigest: 'pd', limit: 6 });
    await listAuthorized(base({ reads, page: { limit: 6, cursor: cursorTok({ v: 1, skip: 2, bind: bind2, signer }) }, candidates: source(ALL.slice(0, 6)) }));
    expect(charges).toEqual([1, 4]);
  });
  it('exhausting the budget is a typed error with its message', async () => {
    await expect(listAuthorized(base({ reads: { charge: () => false } }))).rejects.toMatchObject({
      code: 'read_budget_exhausted',
      message: 'the read budget for this subject and type is exhausted',
    });
  });
  it('the first candidate request carries no cursor key, and an oversized page is cut to the limit', async () => {
    const qs: Array<Record<string, unknown>> = [];
    const candidates: CandidateSource = { async page(q) { qs.push(q); return { objects: ALL.slice(0, 10) }; } };
    const r = await listAuthorized(base({ candidates }));
    expect('cursor' in qs[0]!).toBe(false);
    expect(qs[0]).toEqual({ type: 'doc', limit: 3 });
    expect(r.objects).toEqual(ALL.slice(0, 3));
  });
  it('an empty-string next or an empty page ends the scan after one request', async () => {
    let calls = 0;
    const blank: CandidateSource = { async page() { calls++; return { objects: ['doc:00'], next: '' }; } };
    const r = await listAuthorized(base({ candidates: blank }));
    expect([calls, r.objects, r.next_cursor]).toEqual([1, ['doc:00'], undefined]);
    calls = 0;
    const empty: CandidateSource = { async page() { calls++; return calls === 1 ? { objects: [], next: 'n' } : { objects: ['doc:01'] }; } };
    const r2 = await listAuthorized(base({ candidates: empty }));
    expect([calls, r2.objects]).toEqual([1, []]);
  });
  it('a page filled exactly to the limit stops without fetching another page and hands back a cursor', async () => {
    let calls = 0;
    const counting: CandidateSource = { async page(q) { calls++; return source().page(q); } };
    const r = await listAuthorized(base({ candidates: counting }));
    expect(calls).toBe(1);
    expect(r.objects).toEqual(ALL.slice(0, 3));
    expect(verifyListCursor(r.next_cursor, signer)).toStrictEqual({ ok: true, inner: '3', skip: 0 });
  });
  it('the receipt verifies against the returned objects', async () => {
    const r = await listAuthorized(base());
    expect(verifyListReceipt(r.receipt, signer, r.objects)).toBe(true);
  });
});
