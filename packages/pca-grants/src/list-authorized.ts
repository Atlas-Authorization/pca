import { b64u, decodeB64uStrict, hashCanonical, utf8 } from '@atlasauth/pca';
import { isObj, isSafeInt, isStr, signBody, signerOf, verifyBody } from './sig';

/**
 * LIST-AUTHORIZED: "which objects of this type may this agent touch?" without building a Zanzibar.
 *
 * Authority = capability AND relationship. The capability (the grant's own predicates, supplied as `permits`) decides;
 * a {@link RelationSource} (OpenFGA, SpiceDB, Atlas FGA, your own tuples) can only NARROW. Candidates come from a
 * {@link CandidateSource} (the RS's catalog, or a relation source's list-objects). Every page is charged to a read
 * accumulator (scanned AND returned objects, so a filter-heavy scan cannot scrape), pages are bound by a signed cursor
 * (changing subject/type/filter between pages is refused), and the result carries a signed {@link ListReceipt}.
 */
export const LIST_RECEIPT_DOMAIN = 'atlas-pca/list-receipt/v1\0';
export const LIST_CURSOR_DOMAIN = 'atlas-pca/list-cursor/v1\0';

export interface CandidatePage {
  objects: string[];
  next?: string;
}
export interface CandidateSource {
  page(q: { type: string; cursor?: string; limit: number }): Promise<CandidatePage>;
}
export interface RelationSource {
  /** May `subject` have `relation` on `object`? Only ever narrows. */
  check(q: { subject: string; relation: string; object: string }): Promise<boolean>;
  /** Optional: enumerate objects directly (used as the candidate source by {@link candidatesFromRelation}). */
  listObjects?(q: { subject: string; relation: string; type: string; cursor?: string; limit: number }): Promise<CandidatePage>;
}
/** Adapt a relation source's list-objects into a candidate source for one subject + relation. */
export function candidatesFromRelation(rel: RelationSource, subject: string, relation: string): CandidateSource {
  if (!rel.listObjects) throw new TypeError('candidatesFromRelation: the relation source has no listObjects');
  const list = rel.listObjects.bind(rel);
  return { page: (q) => list({ subject, relation, ...q }) };
}

/** Charges reads against a budget keyed by (subject, type). Returns false when the charge would exceed the cap. */
export interface ReadAccumulator {
  charge(key: string, units: number, now: number): boolean | Promise<boolean>;
}
/** Reference accumulator: `cap` units per `windowMs` fixed window per key. */
export class WindowReadAccumulator implements ReadAccumulator {
  private readonly used = new Map<string, { start: number; n: number }>();
  constructor(private readonly cap: number, private readonly windowMs: number) {}
  charge(key: string, units: number, now: number): boolean {
    const e = this.used.get(key);
    const cur = !e || now - e.start >= this.windowMs ? { start: now, n: 0 } : e;
    if (cur.n + units > this.cap) return false;
    cur.n += units;
    this.used.set(key, cur);
    return true;
  }
}

export interface ListReceipt {
  v: 1;
  subject: string;
  resource_type: string;
  policy_digest: string;
  /** Digest of the consistency token the list was computed under (see freshAtDigest). */
  fresh_at: string;
  /** Digest of the capability + relation filter the list was computed with. */
  filter_digest: string;
  count: number;
  /** Digest of the returned object ids, in order. */
  objects_digest: string;
  issued_at: number;
  signer: string;
  sig: string;
}
export const objectsDigest = (objects: string[]): string => hashCanonical({ d: 'atlas-pca/list-objects/v1', o: objects });
const rbody = (r: Omit<ListReceipt, 'sig'>) => ({ ...r });
export function verifyListReceipt(r: unknown, signer: string, objects?: string[]): r is ListReceipt {
  if (!isObj(r) || r.v !== 1 || r.signer !== signer || !isStr(r.subject) || !isStr(r.resource_type) || !isSafeInt(r.count) || !isSafeInt(r.issued_at)) return false;
  const { sig, ...base } = r as unknown as ListReceipt;
  if (!verifyBody(LIST_RECEIPT_DOMAIN, rbody(base), signer, sig)) return false;
  return objects === undefined || (objects.length === r.count && objectsDigest(objects) === r.objects_digest);
}

export type ListErrorCode = 'read_budget_exhausted' | 'bad_cursor' | 'bad_limit';
export class ListError extends Error {
  constructor(readonly code: ListErrorCode, message: string) {
    super(message);
    this.name = 'ListError';
  }
}

export interface ListAuthorizedArgs {
  subject: string;
  resourceType: string;
  /** The capability: true iff the grant permits the object. REQUIRED (the relationship never widens it). */
  permits: (object: string) => boolean;
  candidates: CandidateSource;
  relation?: { source: RelationSource; relation: string };
  /** Identifies the capability filter (e.g. the chain digest or residual digest); bound into cursor and receipt. */
  filterId: string;
  policyDigest: string;
  freshAtDigest: string;
  page: { cursor?: string; limit: number };
  reads: ReadAccumulator;
  now: number;
  signingSecret: Uint8Array;
  /** Max candidates scanned per call (default 4x limit, at most 1000): bounds work per page. */
  maxScan?: number;
}
export interface ListAuthorizedResult {
  objects: string[];
  next_cursor?: string;
  receipt: ListReceipt;
}
export const MAX_PAGE_LIMIT = 500;

interface Cursor {
  v: 1;
  inner?: string;
  skip: number;
  bind: string;
  signer: string;
}
export interface ListBindInputs {
  subject: string;
  resourceType: string;
  filterId: string;
  policyDigest: string;
  relation?: { relation: string };
  limit: number;
}
/** What a cursor is bound to: changing any of these between pages is refused. */
export const listBind = (a: ListBindInputs): string =>
  hashCanonical({ s: a.subject, t: a.resourceType, f: a.filterId, p: a.policyDigest, r: a.relation?.relation ?? null, l: a.limit });
const encCursor = (c: Cursor, secret: Uint8Array): string =>
  `${b64u(utf8(JSON.stringify(c)))}.${signBody(LIST_CURSOR_DOMAIN, c, secret)}`;
export type CursorVerdict = { ok: true; inner?: string; skip: number } | { ok: false; reason: 'malformed' | 'signature' | 'bind' };
/** Verify a page cursor: shape, signature by `signer`, and (when `bind` inputs are given) that it was issued for exactly those inputs. Never throws. */
export function verifyListCursor(tok: unknown, signer: string, bind?: ListBindInputs): CursorVerdict {
  if (typeof tok !== 'string') return { ok: false, reason: 'malformed' };
  const [p, s, extra] = tok.split('.');
  let c: Cursor | null = null;
  try {
    const raw = p ? decodeB64uStrict(p) : null;
    c = raw ? (JSON.parse(new TextDecoder().decode(raw)) as Cursor) : null;
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (extra !== undefined || !c || !s || !isObj(c) || c.v !== 1 || typeof c.bind !== 'string' || !isSafeInt(c.skip) || (c.inner !== undefined && typeof c.inner !== 'string')) return { ok: false, reason: 'malformed' };
  if (c.signer !== signer || !verifyBody(LIST_CURSOR_DOMAIN, c, signer, s)) return { ok: false, reason: 'signature' };
  if (bind !== undefined && c.bind !== listBind(bind)) return { ok: false, reason: 'bind' };
  return { ok: true, ...(c.inner !== undefined ? { inner: c.inner } : {}), skip: c.skip };
}

export async function listAuthorized(a: ListAuthorizedArgs): Promise<ListAuthorizedResult> {
  if (!Number.isSafeInteger(a.page.limit) || a.page.limit < 1 || a.page.limit > MAX_PAGE_LIMIT) throw new ListError('bad_limit', `limit must be 1..${MAX_PAGE_LIMIT}`);
  const signer = signerOf(a.signingSecret);
  const bindInputs: ListBindInputs = { subject: a.subject, resourceType: a.resourceType, filterId: a.filterId, policyDigest: a.policyDigest, ...(a.relation ? { relation: a.relation } : {}), limit: a.page.limit };
  const bind = listBind(bindInputs);
  let inner: string | undefined;
  let skipIn = 0;
  if (a.page.cursor !== undefined) {
    const c = verifyListCursor(a.page.cursor, signer, bindInputs);
    if (!c.ok) throw new ListError('bad_cursor', c.reason === 'bind' ? 'subject, type, filter, policy or limit changed between pages' : 'the page cursor is malformed, forged or from another signer');
    inner = c.inner;
    skipIn = c.skip;
  }
  const maxScan = Math.min(a.maxScan ?? a.page.limit * 4, 1000);
  const key = hashCanonical({ s: a.subject, t: a.resourceType });
  const out: string[] = [];
  let scanned = 0;
  // Candidate pages are always `limit` long so a resume point (page start + objects already consumed) is exact.
  let pageStart = inner;
  let skip = skipIn;
  let resume: { inner?: string; skip: number } | undefined;
  for (;;) {
    const pg = await a.candidates.page({ type: a.resourceType, ...(pageStart !== undefined ? { cursor: pageStart } : {}), limit: a.page.limit });
    const objs = pg.objects.slice(0, a.page.limit);
    // Charge what was SCANNED before anything is returned: enumeration by filter-heavy scans is the attack.
    if (!(await a.reads.charge(key, Math.max(objs.length - skip, 1), a.now))) throw new ListError('read_budget_exhausted', 'the read budget for this subject and type is exhausted');
    let i = skip;
    for (; i < objs.length && out.length < a.page.limit; i++) {
      scanned++;
      const o = objs[i] as string;
      if (!a.permits(o)) continue;
      if (a.relation && !(await a.relation.source.check({ subject: a.subject, relation: a.relation.relation, object: o }))) continue;
      out.push(o);
    }
    if (i < objs.length) {
      resume = { ...(pageStart !== undefined ? { inner: pageStart } : {}), skip: i };
      break;
    }
    if (pg.next === undefined || pg.next === '' || objs.length === 0) break;
    pageStart = pg.next;
    skip = 0;
    if (out.length >= a.page.limit || scanned >= maxScan) {
      resume = { inner: pg.next, skip: 0 };
      break;
    }
  }
  const receipt: Omit<ListReceipt, 'sig'> = {
    v: 1, subject: a.subject, resource_type: a.resourceType, policy_digest: a.policyDigest, fresh_at: a.freshAtDigest,
    filter_digest: a.filterId, count: out.length, objects_digest: objectsDigest(out), issued_at: a.now, signer,
  };
  const next = resume ? encCursor({ v: 1, ...(resume.inner !== undefined ? { inner: resume.inner } : {}), skip: resume.skip, bind, signer }, a.signingSecret) : undefined;
  return { objects: out, ...(next ? { next_cursor: next } : {}), receipt: { ...receipt, sig: signBody(LIST_RECEIPT_DOMAIN, rbody(receipt), a.signingSecret) } };
}
