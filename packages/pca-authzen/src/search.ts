/**
 * AuthZEN 1.0 SEARCH APIs (OpenID AuthZEN Authorization API 1.0, section 8): subject search, resource search, action
 * search. `resource search` is PCA's `listAuthorized`; `action search` is capability discovery ("what may I do here").
 * Source: https://openid.net/specs/authorization-api-1_0.html (Search APIs).
 *
 * The PDP side is a host-supplied {@link AuthzenSearchProvider}; this module owns what the spec fixes: the member table
 * per search type, `page` handling, the entity-type contract of `results`, and fail-closed error mapping. Search results
 * are advisory enumerations, never a substitute for an Access Evaluation at use time.
 */
export const SEARCH_SUBJECT_PATH = '/access/v1/search/subject' as const;
export const SEARCH_RESOURCE_PATH = '/access/v1/search/resource' as const;
export const SEARCH_ACTION_PATH = '/access/v1/search/action' as const;
export const MAX_SEARCH_LIMIT = 1000;

type Rec = Record<string, unknown>;
export interface SearchEntity {
  type: string;
  id?: string;
  properties?: Rec;
}
export interface SearchAction {
  name: string;
  properties?: Rec;
}
export interface SearchPageRequest {
  token?: string;
  limit?: number;
  properties?: Rec;
}
export interface SearchPageResponse {
  /** Opaque; empty string means the end of the result set. REQUIRED when `page` is present. */
  next_token: string;
  count?: number;
  total?: number;
  properties?: Rec;
}
export interface SubjectSearchRequest { subject: { type: string }; action: SearchAction; resource: SearchEntity & { id: string }; context?: Rec; page?: SearchPageRequest }
export interface ResourceSearchRequest { subject: SearchEntity & { id: string }; action: SearchAction; resource: { type: string }; context?: Rec; page?: SearchPageRequest }
export interface ActionSearchRequest { subject: SearchEntity & { id: string }; resource: SearchEntity & { id: string }; context?: Rec; page?: SearchPageRequest }
export interface SearchResult<T> {
  results: T[];
  /** Present when the provider has a paged result; the handler adds `count`. */
  page?: { next_token: string; total?: number; properties?: Rec };
  context?: Rec;
}
export interface AuthzenSearchProvider {
  searchSubject?(req: SubjectSearchRequest): Promise<SearchResult<SearchEntity>>;
  searchResource?(req: ResourceSearchRequest): Promise<SearchResult<SearchEntity>>;
  searchAction?(req: ActionSearchRequest): Promise<SearchResult<SearchAction>>;
}
export interface SearchResponse<T> {
  page?: SearchPageResponse;
  context?: Rec;
  results: T[];
}

const isRec = (x: unknown): x is Rec => typeof x === 'object' && x !== null && !Array.isArray(x);
const str = (x: unknown): x is string => typeof x === 'string' && x.length > 0;
const entity = (x: unknown, needId: boolean): boolean =>
  isRec(x) && str(x.type) && (needId ? str(x.id) : true) && (x.properties === undefined || isRec(x.properties));
const action = (x: unknown): boolean => isRec(x) && str(x.name) && (x.properties === undefined || isRec(x.properties));
function pageOk(p: unknown): boolean {
  if (p === undefined) return true;
  if (!isRec(p)) return false;
  if (p.token !== undefined && typeof p.token !== 'string') return false;
  if (p.limit !== undefined && !(typeof p.limit === 'number' && Number.isSafeInteger(p.limit) && p.limit >= 0)) return false;
  return p.properties === undefined || isRec(p.properties);
}
const base = (b: Rec): boolean => isRec(b) && (b.context === undefined || isRec(b.context)) && pageOk(b.page);

export const isSubjectSearch = (b: unknown): b is SubjectSearchRequest =>
  isRec(b) && base(b) && entity(b.subject, false) && action(b.action) && entity(b.resource, true);
export const isResourceSearch = (b: unknown): b is ResourceSearchRequest =>
  isRec(b) && base(b) && entity(b.subject, true) && action(b.action) && entity(b.resource, false);
export const isActionSearch = (b: unknown): b is ActionSearchRequest =>
  isRec(b) && base(b) && !('action' in b) && entity(b.subject, true) && entity(b.resource, true);

/** The queried entity's `id` is ignored if present (spec); strip it so a provider cannot be steered by it. */
function stripId<T extends { subject: Rec } | { resource: Rec }>(req: T, key: 'subject' | 'resource'): T {
  const e = { ...(req as Rec)[key] as Rec };
  delete e.id;
  return { ...req, [key]: e };
}

function shape<T extends SearchEntity | SearchAction>(r: SearchResult<T>, limit: number | undefined, typeOk: (t: T) => boolean): SearchResponse<T> {
  const seen = new Set<string>();
  // Only entities of the searched type, de-duplicated, never more than the requested limit.
  const results = r.results.filter((t) => {
    const k = JSON.stringify(t);
    if (!typeOk(t) || seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const capped = limit !== undefined && limit > 0 ? results.slice(0, limit) : results;
  // A provider that ignores the requested limit would make us hide results behind a page marker we cannot resume: fail closed.
  if (capped.length < results.length) throw new Error('provider returned more than the page limit');
  const page = r.page ? { next_token: r.page.next_token, count: capped.length, ...(r.page.total !== undefined ? { total: r.page.total } : {}), ...(r.page.properties ? { properties: r.page.properties } : {}) } : undefined;
  return { ...(page ? { page } : {}), ...(r.context ? { context: r.context } : {}), results: capped };
}

export interface SearchHandlerRequest {
  path: string;
  body: unknown;
}
export interface SearchHandlerResponse {
  status: number;
  body: unknown;
}
/** Metadata fragment for `/.well-known/authzen-configuration` (a missing endpoint means that search is unsupported). */
export function searchMetadata(base: string, p: AuthzenSearchProvider): Record<string, string> {
  return {
    ...(p.searchSubject ? { search_subject_endpoint: `${base}${SEARCH_SUBJECT_PATH}` } : {}),
    ...(p.searchResource ? { search_resource_endpoint: `${base}${SEARCH_RESOURCE_PATH}` } : {}),
    ...(p.searchAction ? { search_action_endpoint: `${base}${SEARCH_ACTION_PATH}` } : {}),
  };
}

/** Returns `undefined` for a path that is not a search path, so it can be chained after {@link authzenHandler}. */
export function authzenSearchHandler(p: AuthzenSearchProvider): (req: SearchHandlerRequest) => Promise<SearchHandlerResponse | undefined> {
  return async (req) => {
    try {
      switch (req.path) {
        case SEARCH_SUBJECT_PATH: {
          if (!p.searchSubject) return { status: 404, body: { error: 'subject search is not supported' } };
          if (!isSubjectSearch(req.body)) return { status: 400, body: { error: 'invalid AuthZEN subject search request' } };
          const type = req.body.subject.type;
          const out = shape(await p.searchSubject(stripId(req.body, 'subject')), req.body.page?.limit, (e) => e.type === type);
          return { status: 200, body: out };
        }
        case SEARCH_RESOURCE_PATH: {
          if (!p.searchResource) return { status: 404, body: { error: 'resource search is not supported' } };
          if (!isResourceSearch(req.body)) return { status: 400, body: { error: 'invalid AuthZEN resource search request' } };
          const type = req.body.resource.type;
          return { status: 200, body: shape(await p.searchResource(stripId(req.body, 'resource')), req.body.page?.limit, (e) => e.type === type) };
        }
        case SEARCH_ACTION_PATH: {
          if (!p.searchAction) return { status: 404, body: { error: 'action search is not supported' } };
          if (!isActionSearch(req.body)) return { status: 400, body: { error: 'invalid AuthZEN action search request' } };
          return { status: 200, body: shape(await p.searchAction(req.body), req.body.page?.limit, () => true) };
        }
        default:
          return undefined;
      }
    } catch {
      return { status: 500, body: { error: 'internal error' } };
    }
  };
}
