// proxy.ts - K7 vault proxy mode: re-derive the params digest of the OUTBOUND request, and the signed release receipt.
//
// The agent never holds the credential. It hands the vault the request it wants made; the vault maps that request back to the
// action's parameters with a pinned extractor, requires paramsDigest(params) to equal the PCActn's signed `params_digest`, and only
// then attaches the token and makes the call itself. The extractor is operator code bound to the confirmed definition: anything the
// request carries that the extractor does not map (an extra query key, an extra body member, a header, a redirect target) is a
// mismatch and is refused, so the credential can serve exactly the authorized request.

import { escalationActionDigest, hashCanonical, strictParse, type PCActn } from '@atlasauth/pca';
import { signArtifact, verifyArtifactSig } from '@atlasauth/pca/ext/intent';
import { RequestMismatchError } from './errors';

export interface ProxyRequest {
  method: string;
  /** Absolute https URL. */
  url: string;
  headers?: Record<string, string>;
  /** The request body as text (JSON or form encoded). */
  body?: string;
}

export interface ProxyResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * The injected outbound transport. It MUST NOT follow redirects (a redirect would send the credential to a host the extractor never
 * saw): the vault passes `redirect: 'manual'` and returns a 3xx to the caller as is.
 */
export type ProxyFetch = (req: { method: string; url: string; headers: Record<string, string>; body?: string; redirect: 'manual' }) => Promise<ProxyResponse>;

export interface HttpRequestSpec {
  /** Exact method, upper case. */
  method: string;
  /** `https://host/path/{param}/more`: literal text matches exactly; each `{name}` is one path segment and becomes the string parameter `name`. No query, no fragment. */
  url: string;
  /** Query keys that may appear; each present key becomes the string parameter of that name. */
  query?: readonly string[];
  /** `json`: the body is a strict-JSON object whose members are parameters. `form`: urlencoded, string parameters. Absent: no body. */
  body?: 'json' | 'form';
  /** Body members the request always carries with exactly these values (not parameters). */
  fixed?: Record<string, unknown>;
}

const mismatch = (m: string): never => { throw new RequestMismatchError(`outbound request refused: ${m}`); };
const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const PLACEHOLDER = /\{([A-Za-z0-9_]+)\}/g;

/** Build the extractor for one operation. Throws on a malformed spec (at configuration time, not at call time). */
export function httpExtractor(spec: HttpRequestSpec): (req: ProxyRequest) => Record<string, unknown> {
  const u = new URL(spec.url.replace(PLACEHOLDER, 'x'));
  if (u.protocol !== 'https:' || u.search !== '' || u.hash !== '' || u.username !== '' || u.password !== '') throw new TypeError('httpExtractor: url must be https without query, fragment or userinfo');
  if (spec.method !== spec.method.toUpperCase()) throw new TypeError('httpExtractor: method must be upper case');
  const names: string[] = [];
  const origin = u.origin;
  const pathTemplate = spec.url.slice(origin.length);
  const re = new RegExp(`^${pathTemplate.split(PLACEHOLDER).map((part, i) => (i % 2 === 1 ? (names.push(part), '([A-Za-z0-9._~%-]+)') : esc(part))).join('')}$`);
  const allowedQuery = new Set(spec.query ?? []);
  const ctype = spec.body === 'json' ? 'application/json' : spec.body === 'form' ? 'application/x-www-form-urlencoded' : undefined;
  return (req) => {
    if (req.method !== spec.method) mismatch(`method ${String(req.method)} is not ${spec.method}`);
    let r: URL;
    try { r = new URL(req.url); } catch { return mismatch('the url does not parse'); }
    if (r.origin !== origin || r.username !== '' || r.password !== '' || r.hash !== '') mismatch('the url is not on the pinned origin');
    const m = re.exec(r.pathname);
    if (m === null) return mismatch('the path does not match the pinned template');
    const params: Record<string, unknown> = {};
    const put = (k: string, v: unknown): void => {
      if (Object.prototype.hasOwnProperty.call(params, k)) mismatch(`parameter '${k}' is carried twice`);
      params[k] = v;
    };
    names.forEach((n, i) => { try { put(n, decodeURIComponent(m[i + 1]!)); } catch (e) { if (e instanceof RequestMismatchError) throw e; mismatch('a path segment is not valid percent-encoding'); } });
    const seen = new Set<string>();
    for (const [k, v] of r.searchParams) {
      if (!allowedQuery.has(k)) mismatch(`query key '${k}' is not allowed`);
      if (seen.has(k)) mismatch(`query key '${k}' is repeated`);
      seen.add(k);
      put(k, v);
    }
    const ct = Object.entries(req.headers ?? {}).find(([h]) => h.toLowerCase() === 'content-type')?.[1];
    if (spec.body === undefined) {
      if (req.body !== undefined && req.body !== '') mismatch('this operation carries no body');
    } else {
      if (typeof req.body !== 'string' || req.body.length === 0) return mismatch('the body is missing');
      if (ct === undefined || ct.split(';')[0]!.trim().toLowerCase() !== ctype) mismatch(`content-type must be ${ctype}`);
      const fixed = { ...(spec.fixed ?? {}) };
      if (spec.body === 'json') {
        let b: unknown;
        try { b = strictParse(req.body); } catch { return mismatch('the body is not strict JSON'); }
        if (b === null || typeof b !== 'object' || Array.isArray(b)) mismatch('the body must be a JSON object');
        for (const [k, v] of Object.entries(b as Record<string, unknown>)) {
          if (Object.prototype.hasOwnProperty.call(fixed, k)) {
            if (hashCanonical(v) !== hashCanonical(fixed[k])) mismatch(`fixed member '${k}' has another value`);
            delete fixed[k];
          } else put(k, v);
        }
      } else {
        const f = new URLSearchParams(req.body);
        const keys = new Set<string>();
        for (const [k, v] of f) {
          if (keys.has(k)) mismatch(`form key '${k}' is repeated`);
          keys.add(k);
          if (Object.prototype.hasOwnProperty.call(fixed, k)) {
            if (v !== fixed[k]) mismatch(`fixed member '${k}' has another value`);
            delete fixed[k];
          } else put(k, v);
        }
      }
      if (Object.keys(fixed).length > 0) mismatch(`fixed member(s) ${Object.keys(fixed).join(', ')} missing`);
    }
    return params;
  };
}

/** Request headers the agent may set; the vault sets Authorization itself. Anything else is refused (Host, Cookie, X-HTTP-Method-Override, ...). */
export const DEFAULT_PROXY_HEADERS: readonly string[] = ['content-type', 'accept', 'idempotency-key'];

export function checkProxyHeaders(headers: Record<string, string> | undefined, allow: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers ?? {})) {
    const n = k.toLowerCase();
    if (!allow.includes(n)) mismatch(`header '${k}' is not allowed`);
    if (Object.prototype.hasOwnProperty.call(out, n)) mismatch(`header '${k}' is repeated`);
    if (typeof v !== 'string' || /[\r\n\0]/.test(v)) mismatch(`header '${k}' has an invalid value`);
    out[n] = v;
  }
  return out;
}

// ---- release receipt ----------------------------------------------------------------------------------------------------

export const RELEASE_RECEIPT_DOMAIN = 'atlas-pca/connect-release-receipt/v1\0';

export interface ReleaseReceiptBody {
  v: 1;
  kind: 'pca-release-receipt';
  /** Digest of the exact PCActn that authorized the release (`escalationActionDigest`). */
  action_digest: string;
  provider: string;
  connection_id: string;
  mode: 'proxy' | 'bearer';
  /** The scopes the credential carried when it was used or released. */
  scopes_released: string[];
  /** Proxy mode: digest of the outbound request as made (method, url, headers sent, body). Bearer mode: null (the vault never sees the call). */
  request_digest: string | null;
  /** Proxy mode: the upstream HTTP status, or null when the call did not complete. */
  http_status: number | null;
  outcome: 'released' | 'executed' | 'failed';
  ts: number;
}
export type ReleaseReceipt = ReleaseReceiptBody & { sig: string };

export const outboundRequestDigest = (method: string, url: string, headers: Record<string, string>, body: string | undefined): string =>
  hashCanonical({ d: 'atlas-pca/connect-request/v1', method, url, headers, body: body ?? null });

export function signReleaseReceipt(body: ReleaseReceiptBody, secretKey: Uint8Array): ReleaseReceipt {
  return signArtifact(RELEASE_RECEIPT_DOMAIN, body as unknown as Record<string, unknown>, secretKey) as unknown as ReleaseReceipt;
}

/** True iff the receipt is signed by the pinned vault key. */
export const verifyReleaseReceipt = (r: ReleaseReceipt, vaultPk: string): boolean => verifyArtifactSig(RELEASE_RECEIPT_DOMAIN, r as unknown as Record<string, unknown>, vaultPk);

export const receiptActionDigest = (p: PCActn): string => escalationActionDigest(p);
