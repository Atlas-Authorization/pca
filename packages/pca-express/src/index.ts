/**
 * Express middleware for Proof-Carrying Authority.
 *
 *   app.post('/refunds',
 *     pcaExpress({ audience: 'ins_acme', resolveGrant, budgetStore, hooks, context }),
 *     (req, res) => { const { verdict, pcactn } = req.pca!; ... });
 *
 * It verifies the inbound PCActn with the framework-agnostic `requirePCA` guard from `@atlasauth/pca`
 * (default-deny: a required check that is unenforced DENIES) and, on success, attaches the verdict +
 * PCActn to `req[attachAs]` (default `req.pca`). On failure it answers 401/403 with a WWW-Authenticate
 * challenge. The client sends the PCActn as `PCA-Action: <base64url>` (see `@atlasauth/pca` `pcaHeaders`)
 * or a JSON body `{ pcactn }`; that is exactly what the default extractor reads, so no wiring is needed.
 *
 * `express` is an OPTIONAL peer dependency and is never imported — the request/response/next shapes are
 * structural, so this stays compatible across Express 4 and 5.
 */

import { requirePCA, requireAuthorized, defaultExtract, memoryPcaStore } from '@atlasauth/pca';
import type { AuthorizeOptions, AuthorizedOperation, PcaGuardResult, RequirePcaOptions, PcaRequestLike, PcaStateStore, RequireAuthorizedOptions } from '@atlasauth/pca';
import type { PCActn } from '@atlasauth/pca';

/** Structural shim of an Express request (only `headers`/`body` are read; the rest passes through). */
export interface ExpressRequestLike {
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  method?: string;
  originalUrl?: string;
  url?: string;
  [k: string]: unknown;
}

/** Structural shim of an Express response (the chainable subset the middleware uses). */
export interface ExpressResponseLike {
  status(code: number): ExpressResponseLike;
  set(field: string, value: string): ExpressResponseLike;
  json(body: unknown): unknown;
}

export type ExpressNextLike = (err?: unknown) => void;

/** The verdict + PCActn attached to the request on success. */
export interface PcaAttachment {
  verdict: Extract<PcaGuardResult, { ok: true }>['verdict'];
  pcactn: PCActn;
  /** The operation the decision is bound to (only with the `operation` option). */
  operation?: AuthorizedOperation;
}

export interface PcaExpressOptions extends RequirePcaOptions {
  /** Property on `req` to attach `{ verdict, pcactn }` to (default `pca`). */
  attachAs?: string;
  /** Override the 401/403 response (otherwise a JSON error + WWW-Authenticate is sent). */
  onDeny?: (result: Extract<PcaGuardResult, { ok: false }>, req: ExpressRequestLike, res: ExpressResponseLike) => void;
  /**
   * The operation each request will execute, from your routing (verb / resource for the route, the parsed body as
   * params), never from the PCActn. When set, requests are authorized by `authorize` (the strict pipeline: `budgetStore`
   * and `hooks.revocation` are required, and a proof for another operation, other params, or params outside the grant
   * is refused before your handler runs) and the bound `operation` is attached with the verdict. Absent: `requirePCA`,
   * unchanged.
   */
  operation?: RequirePcaOptions['operation'];
  /** With `operation`: `'single-step'` accepts a one-node plan equal to the bound operation (see `authorize`). */
  plan?: AuthorizeOptions['plan'];
}

/** Build an Express middleware that requires a valid PCActn on the request. */
export function pcaExpress(options: PcaExpressOptions) {
  const attachAs = options.attachAs ?? 'pca';
  const onDeny = options.onDeny;
  const guard = options.operation ? requireAuthorized(options as RequireAuthorizedOptions) : requirePCA(options);
  return async (req: ExpressRequestLike, res: ExpressResponseLike, next: ExpressNextLike): Promise<void> => {
    let result: PcaGuardResult;
    try {
      result = await guard({ headers: req.headers, body: req.body, method: req.method, url: req.originalUrl ?? req.url } as PcaRequestLike);
    } catch (e) {
      next(e);
      return;
    }
    if (result.ok) {
      (req as Record<string, unknown>)[attachAs] = { verdict: result.verdict, pcactn: result.pcactn, ...(result.operation ? { operation: result.operation } : {}) };
      next();
      return;
    }
    if (onDeny) {
      onDeny(result, req, res);
      return;
    }
    res.status(result.status);
    if (result.wwwAuthenticate) res.set('WWW-Authenticate', result.wwwAuthenticate);
    res.json({ error: result.verdict.reasons?.[0] ?? 'forbidden', verdict: result.verdict });
  };
}

export { requirePCA, requireAuthorized, defaultExtract, memoryPcaStore };
export type { PcaGuardResult, RequirePcaOptions, PcaStateStore };
