import { siteGuard, type SiteDecision, type SiteGuardOptions, type SiteRequest } from '../guard';
import { absoluteUrl } from './url';

/**
 * Express drop-in: `app.use(pcaSiteExpress({ audience, policy, verbOf, pca, intent, siteKey, ... }))`. Structural
 * shims only (Express 4 and 5): the framework is never imported. On allow the decision is attached as `req.pcaSite`
 * (or `attachAs`) and `next()` runs; otherwise the guard's status, headers and (problem+json) body are sent.
 */
export interface ExpressRequestLike {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  originalUrl?: string;
  url?: string;
  protocol?: string;
  [k: string]: unknown;
}

export interface ExpressResponseLike {
  status(code: number): ExpressResponseLike;
  set(field: string, value: string): ExpressResponseLike;
  json(body: unknown): unknown;
}

export type ExpressNextLike = (err?: unknown) => void;

export interface PcaSiteExpressOptions extends SiteGuardOptions {
  /** The site's public origin when a proxy rewrites Host / scheme (recommended in production). */
  publicOrigin?: string;
  attachAs?: string;
}

export function pcaSiteExpress(options: PcaSiteExpressOptions) {
  const { publicOrigin, attachAs = 'pcaSite', ...guardOpts } = options;
  const guard = siteGuard(guardOpts);
  return async (req: ExpressRequestLike, res: ExpressResponseLike, next: ExpressNextLike): Promise<void> => {
    let decision: SiteDecision;
    try {
      const sreq: SiteRequest = { method: req.method ?? 'GET', url: absoluteUrl(req, publicOrigin), headers: req.headers, body: req.body };
      decision = await guard(sreq);
    } catch (e) {
      next(e);
      return;
    }
    req[attachAs] = decision;
    if (decision.allow) {
      next();
      return;
    }
    res.status(decision.status);
    for (const [k, v] of Object.entries(decision.headers)) res.set(k, v);
    res.json(decision.body ?? { error: decision.reason ?? 'forbidden' });
  };
}
