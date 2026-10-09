/**
 * Hono middleware for Proof-Carrying Authority.
 *
 *   app.post('/refunds', pcaHono({ audience: 'ins_acme', resolveGrant, budgetStore, hooks, context }),
 *     (c) => { const { verdict, pcactn } = c.get('pca'); ... });
 *
 * It verifies the inbound PCActn with the framework-agnostic `requirePCA` guard from `@atlasauth/pca`
 * (default-deny: a required check that is unenforced DENIES) and, on success, sets the verdict + PCActn on the
 * context via `c.set(attachAs)` (default `pca`) then calls `next()`. On failure it answers 401/403 with a
 * WWW-Authenticate challenge. The client sends the PCActn as `PCA-Action: <base64url>` (see `@atlasauth/pca`
 * `pcaHeaders`) or a JSON body `{ pcactn }`; that is exactly what the default extractor reads, so no wiring is
 * needed.
 *
 * `hono` is an OPTIONAL peer dependency and is never imported — the context shape is structural, so this stays
 * compatible across Hono 4 runtimes.
 */

import { requirePCA, defaultExtract, memoryPcaStore } from '@atlasauth/pca';
import type { PcaGuardResult, RequirePcaOptions, PcaRequestLike, PcaStateStore } from '@atlasauth/pca';
import type { PCActn } from '@atlasauth/pca';

/** Structural shim of a Hono context (the subset the middleware uses). */
export interface HonoContextLike {
  req: { header(name: string): string | undefined; json(): Promise<unknown> };
  set(key: string, value: unknown): void;
  json(body: unknown, status?: number, headers?: Record<string, string>): Response;
}

export type HonoNext = () => Promise<void>;

/** The verdict + PCActn set on the context on success. */
export interface PcaAttachment {
  verdict: Extract<PcaGuardResult, { ok: true }>['verdict'];
  pcactn: PCActn;
}

export interface PcaHonoOptions extends RequirePcaOptions {
  /** Context key to `c.set` `{ verdict, pcactn }` on (default `pca`). */
  attachAs?: string;
  /** Override the 401/403 response (otherwise a JSON error + WWW-Authenticate is sent). */
  onDeny?: (result: Extract<PcaGuardResult, { ok: false }>, c: HonoContextLike) => Response;
}

/** Build a Hono middleware that requires a valid PCActn on the request. */
export function pcaHono(options: PcaHonoOptions) {
  const attachAs = options.attachAs ?? 'pca';
  const onDeny = options.onDeny;
  const guard = requirePCA(options);
  return async (c: HonoContextLike, next: HonoNext): Promise<Response | void> => {
    const req: PcaRequestLike = {
      headers: { get: (n: string) => c.req.header(n) ?? null },
      body: await c.req.json().catch(() => undefined),
    };
    const result: PcaGuardResult = await guard(req);
    if (result.ok) {
      c.set(attachAs, { verdict: result.verdict, pcactn: result.pcactn });
      await next();
      return;
    }
    if (onDeny) return onDeny(result, c);
    return c.json(
      { error: result.verdict.reasons?.[0] ?? 'forbidden', verdict: result.verdict },
      result.status,
      result.wwwAuthenticate ? { 'WWW-Authenticate': result.wwwAuthenticate } : undefined,
    );
  };
}

export { requirePCA, defaultExtract, memoryPcaStore };
export type { PcaGuardResult, RequirePcaOptions, PcaStateStore };
