/**
 * Next.js App-Router helper for Proof-Carrying Authority.
 *
 *   export const POST = withPCA(
 *     { audience: 'ins_acme', resolveGrant, budgetStore, hooks, context },
 *     async (req, { pca }) => { const { verdict, pcactn } = pca; return Response.json({ ok: true }); },
 *   );
 *
 * It wraps a Route Handler so the inbound PCActn is verified with the framework-agnostic `requirePCA` guard
 * from `@atlasauth/pca` (default-deny: a required check that is unenforced DENIES) before your handler
 * runs. On success it calls your handler with `{ pca: { verdict, pcactn } }`; on failure it returns a 401/403
 * JSON response with a WWW-Authenticate challenge. The client sends the PCActn as `PCA-Action: <base64url>`
 * (see `@atlasauth/pca` `pcaHeaders`) or a JSON body `{ pcactn }`; that is exactly what the default extractor
 * reads, so no wiring is needed.
 *
 * `next` is an OPTIONAL peer dependency and is never imported — the handler takes the web `Request` and returns
 * a web `Response`, which is exactly what an App-Router Route Handler is.
 */

import { requirePCA, requireAuthorized, defaultExtract, memoryPcaStore } from '@atlasauth/pca';
import type { AuthorizeOptions, AuthorizedOperation, PcaGuardResult, RequirePcaOptions, PcaRequestLike, PcaStateStore, RequireAuthorizedOptions } from '@atlasauth/pca';
import type { PCActn } from '@atlasauth/pca';

/** The verdict + PCActn handed to the wrapped handler on success. */
export interface PcaAttachment {
  verdict: Extract<PcaGuardResult, { ok: true }>['verdict'];
  pcactn: PCActn;
  /** The operation the decision is bound to (only with the `operation` option). */
  operation?: AuthorizedOperation;
}

/** A Next.js App-Router Route Handler that receives the verified PCActn in its context. */
export type PcaRouteHandler = (req: Request, ctx: { pca: PcaAttachment }) => Response | Promise<Response>;

export interface PcaNextOptions extends RequirePcaOptions {
  /** Override the 401/403 response (otherwise a JSON error + WWW-Authenticate is returned). */
  onDeny?: (result: Extract<PcaGuardResult, { ok: false }>, req: Request) => Response | Promise<Response>;
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

/** Wrap an App-Router Route Handler so it only runs for a valid PCActn. */
export function withPCA(options: PcaNextOptions, handler: PcaRouteHandler): (req: Request) => Promise<Response> {
  const onDeny = options.onDeny;
  const guard = options.operation ? requireAuthorized(options as RequireAuthorizedOptions) : requirePCA(options);
  return async (req: Request): Promise<Response> => {
    const like: PcaRequestLike = {
      headers: { get: (n: string) => req.headers.get(n) },
      body: await req.clone().json().catch(() => undefined),
      method: req.method,
      url: req.url,
    };
    const result: PcaGuardResult = await guard(like);
    if (result.ok) {
      return handler(req, { pca: { verdict: result.verdict, pcactn: result.pcactn, ...(result.operation ? { operation: result.operation } : {}) } });
    }
    if (onDeny) return onDeny(result, req);
    return new Response(JSON.stringify({ error: result.verdict.reasons?.[0] ?? 'forbidden', verdict: result.verdict }), {
      status: result.status,
      headers: {
        'content-type': 'application/json',
        ...(result.wwwAuthenticate ? { 'WWW-Authenticate': result.wwwAuthenticate } : {}),
      },
    });
  };
}

export { requirePCA, requireAuthorized, defaultExtract, memoryPcaStore };
export type { PcaGuardResult, RequirePcaOptions, PcaStateStore };
