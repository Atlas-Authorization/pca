/**
 * Runtime-neutral Web Fetch guard for Proof-Carrying Authority.
 *
 * Works in any `Request → Response` runtime — Cloudflare Workers, Deno, Bun, Vercel Edge, Netlify, a
 * Lambda Function URL — using only the web platform (no Node APIs), so the same code protects a
 * resource server wherever it runs on the internet:
 *
 *   export default { fetch: withPCA({ audience, resolveGrant, context }, async (req, { pca }) => {
 *     return Response.json({ ok: true, verdict: pca.verdict });
 *   }) };
 *
 * It verifies the inbound PCActn with the framework-agnostic `requirePCA` guard from
 * `@atlasauth/pca` (default-deny) and, on success, calls your handler with the verdict + PCActn;
 * otherwise it returns a 401/403 `Response` with a WWW-Authenticate challenge. The client sends the
 * PCActn as `PCA-Action: <base64url>` (see `@atlasauth/pca` `pcaHeaders`) or a JSON body `{ pcactn }`.
 * Nothing here authorizes on its own — the resource server's verifier decides.
 */

import { requirePCA, requireAuthorized, defaultExtract, memoryPcaStore } from '@atlasauth/pca';
import type { AuthorizeOptions, AuthorizedOperation, PcaGuardResult, RequirePcaOptions, PcaRequestLike, PcaStateStore, RequireAuthorizedOptions } from '@atlasauth/pca';
import type { PCActn } from '@atlasauth/pca';

/** The verdict + PCActn handed to a guarded handler on success. */
export interface PcaContextValue {
  verdict: Extract<PcaGuardResult, { ok: true }>['verdict'];
  pcactn: PCActn;
  /** The operation the decision is bound to (only with the `operation` option). */
  operation?: AuthorizedOperation;
}

export interface PcaFetchOptions extends RequirePcaOptions {
  /** Shape the 401/403 body (default: `{ error, verdict }`). */
  denyBody?: (result: Extract<PcaGuardResult, { ok: false }>) => unknown;
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

/** Adapt a web `Request` to the framework-agnostic `PcaRequestLike` (headers getter + parsed JSON body). */
async function toPcaRequest(req: Request): Promise<PcaRequestLike> {
  let body: unknown;
  try {
    // clone so the handler can still read the body; ignore non-JSON bodies.
    body = await req.clone().json();
  } catch {
    body = undefined;
  }
  return { headers: { get: (name: string) => req.headers.get(name) }, body, method: req.method, url: req.url };
}

function denyResponse(result: Extract<PcaGuardResult, { ok: false }>, denyBody?: PcaFetchOptions['denyBody']): Response {
  const body = denyBody ? denyBody(result) : { error: result.verdict.reasons?.[0] ?? 'forbidden', verdict: result.verdict, decision: result.decision ?? 'deny', ...(result.escalation ? { escalation: result.escalation } : {}) };
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (result.wwwAuthenticate) headers['WWW-Authenticate'] = result.wwwAuthenticate;
  return new Response(JSON.stringify(body), { status: result.status, headers });
}

/**
 * Build a verifier over a web `Request`. Returns the full guard result so you can compose it yourself
 * (e.g. inside an existing router). Use `withPCA` for the common wrap-a-handler case.
 */
export function createPcaFetchGuard(options: PcaFetchOptions): (req: Request) => Promise<PcaGuardResult> {
  const guard = options.operation ? requireAuthorized(options as RequireAuthorizedOptions) : requirePCA(options);
  return async (req: Request) => guard(await toPcaRequest(req));
}

export type PcaFetchHandler = (req: Request, ctx: { pca: PcaContextValue }) => Response | Promise<Response>;

/** Wrap a Fetch handler so the inbound PCActn is verified first; on success your handler runs with the verdict. */
export function withPCA(options: PcaFetchOptions, handler: PcaFetchHandler): (req: Request) => Promise<Response> {
  const guard = createPcaFetchGuard(options);
  return async (req: Request): Promise<Response> => {
    const result = await guard(req);
    if (result.ok) return handler(req, { pca: { verdict: result.verdict, pcactn: result.pcactn, ...(result.operation ? { operation: result.operation } : {}) } });
    return denyResponse(result, options.denyBody);
  };
}

export { requirePCA, requireAuthorized, defaultExtract, memoryPcaStore };
export type { PcaGuardResult, RequirePcaOptions, PcaStateStore };
