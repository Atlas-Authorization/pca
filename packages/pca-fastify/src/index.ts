/**
 * Fastify preHandler for Proof-Carrying Authority.
 *
 *   app.post('/refunds', { preHandler: pcaFastify({ audience: 'ins_acme', resolveGrant, budgetStore, hooks, context }) },
 *     async (req, reply) => { const { verdict, pcactn } = (req as { pca: PcaAttachment }).pca; ... });
 *
 * It verifies the inbound PCActn with the framework-agnostic `requirePCA` guard from `@atlasauth/pca`
 * (default-deny: a required check that is unenforced DENIES) and, on success, attaches the verdict +
 * PCActn to `req[attachAs]` (default `req.pca`) and returns so the route handler runs. On failure it answers
 * 401/403 with a WWW-Authenticate challenge (sending from a preHandler short-circuits the route). The client
 * sends the PCActn as `PCA-Action: <base64url>` (see `@atlasauth/pca` `pcaHeaders`) or a JSON body
 * `{ pcactn }`; that is exactly what the default extractor reads, so no wiring is needed.
 *
 * `fastify` is an OPTIONAL peer dependency and is never imported — the request/reply shapes are structural,
 * so this stays compatible across Fastify 4 and 5.
 */

import { requirePCA, defaultExtract, memoryPcaStore } from '@atlasauth/pca';
import type { PcaGuardResult, RequirePcaOptions, PcaRequestLike, PcaStateStore } from '@atlasauth/pca';
import type { PCActn } from '@atlasauth/pca';

/** Structural shim of a Fastify request (only `headers`/`body` are read; the rest passes through). */
export interface FastifyRequestLike {
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  [k: string]: unknown;
}

/** Structural shim of a Fastify reply (the chainable subset the preHandler uses). */
export interface FastifyReplyLike {
  code(n: number): FastifyReplyLike;
  header(k: string, v: string): FastifyReplyLike;
  send(body: unknown): unknown;
}

/** The verdict + PCActn attached to the request on success. */
export interface PcaAttachment {
  verdict: Extract<PcaGuardResult, { ok: true }>['verdict'];
  pcactn: PCActn;
}

export interface PcaFastifyOptions extends RequirePcaOptions {
  /** Property on `req` to attach `{ verdict, pcactn }` to (default `pca`). */
  attachAs?: string;
  /** Override the 401/403 response (otherwise a JSON error + WWW-Authenticate is sent). */
  onDeny?: (result: Extract<PcaGuardResult, { ok: false }>, req: FastifyRequestLike, reply: FastifyReplyLike) => void;
}

/** Build a Fastify preHandler that requires a valid PCActn on the request. */
export function pcaFastify(options: PcaFastifyOptions) {
  const attachAs = options.attachAs ?? 'pca';
  const onDeny = options.onDeny;
  const guard = requirePCA(options);
  return async (req: FastifyRequestLike, reply: FastifyReplyLike): Promise<void> => {
    const result: PcaGuardResult = await guard({ headers: req.headers, body: req.body } as PcaRequestLike);
    if (result.ok) {
      (req as Record<string, unknown>)[attachAs] = { verdict: result.verdict, pcactn: result.pcactn };
      return;
    }
    if (onDeny) {
      onDeny(result, req, reply);
      return;
    }
    reply.code(result.status);
    if (result.wwwAuthenticate) reply.header('WWW-Authenticate', result.wwwAuthenticate);
    reply.send({ error: result.verdict.reasons?.[0] ?? 'forbidden', verdict: result.verdict });
  };
}

export { requirePCA, defaultExtract, memoryPcaStore };
export type { PcaGuardResult, RequirePcaOptions, PcaStateStore };
