import { siteGuard, type SiteDecision, type SiteGuardOptions } from '../guard';
import { absoluteUrl } from './url';

/** Fastify drop-in (`preHandler` hook). Structural shims; Fastify is never imported. */
export interface FastifyRequestLike {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  url?: string;
  protocol?: string;
  [k: string]: unknown;
}

export interface FastifyReplyLike {
  code(n: number): FastifyReplyLike;
  header(k: string, v: string): FastifyReplyLike;
  send(body: unknown): unknown;
}

export interface PcaSiteFastifyOptions extends SiteGuardOptions {
  publicOrigin?: string;
  attachAs?: string;
}

export function pcaSiteFastify(options: PcaSiteFastifyOptions) {
  const { publicOrigin, attachAs = 'pcaSite', ...guardOpts } = options;
  const guard = siteGuard(guardOpts);
  return async (req: FastifyRequestLike, reply: FastifyReplyLike): Promise<void> => {
    const decision: SiteDecision = await guard({ method: req.method ?? 'GET', url: absoluteUrl(req, publicOrigin), headers: req.headers, body: req.body });
    req[attachAs] = decision;
    if (decision.allow) return;
    reply.code(decision.status);
    for (const [k, v] of Object.entries(decision.headers)) reply.header(k, v);
    reply.send(decision.body ?? { error: decision.reason ?? 'forbidden' });
  };
}
