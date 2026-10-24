import { siteGuard, type SiteDecision, type SiteGuardOptions } from '../guard';
import { denyResponse, siteRequestOf } from './web';

/**
 * Web Fetch drop-in (Cloudflare Workers, Deno, Bun, Vercel Edge, Netlify, Lambda Function URLs). For enforcement at the
 * gateway instead (Envoy ext_authz / Istio CUSTOM, Workers in front of an origin, AWS API Gateway authorizers), see
 * `@atlasauth/pca-gateway`; a Worker in front of an origin can also simply use this adapter.
 */
export type PcaSiteFetchHandler = (req: Request, ctx: { pcaSite: SiteDecision }) => Response | Promise<Response>;

export function createSiteFetchGuard(options: SiteGuardOptions): (req: Request) => Promise<SiteDecision> {
  const guard = siteGuard(options);
  return async (req) => guard(await siteRequestOf(req));
}

export function withSite(options: SiteGuardOptions, handler: PcaSiteFetchHandler): (req: Request) => Promise<Response> {
  const guard = createSiteFetchGuard(options);
  return async (req) => {
    const d = await guard(req);
    return d.allow ? handler(req, { pcaSite: d }) : denyResponse(d);
  };
}
