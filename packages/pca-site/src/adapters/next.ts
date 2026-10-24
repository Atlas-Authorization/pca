import { siteGuard, type SiteDecision, type SiteGuardOptions } from '../guard';
import { denyResponse, siteRequestOf } from './web';

/** Next.js App Router route-handler wrapper: `export const POST = withSiteRoute(opts, async (req, { pcaSite }) => ...)`. */
export type PcaSiteRouteHandler = (req: Request, ctx: { pcaSite: SiteDecision }) => Response | Promise<Response>;

export interface PcaSiteNextOptions extends SiteGuardOptions {
  /** Override the deny response. */
  onDeny?: (d: SiteDecision, req: Request) => Response | Promise<Response>;
}

export function withSiteRoute(options: PcaSiteNextOptions, handler: PcaSiteRouteHandler): (req: Request) => Promise<Response> {
  const { onDeny, ...guardOpts } = options;
  const guard = siteGuard(guardOpts);
  return async (req) => {
    const d = await guard(await siteRequestOf(req));
    if (d.allow) return handler(req, { pcaSite: d });
    return onDeny ? onDeny(d, req) : denyResponse(d);
  };
}
