import { siteGuard, type SiteGuardOptions } from '../guard';
import { denyResponse, siteRequestOf } from './web';

/** Hono drop-in: `app.use('/api/*', pcaSiteHono(opts))`. Structural shim over `c.req.raw` (the web Request). */
export interface HonoContextLike {
  req: { raw: Request };
  set(key: string, value: unknown): void;
}

export type HonoNext = () => Promise<void>;

export interface PcaSiteHonoOptions extends SiteGuardOptions {
  attachAs?: string;
}

export function pcaSiteHono(options: PcaSiteHonoOptions) {
  const { attachAs = 'pcaSite', ...guardOpts } = options;
  const guard = siteGuard(guardOpts);
  return async (c: HonoContextLike, next: HonoNext): Promise<Response | void> => {
    const d = await guard(await siteRequestOf(c.req.raw));
    c.set(attachAs, d);
    if (!d.allow) return denyResponse(d);
    await next();
  };
}
