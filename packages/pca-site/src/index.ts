/**
 * @atlasauth/pca-site: the site adoption kit of the PCA Intent Layer v2 (docs/specs/pca-intent-layer-v2.md §3.15, §5).
 *
 * Access tiers 0–4 as data and presets, the §5 verifier policy parser, the discovery `intent` block, a
 * framework-neutral site guard (Web Bot Auth → requirePCA → intent port → JIT → bond + evidence), drop-in adapters for
 * Express, Fastify, Hono, Next.js and Web Fetch runtimes, and the agent-side tier planner.
 */
export * from './tiers';
export * from './policy';
export * from './discovery';
export * from './guard';
export * from './agent';
export { pcaSiteExpress, type PcaSiteExpressOptions, type ExpressRequestLike, type ExpressResponseLike, type ExpressNextLike } from './adapters/express';
export { pcaSiteFastify, type PcaSiteFastifyOptions, type FastifyRequestLike, type FastifyReplyLike } from './adapters/fastify';
export { pcaSiteHono, type PcaSiteHonoOptions, type HonoContextLike, type HonoNext } from './adapters/hono';
export { withSiteRoute, type PcaSiteNextOptions, type PcaSiteRouteHandler } from './adapters/next';
export { withSite, createSiteFetchGuard, type PcaSiteFetchHandler } from './adapters/fetch';
export { siteRequestOf } from './adapters/web';
export { absoluteUrl } from './adapters/url';
