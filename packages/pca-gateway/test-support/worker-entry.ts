/**
 * Cloudflare Worker entry used ONLY by the workerd (miniflare) test. It wires the gateway's
 * `cloudflareWorker` adapter to the platform's real `Request` / `Response` classes. Configuration
 * arrives through bindings so the test can mint a proof in Node and hand the matching grant over.
 */
import { cloudflareWorker, type Capability, type RouteRule } from '../src/index';

interface Env {
  AUDIENCE: string;
  ROUTES: string;
  GRANT_REF: string;
  GRANT_JSON: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const handler = cloudflareWorker<Request, Response>({
      audience: env.AUDIENCE,
      routes: JSON.parse(env.ROUTES) as RouteRule[],
      resolveGrant: async (ref: string): Promise<Capability | null> =>
        ref === env.GRANT_REF ? (JSON.parse(env.GRANT_JSON) as Capability) : null,
      next: (): Response => new Response('upstream-reached', { status: 200 }),
      respond: (body: string, init: { status: number; headers: Record<string, string> }): Response =>
        new Response(body, init),
    });
    return handler(request);
  },
};
