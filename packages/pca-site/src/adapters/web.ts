import type { SiteDecision, SiteRequest } from '../guard';

/** Adapt a web `Request` (Fetch, Next.js App Router, Hono's `c.req.raw`) to the guard's request shape. */
export async function siteRequestOf(req: Request): Promise<SiteRequest> {
  const headers: Record<string, string> = {};
  req.headers.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
  });
  let body: unknown;
  const type = req.headers.get('content-type') ?? '';
  if (/^application\/([a-z0-9.+-]*\+)?json\b/i.test(type)) {
    try {
      // The raw text, so requirePCA can apply its strict JSON profile to a string `pcactn` body.
      body = await req.clone().text();
    } catch {
      body = undefined;
    }
  }
  return { method: req.method, url: req.url, headers, body };
}

/** A deny decision as a web `Response`. */
export function denyResponse(d: SiteDecision): Response {
  const headers = new Headers(d.headers);
  if (!headers.has('content-type')) headers.set('content-type', 'application/json');
  return new Response(JSON.stringify(d.body ?? { error: d.reason ?? 'forbidden' }), { status: d.status, headers });
}
