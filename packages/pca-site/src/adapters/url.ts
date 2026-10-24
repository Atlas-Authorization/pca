/**
 * Rebuild the absolute URL a client addressed from a Node-style request (Express, Fastify). RFC 9421 signatures
 * cover `@authority` and `@path`, so the guard needs the URL as the CLIENT saw it. Behind a proxy that rewrites
 * the host or scheme, pass `publicOrigin` (e.g. `https://api.example.com`): forwarded headers are client-controlled
 * and are never trusted here.
 */
export function absoluteUrl(req: { headers: Record<string, string | string[] | undefined>; originalUrl?: unknown; url?: unknown; protocol?: unknown }, publicOrigin?: string): string {
  const path = typeof req.originalUrl === 'string' ? req.originalUrl : typeof req.url === 'string' ? req.url : '/';
  if (publicOrigin !== undefined) return new URL(path, publicOrigin).href;
  const hostRaw = req.headers['host'] ?? req.headers['Host'];
  const host = Array.isArray(hostRaw) ? hostRaw[0] : hostRaw;
  if (typeof host !== 'string' || host.length === 0) throw new Error('cannot rebuild the request URL: no Host header (set publicOrigin)');
  const scheme = req.protocol === 'http' ? 'http' : 'https';
  return new URL(path, `${scheme}://${host}`).href;
}
