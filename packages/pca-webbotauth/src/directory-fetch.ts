import type { KeyDirectory } from './index';

export interface FetchDirectoryOptions {
  /** The HTTP client (default: global `fetch`). Inject your own for SSRF-safe egress. */
  fetch?: (url: string, init: { redirect: 'error'; signal: AbortSignal; headers: Record<string, string> }) => Promise<{
    status: number;
    headers: { get(name: string): string | null };
    text(): Promise<string>;
  }>;
  /** Largest accepted response body in characters (default 65536). */
  maxBytes?: number;
  /** Request timeout in ms (default 5000). */
  timeoutMs?: number;
  /** Allow `http:` (tests only; default false: https only). */
  allowInsecureHttp?: boolean;
}

/**
 * Fetch and strictly parse a Web Bot Auth key directory. FAIL-CLOSED: throws on a non-https URL, redirect, non-200
 * status, wrong content type, oversize body, invalid JSON, or any key that is not a well-formed Ed25519 OKP JWK with
 * a string `kid` and 32-byte `x`. Never returns a partial directory.
 */
export async function fetchKeyDirectory(url: string, options: FetchDirectoryOptions = {}): Promise<KeyDirectory> {
  const u = new URL(url);
  if (u.protocol !== 'https:' && !(options.allowInsecureHttp === true && u.protocol === 'http:')) throw new Error('directory URL must be https');
  const doFetch = options.fetch ?? ((x, i) => fetch(x, i));
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), options.timeoutMs ?? 5000);
  try {
    const res = await doFetch(u.href, { redirect: 'error', signal: ctl.signal, headers: { accept: 'application/http-message-signatures-directory+json' } });
    if (res.status !== 200) throw new Error(`directory fetch returned status ${res.status}`);
    const ct = (res.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase();
    if (ct !== 'application/http-message-signatures-directory+json') throw new Error('directory has the wrong content type');
    const text = await res.text();
    if (text.length > (options.maxBytes ?? 65536)) throw new Error('directory response is too large');
    const doc: unknown = JSON.parse(text);
    const keys = (doc as { keys?: unknown } | null)?.keys;
    if (!Array.isArray(keys) || keys.length === 0) throw new Error('directory has no keys');
    for (const k of keys) {
      const j = k as Record<string, unknown> | null;
      if (typeof j !== 'object' || j === null || j.kty !== 'OKP' || j.crv !== 'Ed25519' || typeof j.kid !== 'string' || j.kid === '') {
        throw new Error('directory contains a malformed key');
      }
      if (typeof j.x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(j.x) || Buffer.from(j.x, 'base64url').length !== 32) throw new Error('directory contains a malformed key');
      for (const f of ['nbf', 'exp'] as const) if (j[f] !== undefined && !Number.isFinite(j[f])) throw new Error('directory contains a malformed key');
    }
    return doc as KeyDirectory;
  } finally {
    clearTimeout(timer);
  }
}
