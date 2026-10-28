import type { KeyDirectory } from './index';
import { parseKeyDirectory, verifyDirectoryResponse } from './signed-directory';

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
  /**
   * Require the directory response signature of the Web Bot Auth directory draft (RFC 9421, `tag="http-message-signatures-directory"`,
   * covering `@authority;req`) and return only the keys that have a valid signature. Throws when none does. Default false.
   */
  requireSignature?: boolean;
  /** Clock (epoch seconds) for the signature check. Default now. */
  now?: number;
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
    const directory = parseKeyDirectory(text);
    if (options.requireSignature === true) {
      const authority = u.host.toLowerCase();
      const v = verifyDirectoryResponse({ authority, headers: { 'signature-input': res.headers.get('signature-input') ?? '', signature: res.headers.get('signature') ?? '' }, body: text, ...(options.now !== undefined ? { now: options.now } : {}) });
      if (!v.valid) throw new Error(`directory signature: ${v.reason}`);
      return { keys: v.keys };
    }
    return directory;
  } finally {
    clearTimeout(timer);
  }
}
