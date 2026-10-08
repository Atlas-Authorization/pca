/**
 * QRNG (quantum random number generator) entropy integration for PCA key generation.
 *
 * HONEST SCOPE: this module adds real quantum entropy to key generation and is usable today. It is
 * NOT a quantum root of trust and makes NO post-quantum security claim. Post-quantum resistance comes
 * from the ML-DSA / SLH-DSA signature suites (see `pq.ts`); QRNG here only improves the *quality* of the
 * entropy that feeds key derivation. It is an entropy ADD, never a trust dependency: if the QRNG is
 * unavailable, slow, malformed, or fully adversarial, key generation still proceeds from the local
 * CSPRNG with its full strength intact.
 *
 * SAFETY INVARIANT (mix, never replace): every seed is `HKDF-SHA256(localCsprng ‖ quantum)`. Because the
 * local CSPRNG bytes are ALWAYS part of the HKDF input keying material, the derived seed is a pseudorandom
 * function of a secret the attacker does not control. An attacker who fully controls the quantum bytes
 * (constant, chosen, empty, biased) therefore cannot weaken the seed below the strength of the local
 * CSPRNG alone — this is the classic robust randomness combiner (concatenate, then extract). A genuine
 * high-entropy quantum source strengthens a weak local source symmetrically. Quantum bytes are NEVER used
 * raw as a key.
 */

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils';
import { utf8 } from './hash';

// ---------------------------------------------------------------------------------------------------
// Constants / limits
// ---------------------------------------------------------------------------------------------------

/** HKDF-SHA256 output is capped at 255 * HashLen = 255 * 32 bytes (RFC 5869). */
export const MAX_HKDF_OUTPUT = 255 * 32; // 8160

/**
 * Minimum local-CSPRNG input the combiner will accept. The whole safety argument rests on the local
 * bytes carrying real entropy, so we fail CLOSED rather than derive a seed from a too-short secret.
 */
export const MIN_LOCAL_BYTES = 16;

/** Default seed length (256-bit). */
export const DEFAULT_SEED_BYTES = 32;

/** Default per-request cap for an HTTP QRNG backend. */
export const DEFAULT_MAX_QRNG_BYTES = 1024;

/** Default HTTP timeout for a QRNG fetch (ms). */
export const DEFAULT_TIMEOUT_MS = 5000;

/** Domain-separation label folded into HKDF `info`. */
const MIX_LABEL = 'atlas-pca/entropy/mix/v1';
/** Fixed, non-secret HKDF salt (domain separation at the extract step). */
const MIX_SALT = utf8('atlas-pca/entropy/salt/v1');

// ---------------------------------------------------------------------------------------------------
// QRNG source interface + backends
// ---------------------------------------------------------------------------------------------------

/** A source of quantum random bytes. `fetch(n)` resolves to EXACTLY `n` bytes or rejects. */
export interface QrngSource {
  /** Short, log-safe identifier for the backend (never contains secrets). */
  readonly name: string;
  /** Fetch exactly `numBytes` random bytes, or reject on any error/timeout/validation failure. */
  fetch(numBytes: number): Promise<Uint8Array>;
}

/** Response shape the HTTP backend knows how to parse. */
export type QrngResponseFormat = 'anu-uint8' | 'hex' | 'base64';

/** Minimal response subset used by the HTTP backend (compatible with the global `fetch` Response). */
export interface QrngFetchResponse {
  readonly ok: boolean;
  readonly status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

/** Minimal fetch subset used by the HTTP backend (compatible with the global `fetch`). */
export type QrngFetch = (
  url: string,
  init?: { readonly headers?: Record<string, string>; readonly signal?: AbortSignal },
) => Promise<QrngFetchResponse>;

/** Configuration for {@link HttpQrngSource}. */
export interface HttpQrngConfig {
  /** Base endpoint URL. The requested length is appended as a query param unless {@link buildUrl} is given. */
  readonly url: string;
  /** Optional API key. Sent as a header; NEVER logged or placed in error messages. */
  readonly apiKey?: string;
  /** Header name for the API key (default `x-api-key`). */
  readonly apiKeyHeader?: string;
  /** Response format to parse (default `anu-uint8` — the ANU QRNG `{ data: number[] }` shape). */
  readonly format?: QrngResponseFormat;
  /** Request timeout in ms (default {@link DEFAULT_TIMEOUT_MS}). */
  readonly timeoutMs?: number;
  /** Max bytes per request (default {@link DEFAULT_MAX_QRNG_BYTES}). Requests above this are rejected. */
  readonly maxBytes?: number;
  /** Query-param name carrying the requested length (default `length`; ignored when {@link buildUrl} is set). */
  readonly lengthParam?: string;
  /** Extra static query params appended to every request (e.g. `{ type: 'uint8' }` for ANU). */
  readonly extraParams?: Readonly<Record<string, string>>;
  /** Build the full request URL yourself (overrides {@link lengthParam}/{@link extraParams}). */
  readonly buildUrl?: (base: string, numBytes: number) => string;
  /** Inject a fetch implementation (for tests / custom transports). Defaults to the global `fetch`. */
  readonly fetchImpl?: QrngFetch;
}

function isPositiveIntByte(n: unknown): n is number {
  return typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= 255;
}

function requireValidCount(numBytes: number, maxBytes: number): void {
  if (!Number.isInteger(numBytes) || numBytes <= 0) {
    throw new TypeError(`QRNG: numBytes must be a positive integer, got ${String(numBytes)}`);
  }
  if (numBytes > maxBytes) {
    throw new RangeError(`QRNG: requested ${numBytes} bytes exceeds per-request cap ${maxBytes}`);
  }
}

/** Default fetch wrapper around the global `fetch` (if present). */
function defaultFetch(): QrngFetch | null {
  const g = (globalThis as { fetch?: unknown }).fetch;
  if (typeof g !== 'function') return null;
  const f = g as (url: string, init?: unknown) => Promise<QrngFetchResponse>;
  return (url, init) => f(url, init);
}

/**
 * A real HTTP QRNG backend. It hits a CONFIGURABLE REST endpoint (shaped like the ANU QRNG public API or a
 * hardware-QRNG service) and strictly validates the response into exactly the requested number of bytes.
 *
 * Validation is fail-closed: a non-2xx status, a malformed body, a wrong-length payload (short OR
 * oversized), an out-of-range byte, or a timeout all REJECT rather than return partial/padded entropy.
 * The API key is sent only as a request header and never appears in any thrown error.
 */
export class HttpQrngSource implements QrngSource {
  readonly name: string;
  private readonly cfg: Required<Omit<HttpQrngConfig, 'apiKey' | 'buildUrl' | 'fetchImpl' | 'extraParams'>> &
    Pick<HttpQrngConfig, 'apiKey' | 'buildUrl' | 'extraParams'>;
  private readonly fetchImpl: QrngFetch | null;

  constructor(config: HttpQrngConfig) {
    if (typeof config.url !== 'string' || config.url.length === 0) {
      throw new TypeError('HttpQrngSource: `url` must be a non-empty string');
    }
    const maxBytes = config.maxBytes ?? DEFAULT_MAX_QRNG_BYTES;
    if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
      throw new TypeError('HttpQrngSource: `maxBytes` must be a positive integer');
    }
    const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError('HttpQrngSource: `timeoutMs` must be a positive integer');
    }
    this.cfg = {
      url: config.url,
      apiKey: config.apiKey,
      apiKeyHeader: config.apiKeyHeader ?? 'x-api-key',
      format: config.format ?? 'anu-uint8',
      timeoutMs,
      maxBytes,
      lengthParam: config.lengthParam ?? 'length',
      extraParams: config.extraParams,
      buildUrl: config.buildUrl,
    };
    this.fetchImpl = config.fetchImpl ?? defaultFetch();
    this.name = `http-qrng(${safeHost(config.url)})`;
  }

  private buildUrl(numBytes: number): string {
    if (this.cfg.buildUrl) return this.cfg.buildUrl(this.cfg.url, numBytes);
    const u = new URL(this.cfg.url);
    u.searchParams.set(this.cfg.lengthParam, String(numBytes));
    if (this.cfg.extraParams) {
      for (const [k, v] of Object.entries(this.cfg.extraParams)) u.searchParams.set(k, v);
    }
    return u.toString();
  }

  async fetch(numBytes: number): Promise<Uint8Array> {
    requireValidCount(numBytes, this.cfg.maxBytes);
    const doFetch = this.fetchImpl;
    if (!doFetch) throw new Error('QRNG: no fetch implementation available in this runtime');

    const url = this.buildUrl(numBytes);
    const headers: Record<string, string> = { accept: 'application/json, text/plain' };
    if (this.cfg.apiKey !== undefined && this.cfg.apiKey.length > 0) {
      headers[this.cfg.apiKeyHeader] = this.cfg.apiKey;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs);
    let res: QrngFetchResponse;
    try {
      res = await doFetch(url, { headers, signal: controller.signal });
    } catch (err) {
      // Normalize (and scrub) any transport/timeout error — never leak the key.
      throw new Error(`QRNG: fetch failed (${scrub(describeError(err), this.cfg.apiKey)})`);
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) throw new Error(`QRNG: endpoint returned HTTP ${res.status}`);

    const bytes = await parseBody(res, this.cfg.format);
    if (bytes.length !== numBytes) {
      throw new Error(`QRNG: expected ${numBytes} bytes, response decoded to ${bytes.length}`);
    }
    return bytes;
  }
}

async function parseBody(res: QrngFetchResponse, format: QrngResponseFormat): Promise<Uint8Array> {
  if (format === 'anu-uint8') {
    const body = await res.json();
    return parseAnuUint8(body);
  }
  const text = (await res.text()).trim();
  return format === 'hex' ? parseHex(text) : parseBase64(text);
}

/** ANU / hardware-REST JSON shape: `{ success?: boolean, data: number[] }`, each element a 0..255 byte. */
export function parseAnuUint8(body: unknown): Uint8Array {
  if (typeof body !== 'object' || body === null) throw new Error('QRNG: response body is not a JSON object');
  const rec = body as Record<string, unknown>;
  if ('success' in rec && rec.success !== true) throw new Error('QRNG: response reports success=false');
  const data = rec.data;
  if (!Array.isArray(data)) throw new Error('QRNG: response `data` is not an array');
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    const v = data[i];
    if (!isPositiveIntByte(v)) throw new Error(`QRNG: response data[${i}] is not a 0..255 integer`);
    out[i] = v;
  }
  return out;
}

const HEX_RE = /^[0-9a-fA-F]*$/;

/** Parse a flat hex string into bytes. Rejects odd length or non-hex characters. */
export function parseHex(text: string): Uint8Array {
  if (!HEX_RE.test(text) || text.length % 2 !== 0) throw new Error('QRNG: malformed hex payload');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/** Parse a standard base64 string into bytes. Rejects non-base64 characters. */
export function parseBase64(text: string): Uint8Array {
  if (!B64_RE.test(text)) throw new Error('QRNG: malformed base64 payload');
  // atob is available in Node 24+ and browsers.
  const atobFn = (globalThis as { atob?: (s: string) => string }).atob;
  if (typeof atobFn !== 'function') throw new Error('QRNG: base64 decoder unavailable in this runtime');
  let bin: string;
  try {
    bin = atobFn(text);
  } catch {
    throw new Error('QRNG: malformed base64 payload');
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

/** A null/unavailable QRNG source: every fetch rejects. Use when no QRNG is configured. */
export class NullQrngSource implements QrngSource {
  readonly name = 'null-qrng';
  private readonly reason: string;
  constructor(reason = 'no QRNG source configured') {
    this.reason = reason;
  }
  fetch(_numBytes: number): Promise<Uint8Array> {
    return Promise.reject(new Error(`QRNG unavailable: ${this.reason}`));
  }
}

/** Convenience: the shared unavailable source. */
export function unavailableSource(reason?: string): QrngSource {
  return new NullQrngSource(reason);
}

// ---------------------------------------------------------------------------------------------------
// Entropy combiner
// ---------------------------------------------------------------------------------------------------

/** Options for {@link mixEntropy}. */
export interface MixOptions {
  /** Output length in bytes (default = the local input length). 1..{@link MAX_HKDF_OUTPUT}. */
  readonly length?: number;
  /** Extra domain-separation context folded into HKDF `info` alongside the fixed label. */
  readonly context?: string;
}

/**
 * Robust randomness combiner: `HKDF-SHA256(ikm = local ‖ quantum, salt, info = label ‖ context ‖ len)`.
 *
 * The local CSPRNG bytes are ALWAYS part of the keying material, so the output is a pseudorandom function
 * of a secret the attacker does not control: an adversarial/constant/empty `quantum` can never lower the
 * output below the strength of `local` alone, and a genuine quantum source strengthens a weak `local`.
 *
 * Fail-closed: throws if `local` is shorter than {@link MIN_LOCAL_BYTES} (the safety anchor) or if
 * `length` is out of range. `quantum` may be empty.
 */
export function mixEntropy(local: Uint8Array, quantum: Uint8Array, opts: MixOptions = {}): Uint8Array {
  if (!(local instanceof Uint8Array)) throw new TypeError('mixEntropy: `local` must be a Uint8Array');
  if (!(quantum instanceof Uint8Array)) throw new TypeError('mixEntropy: `quantum` must be a Uint8Array');
  if (local.length < MIN_LOCAL_BYTES) {
    throw new RangeError(`mixEntropy: local CSPRNG must be >= ${MIN_LOCAL_BYTES} bytes (fail-closed)`);
  }
  const length = opts.length ?? local.length;
  if (!Number.isInteger(length) || length <= 0 || length > MAX_HKDF_OUTPUT) {
    throw new RangeError(`mixEntropy: length must be an integer in 1..${MAX_HKDF_OUTPUT}`);
  }

  // ikm = local ‖ quantum. Length-prefix each part so no (local, quantum) pair is ambiguous with another.
  const ikm = new Uint8Array(8 + local.length + quantum.length);
  const dv = new DataView(ikm.buffer);
  dv.setUint32(0, local.length, false);
  dv.setUint32(4, quantum.length, false);
  ikm.set(local, 8);
  ikm.set(quantum, 8 + local.length);

  const info = buildInfo(opts.context, length);
  const out = hkdf(sha256, ikm, MIX_SALT, info, length);
  ikm.fill(0); // best-effort zeroization of the transient keying material
  return out;
}

function buildInfo(context: string | undefined, length: number): Uint8Array {
  const label = context !== undefined && context.length > 0 ? `${MIX_LABEL}/${context}` : MIX_LABEL;
  const labelBytes = utf8(label);
  const info = new Uint8Array(labelBytes.length + 4);
  info.set(labelBytes, 0);
  new DataView(info.buffer).setUint32(labelBytes.length, length, false);
  return info;
}

// ---------------------------------------------------------------------------------------------------
// secureSeed: CSPRNG, strengthened by best-effort QRNG
// ---------------------------------------------------------------------------------------------------

/** Options for {@link secureSeed}. */
export interface SecureSeedOptions {
  /** Output seed length in bytes (default {@link DEFAULT_SEED_BYTES}). */
  readonly length?: number;
  /** QRNG source to draw best-effort quantum entropy from. `null`/omitted => CSPRNG-only. */
  readonly source?: QrngSource | null;
  /** How many quantum bytes to request (default = max(32, length)). */
  readonly quantumBytes?: number;
  /** How many local CSPRNG bytes to draw (default = max(32, length)). */
  readonly localBytes?: number;
  /** Extra domain-separation context for the combiner. */
  readonly context?: string;
  /** Observability hook invoked (never throwing) when the QRNG is skipped/fails. */
  readonly onQrngError?: (err: unknown) => void;
  /** Inject a CSPRNG (for tests). Defaults to the platform CSPRNG. MUST return `n` random bytes. */
  readonly randomBytesImpl?: (n: number) => Uint8Array;
}

/** Result of {@link secureSeed}. */
export interface SecureSeedResult {
  /** The derived key seed. Always full length, always at least CSPRNG-strength. */
  readonly seed: Uint8Array;
  /** True iff genuine quantum bytes were successfully mixed in. */
  readonly usedQuantum: boolean;
  /** Number of quantum bytes that were mixed in (0 on fallback). */
  readonly quantumByteCount: number;
  /** The source name, or null when none was used. */
  readonly source: string | null;
}

function drawLocal(impl: ((n: number) => Uint8Array) | undefined, n: number): Uint8Array {
  const bytes = impl ? impl(n) : nobleRandomBytes(n);
  if (!(bytes instanceof Uint8Array) || bytes.length !== n) {
    // The local CSPRNG is the trust anchor; if it misbehaves we fail CLOSED.
    throw new Error('secureSeed: local CSPRNG did not return the requested bytes (fail-closed)');
  }
  return bytes;
}

/**
 * Produce a key seed = `mixEntropy(CSPRNG, best-effort QRNG)`.
 *
 * FAIL-SAFE: a missing/erroring/timing-out/adversarial QRNG never blocks and never degrades the result
 * below CSPRNG strength — the seed falls back to CSPRNG-only and `usedQuantum` is false. The only throws
 * are configuration errors (bad `length`) or a local-CSPRNG malfunction (the trust anchor), never a QRNG
 * failure. QRNG is an entropy ADD, not a trust dependency.
 */
export async function secureSeed(opts: SecureSeedOptions = {}): Promise<SecureSeedResult> {
  const length = opts.length ?? DEFAULT_SEED_BYTES;
  if (!Number.isInteger(length) || length <= 0 || length > MAX_HKDF_OUTPUT) {
    throw new RangeError(`secureSeed: length must be an integer in 1..${MAX_HKDF_OUTPUT}`);
  }
  const localBytes = opts.localBytes ?? Math.max(DEFAULT_SEED_BYTES, length);
  if (!Number.isInteger(localBytes) || localBytes < MIN_LOCAL_BYTES) {
    throw new RangeError(`secureSeed: localBytes must be an integer >= ${MIN_LOCAL_BYTES}`);
  }
  const quantumBytes = opts.quantumBytes ?? Math.max(DEFAULT_SEED_BYTES, length);
  if (!Number.isInteger(quantumBytes) || quantumBytes <= 0) {
    throw new RangeError('secureSeed: quantumBytes must be a positive integer');
  }

  const local = drawLocal(opts.randomBytesImpl, localBytes);

  let quantum: Uint8Array = new Uint8Array(0);
  let usedQuantum = false;
  let sourceName: string | null = null;
  const source = opts.source ?? null;
  if (source) {
    sourceName = source.name;
    try {
      const q = await source.fetch(quantumBytes);
      if (!(q instanceof Uint8Array) || q.length !== quantumBytes) {
        throw new Error(`QRNG: source returned ${q instanceof Uint8Array ? q.length : 'non-bytes'}, expected ${quantumBytes}`);
      }
      quantum = q;
      usedQuantum = true;
    } catch (err) {
      // Fail-safe: swallow and fall back to CSPRNG-only. Report via the hook if provided.
      usedQuantum = false;
      quantum = new Uint8Array(0);
      if (opts.onQrngError) {
        try {
          opts.onQrngError(err);
        } catch {
          /* observability must never break key generation */
        }
      }
    }
  }

  const seed = mixEntropy(local, quantum, { length, context: opts.context });
  local.fill(0); // best-effort zeroization
  return { seed, usedQuantum, quantumByteCount: usedQuantum ? quantum.length : 0, source: sourceName };
}

// ---------------------------------------------------------------------------------------------------
// internal helpers (log-safe)
// ---------------------------------------------------------------------------------------------------

function safeHost(url: string): string {
  try {
    return new URL(url).host || 'unknown';
  } catch {
    return 'unknown';
  }
}

function describeError(err: unknown): string {
  if (err instanceof Error) {
    if (err.name === 'AbortError') return 'timeout';
    return err.message;
  }
  return 'unknown error';
}

/** Remove the API key from a message if it somehow appears (defense in depth). */
function scrub(msg: string, apiKey: string | undefined): string {
  if (!apiKey || apiKey.length === 0) return msg;
  return msg.split(apiKey).join('[redacted]');
}
