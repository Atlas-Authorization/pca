/**
 * Observe mode for the resource-server middleware (`@atlasauth/pca/observe`, Node only).
 *
 * The middleware runs the FULL verification on every request, never blocks, and appends one line per request that succeeded to a
 * JSONL file in the exact format `pca autopilot observe` reads. Each line says what the action was and whether the verifier WOULD
 * have denied it, with short reason codes. Nothing else leaves the process: no tokens, no proofs, no bodies, no headers. A
 * parameter is recorded only when it is a number, a boolean, or a short enum string whose key the operator listed in `enumKeys`.
 * It starts with a loud log line and refuses to start in a production environment unless that is acknowledged.
 */
import { appendFileSync, mkdirSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import type { PcaGuardResult, PcaRequestLike } from './require-pca';
import type { PcaOperation } from './verify';

export interface ObserveOptions {
  /** The JSONL file to append to. */
  file: string;
  /** Without this, `NODE_ENV` or `PCA_ENV` set to production makes the middleware throw at construction. */
  acknowledgeProduction?: boolean;
  /** Parameter names whose short string values (`^[A-Za-z0-9_.-]{1,24}$`) may be recorded. Default none. */
  enumKeys?: readonly string[];
  /** Stop recording past this size (default 50 MiB), with one log line. */
  maxBytes?: number;
  env?: Record<string, string | undefined>;
  log?: (message: string) => void;
  now?: () => number;
}

export interface Observer {
  /** Verify (never throws, never blocks) and return `done(status)`, to call once the response status is known. */
  observe(req: PcaRequestLike, verify: () => Promise<PcaGuardResult>, operation: PcaOperation | null | undefined): Promise<(status: number) => void>;
}

const KEY = /^[A-Za-z0-9_]{1,64}$/;
const ENUM = /^[A-Za-z0-9_.-]{1,24}$/;
const REASON = /^[A-Za-z0-9_.:-]{1,48}/;
const PRODUCTION = /^(production|prod)$/i;

/** The operation to record when the adapter has no `operation` option: the method and the path. */
export function defaultObservedOperation(req: PcaRequestLike): PcaOperation {
  let path = '/';
  try {
    path = new URL(req.url ?? '/', 'http://localhost').pathname;
  } catch {
    /* keep '/' */
  }
  return { verb: `http.${String(req.method ?? 'GET').toLowerCase()}`, resource: path } as PcaOperation;
}

export function redactParams(params: unknown, enumKeys: readonly string[]): Record<string, number | boolean | string> {
  const out: Record<string, number | boolean | string> = Object.create(null) as Record<string, number | boolean | string>;
  if (params === null || typeof params !== 'object' || Array.isArray(params)) return out;
  for (const [k, v] of Object.entries(params as Record<string, unknown>)) {
    if (!KEY.test(k)) continue;
    if (typeof v === 'number' && Number.isFinite(v)) out[k] = v;
    else if (typeof v === 'boolean') out[k] = v;
    else if (typeof v === 'string' && enumKeys.includes(k) && ENUM.test(v)) out[k] = v;
  }
  return out;
}

export function createObserver(o: ObserveOptions): Observer {
  const env = o.env ?? process.env;
  const log = o.log ?? ((m: string) => console.warn(m));
  const now = o.now ?? Date.now;
  const cap = o.maxBytes ?? 50 * 1024 * 1024;
  if (typeof o.file !== 'string' || o.file.length === 0) throw new Error('observe: file is required');
  if ((PRODUCTION.test(env.NODE_ENV ?? '') || PRODUCTION.test(env.PCA_ENV ?? '')) && o.acknowledgeProduction !== true) {
    throw new Error('PCA observe mode refuses to start in a production environment: it verifies but ENFORCES NOTHING. Set observe.acknowledgeProduction to true if that is what you want.');
  }
  log(`PCA OBSERVE MODE: every request is verified and none is blocked. Would-deny decisions are recorded to ${o.file}. Nothing is enforced.`);
  let full = false;
  const write = (line: string): void => {
    if (full) return;
    try {
      let size = 0;
      try {
        size = statSync(o.file).size;
      } catch {
        mkdirSync(dirname(o.file), { recursive: true });
      }
      if (size + line.length > cap) {
        full = true;
        log(`PCA observe: ${o.file} reached ${cap} bytes; recording stopped`);
        return;
      }
      appendFileSync(o.file, line);
    } catch {
      /* observing must never break the app */
    }
  };
  return {
    async observe(req, verify, op) {
      let would: 'allow' | 'deny' = 'deny';
      let reasons: string[] = ['verifier_error'];
      try {
        const r = await verify();
        would = r.ok ? 'allow' : 'deny';
        reasons = r.ok ? [] : (r.verdict.reasons ?? []).map((x) => REASON.exec(String(x))?.[0] ?? 'denied').slice(0, 5);
        if (!r.ok && reasons.length === 0) reasons = ['denied'];
      } catch {
        /* recorded as a would-deny with reason verifier_error */
      }
      const operation = op ?? defaultObservedOperation(req);
      const at = now();
      return (status: number): void => {
        if (status >= 400) return; // a request that failed is never recorded: it must not widen what is learned
        write(
          JSON.stringify({
            at,
            verb: operation.verb,
            resource: operation.resource,
            params: redactParams((operation as { params?: unknown }).params, o.enumKeys ?? []),
            outcome: 'allow',
            would,
            ...(reasons.length > 0 ? { reasons } : {}),
            mode: 'observe',
          }) + '\n',
        );
      };
    },
  };
}
