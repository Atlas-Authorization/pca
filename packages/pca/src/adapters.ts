/**
 * Framework adapters — the distribution engine (spec Part 2.1).
 *
 * "Nobody adopts a protocol; they adopt a wrapper in the framework they already use." These are the
 * dep-free, framework-AGNOSTIC primitives every concrete adapter (LangChain / Vercel AI SDK / OpenAI &
 * Anthropic Agents SDK / CrewAI / MCP) is built from: wrap a tool so each call silently produces a
 * PCActn, attach it to the outbound request, and fast-fail locally on an obvious deny. The typed
 * per-framework packages (which pull in those frameworks' own types) sit on top of this and are a
 * separate, additive follow — this module imports nothing but the PCA core so it ships everywhere.
 *
 * HONESTY: `guard` is NOT the authorization. It builds a proof-carrying action, offers the agent's
 * local non-authoritative `dryRun` as a fast client-side reject, and hands the encoded PCActn to the
 * caller's dispatch so the RESOURCE SERVER's `requirePCA` / adjudicator can verify and decide. A guard
 * that is bypassed changes nothing: an action without a valid PCActn simply fails server-side.
 */

import type { Agent } from './facade';
import type { PCActn } from './pcactn';
import { b64u, decodeB64uStrict } from './hash';

const HDR_ENC = new TextEncoder();
/** Fatal (invalid UTF-8 throws) and BOM-preserving (a leading U+FEFF reaches the strict JSON parser, which refuses it). */
const HDR_DEC = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Thrown by `guard` when the agent's local dry-run rejects a call before dispatch. */
export class PcaDenied extends Error {
  constructor(
    public readonly reason: string,
    public readonly verb: string,
    public readonly resource: string,
  ) {
    super(`PCA denied ${verb} on ${resource}: ${reason}`);
    this.name = 'PcaDenied';
  }
}

/** What a guarded dispatch receives so it can carry the proof to the resource server. */
export interface PcaCall {
  encoded: string;
  pcactn: PCActn;
  /** Ready-to-spread HTTP headers carrying the PCActn. */
  headers: Record<string, string>;
}

/**
 * The canonical header a resource server reads the PCActn from. The value is base64url(encoded PCActn
 * JSON) — the exact form the server-side verifier's default extractor expects — so a PCActn survives
 * transit as a single header token. Use `decodePcaHeader` to reverse it.
 */
export const PCA_HEADER = 'PCA-Action';

/** Headers carrying an encoded PCActn (spread into any fetch/axios/SDK request). base64url over the wire. */
export function pcaHeaders(encoded: string): Record<string, string> {
  return { [PCA_HEADER]: b64u(HDR_ENC.encode(encoded)) };
}

/** Thrown by {@link decodePcaHeader} for a `PCA-Action` value that is not strict unpadded base64url of UTF-8 text. */
export class PcaHeaderError extends Error {
  readonly code = 'invalid_pca_header' as const;
  constructor(message: string) {
    super(message);
    this.name = 'PcaHeaderError';
  }
}

/**
 * Reverse `pcaHeaders`: `PCA-Action` header value → the encoded PCActn JSON text (pass to `decodePCActn`).
 *
 * STRICT (0.4.1), exactly the profile's base64url rule: unpadded RFC 4648 §5 alphabet only (`A-Z a-z 0-9 - _`), no `=`,
 * no `+` or `/`, no whitespace anywhere (HTTP stacks strip optional whitespace around a field value before it gets
 * here), length mod 4 != 1, zero unused trailing bits, and the bytes must be valid UTF-8. Anything else throws
 * {@link PcaHeaderError}. Nothing is normalized, so one PCActn has exactly one header spelling.
 */
export function decodePcaHeader(value: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new PcaHeaderError('PCA-Action header is empty');
  const bytes = decodeB64uStrict(value);
  if (bytes === null) throw new PcaHeaderError('PCA-Action header is not strict unpadded base64url');
  try {
    return HDR_DEC.decode(bytes);
  } catch {
    throw new PcaHeaderError('PCA-Action header does not decode to UTF-8 text');
  }
}

export interface GuardSpec<P> {
  /** The PCA verb (catalog verb, e.g. `stripe.refund`). */
  verb: string;
  /** Resource for this call, derived from its params (so each call binds its own target). */
  resource: string | ((params: P) => string);
  /** Audience override (else the agent's default). */
  aud?: string;
  /**
   * When `true` (default), a failing local dry-run throws `PcaDenied` BEFORE dispatch — a fast,
   * offline reject. When `false`, dispatch proceeds regardless and the resource server is the only
   * gate (useful when the client can't fully evaluate policy, e.g. server-only env/state).
   */
  failFast?: boolean;
}

/**
 * Wrap a tool `run(params, pca)` so every invocation first builds a PCActn via `agent.act`, optionally
 * fast-fails on the local dry-run, then dispatches with the proof attached. Returns a drop-in
 * `(params) => Promise<R>` with the same call shape as the original tool.
 */
export function guard<P extends Record<string, unknown>, R>(
  agent: Agent,
  spec: GuardSpec<P>,
  run: (params: P, pca: PcaCall) => Promise<R> | R,
): (params: P, opts?: { counter?: number; now?: number }) => Promise<R> {
  const failFast = spec.failFast !== false;
  return async (params: P, opts) => {
    const resource = typeof spec.resource === 'function' ? spec.resource(params) : spec.resource;
    const { pcactn, encoded, dryRun } = agent.act(spec.verb, resource, params, {
      ...(spec.aud !== undefined ? { aud: spec.aud } : {}),
      ...(opts?.counter !== undefined ? { counter: opts.counter } : {}),
      ...(opts?.now !== undefined ? { now: opts.now } : {}),
    });
    if (failFast && !dryRun.allowed) throw new PcaDenied(dryRun.reason ?? 'denied', spec.verb, resource);
    return run(params, { pcactn, encoded, headers: pcaHeaders(encoded) });
  };
}

/** A framework-agnostic tool call: `{ name, arguments }` (OpenAI/Anthropic/LangChain all reduce to this). */
export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

/** How a framework tool name maps onto a PCA (verb, resource). */
export type ToolMapping = (call: ToolCall) => { verb: string; resource: string } | null;

/**
 * Bridge a single framework tool call into a PCActn using a name→(verb,resource) mapping. Returns null
 * when the mapping declines the call (an unmapped tool). Use this inside any framework's middleware to
 * turn its tool-invocation event into a proof-carrying action.
 */
export function bridgeToolCall(
  agent: Agent,
  call: ToolCall,
  map: ToolMapping,
  opts?: { aud?: string; counter?: number; now?: number },
): PcaCall | null {
  const m = map(call);
  if (!m) return null;
  const { pcactn, encoded } = agent.act(m.verb, m.resource, call.arguments, {
    ...(opts?.aud !== undefined ? { aud: opts.aud } : {}),
    ...(opts?.counter !== undefined ? { counter: opts.counter } : {}),
    ...(opts?.now !== undefined ? { now: opts.now } : {}),
  });
  return { pcactn, encoded, headers: pcaHeaders(encoded) };
}
