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
import { b64u, canonicalizeStrict, decodeB64uStrict } from './hash';
import { PROV_HEADER, type ProvenanceBundle, type ProvenanceRecorder } from './arg-provenance';
import { strictParse } from './strict-json';

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
  /** Ready-to-spread HTTP headers carrying the PCActn (and the provenance bundle when it fits a header, see {@link provenanceHeaders}). */
  headers: Record<string, string>;
  /** The provenance bundle of this action (send it as body member `pca_provenance` when it is not in `headers`). */
  provenance?: ProvenanceBundle;
}

/** Largest bundle carried as a header (base64url characters); a larger one goes in the request body as `pca_provenance`. */
export const PROV_HEADER_MAX = 8192;

/** `PCA-Provenance: <base64url JSON>` for a bundle that fits {@link PROV_HEADER_MAX}; `{}` otherwise (send it in the body). */
export function provenanceHeaders(bundle: ProvenanceBundle | undefined): Record<string, string> {
  if (bundle === undefined) return {};
  const v = b64u(HDR_ENC.encode(canonicalizeStrict(bundle)));
  return v.length <= PROV_HEADER_MAX ? { [PROV_HEADER]: v } : {};
}

/** Record the principal's own message in the agent's provenance chain (TRUSTED). Adapters call it for every user turn. */
export function recordPrincipal(agent: Pick<Agent, 'provenance'>, text: string): void {
  agent.provenance?.principal(text);
}

/** Record a tool result entering the model's context (UNTRUSTED). Adapters call it for every tool result they hand back. */
export function recordToolResult(agent: Pick<Agent, 'provenance'>, tool: string, output: unknown): void {
  agent.provenance?.tool(tool, output);
}

export type MessageSegment = { origin: 'principal' | 'tool'; source: string; content: unknown };
const recorderOf = (t: Pick<Agent, 'provenance'> | ProvenanceRecorder | undefined): ProvenanceRecorder | undefined =>
  t === undefined || t === null ? undefined : 'forAction' in t ? (t as ProvenanceRecorder) : (t as Pick<Agent, 'provenance'>).provenance;
const roleOf = (m: Record<string, unknown>): string => {
  for (const g of ['_getType', 'getType'] as const) {
    const f = m[g];
    if (typeof f === 'function') {
      try {
        const r = (f as () => unknown).call(m);
        if (typeof r === 'string') return r;
      } catch {
        /* fall through */
      }
    }
  }
  return typeof m.role === 'string' ? m.role : typeof m.type === 'string' ? m.type : '';
};
const PRINCIPAL_ROLES = new Set(['user', 'human']);
const MODEL_ROLES = new Set(['assistant', 'ai', 'model', 'system', 'developer']);

/**
 * The context segments a chat message adds, by the conversation's own roles: a user / human turn is the PRINCIPAL (its text, and its
 * other parts); a `tool_result` / `tool-result` part inside any turn, a `tool` / `function` turn, and a turn of an unknown role are
 * UNTRUSTED tool output; assistant / system turns add nothing (the model's output and the developer's prompt are not the principal's
 * choice, and their values never count as principal text).
 */
export function messageSegments(m: unknown): MessageSegment[] {
  if (m === null || typeof m !== 'object') return [];
  const msg = m as Record<string, unknown>;
  const role = roleOf(msg).toLowerCase();
  if (MODEL_ROLES.has(role)) return [];
  const content = msg.content;
  const toolName = (x: Record<string, unknown>): string =>
    String(x.toolName ?? x.name ?? x.tool_use_id ?? x.toolCallId ?? x.tool_call_id ?? msg.name ?? msg.tool_call_id ?? 'tool');
  if (!PRINCIPAL_ROLES.has(role)) return [{ origin: 'tool', source: toolName(msg), content: content ?? msg }];
  if (!Array.isArray(content)) return [{ origin: 'principal', source: 'user', content: content ?? '' }];
  const out: MessageSegment[] = [];
  const text: string[] = [];
  for (const part of content) {
    const pt = part !== null && typeof part === 'object' ? (part as Record<string, unknown>) : { type: 'text', text: String(part) };
    const t = typeof pt.type === 'string' ? pt.type : '';
    if (t === 'tool_result' || t === 'tool-result' || t === 'function_call_output') out.push({ origin: 'tool', source: toolName(pt), content: pt.content ?? pt.result ?? pt.output ?? pt });
    else if (typeof pt.text === 'string') text.push(pt.text);
    else out.push({ origin: 'principal', source: 'user', content: pt });
  }
  if (text.length) out.unshift({ origin: 'principal', source: 'user', content: text.join('\n') });
  return out;
}

const seenMessages = new WeakMap<ProvenanceRecorder, number>();

/**
 * Record a conversation's new messages in the agent's provenance chain (call it with the whole message list before each model turn;
 * messages already recorded are skipped, a shorter list starts over). The framework adapters call it for you.
 */
export function recordMessages(target: Pick<Agent, 'provenance'> | ProvenanceRecorder | undefined, messages: readonly unknown[]): void {
  const rec = recorderOf(target);
  if (!rec || !Array.isArray(messages)) return;
  const from = seenMessages.get(rec) ?? 0;
  const start = messages.length < from ? 0 : from;
  for (let i = start; i < messages.length; i++) {
    for (const seg of messageSegments(messages[i])) {
      if (seg.origin === 'principal') rec.principal(typeof seg.content === 'string' ? seg.content : JSON.stringify(seg.content) ?? '');
      else rec.tool(seg.source, seg.content);
    }
  }
  seenMessages.set(rec, messages.length);
}

/**
 * Record what the principal asked for: a string is the principal's message; a message list (or `{messages}`) is recorded with
 * {@link recordMessages}; an object's `input` / `prompt` / `query` / `question` / `message` / `text` string (or message list) is
 * the principal's message. Anything else records nothing (the gate then keeps the context at `agent`: fail closed).
 */
export function recordInput(target: Pick<Agent, 'provenance'> | ProvenanceRecorder | undefined, input: unknown): void {
  const rec = recorderOf(target);
  if (!rec) return;
  if (typeof input === 'string') rec.principal(input);
  else if (Array.isArray(input)) recordMessages(rec, input);
  else if (input !== null && typeof input === 'object') {
    const o = input as Record<string, unknown>;
    if (Array.isArray(o.messages)) recordMessages(rec, o.messages);
    for (const k of ['input', 'prompt', 'query', 'question', 'message', 'text']) {
      const v = o[k];
      if (typeof v === 'string') rec.principal(v);
      else if (Array.isArray(v)) recordMessages(rec, v);
    }
  }
}

/**
 * Wrap a framework entry point (`executor.invoke`, `generateText`, `chatEngine.chat`, ...) so its first argument, the principal's
 * request, is recorded before it runs. The returned function has the same signature.
 */
export function withPrincipalInput<A extends unknown[], R>(target: Pick<Agent, 'provenance'> | ProvenanceRecorder | undefined, fn: (...args: A) => R): (...args: A) => R {
  return (...args: A) => {
    recordInput(target, args[0]);
    return fn(...args);
  };
}

/**
 * A provenance bundle from wherever a framework carried it: the bundle object itself, its JSON text, or a `PCA-Provenance` header
 * value (base64url JSON). Undefined for anything else (the gate then treats the call as unlabelled: fail closed).
 */
export function provenanceFrom(v: unknown): unknown {
  if (v === null || v === undefined) return undefined;
  if (typeof v === 'object') return v;
  if (typeof v !== 'string' || v.length === 0) return undefined;
  try {
    return strictParse(v);
  } catch {
    try {
      return strictParse(decodePcaHeader(v));
    } catch {
      return undefined;
    }
  }
}

const callOf = (pcactn: PCActn, encoded: string, provenance: ProvenanceBundle | undefined): PcaCall => ({
  pcactn,
  encoded,
  headers: pcaHeaders(encoded, provenance),
  ...(provenance ? { provenance } : {}),
});

/**
 * The canonical header a resource server reads the PCActn from. The value is base64url(encoded PCActn
 * JSON) — the exact form the server-side verifier's default extractor expects — so a PCActn survives
 * transit as a single header token. Use `decodePcaHeader` to reverse it.
 */
export const PCA_HEADER = 'PCA-Action';

/**
 * Headers carrying an encoded PCActn (spread into any fetch/axios/SDK request), and its provenance bundle (`act().provenance`)
 * as `PCA-Provenance`. base64url over the wire. A bundle too large for a header is left out: send it as the body member
 * `pca_provenance` instead (without it the verifier escalates every sensitive action).
 */
export function pcaHeaders(encoded: string, provenance?: ProvenanceBundle): Record<string, string> {
  return { [PCA_HEADER]: b64u(HDR_ENC.encode(encoded)), ...provenanceHeaders(provenance) };
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
    const { pcactn, encoded, dryRun, provenance } = agent.act(spec.verb, resource, params, {
      ...(spec.aud !== undefined ? { aud: spec.aud } : {}),
      ...(opts?.counter !== undefined ? { counter: opts.counter } : {}),
      ...(opts?.now !== undefined ? { now: opts.now } : {}),
    });
    if (failFast && !dryRun.allowed) throw new PcaDenied(dryRun.reason ?? 'denied', spec.verb, resource);
    const out = await run(params, callOf(pcactn, encoded, provenance));
    // what the tool returned enters the model's context: it is untrusted from here on
    recordToolResult(agent, spec.verb, out);
    return out;
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
 * turn its tool-invocation event into a proof-carrying action. The tool's result is not seen here: the caller records it
 * with {@link recordToolResult} (the framework adapters do).
 */
export function bridgeToolCall(
  agent: Agent,
  call: ToolCall,
  map: ToolMapping,
  opts?: { aud?: string; counter?: number; now?: number },
): PcaCall | null {
  const m = map(call);
  if (!m) return null;
  const { pcactn, encoded, provenance } = agent.act(m.verb, m.resource, call.arguments, {
    ...(opts?.aud !== undefined ? { aud: opts.aud } : {}),
    ...(opts?.counter !== undefined ? { counter: opts.counter } : {}),
    ...(opts?.now !== undefined ? { now: opts.now } : {}),
  });
  return callOf(pcactn, encoded, provenance);
}
