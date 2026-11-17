/**
 * Authenticated event ingest. A source (a gateway or resource server) holds an Ed25519 key the operator pinned,
 * signs each batch with a strictly increasing sequence number, and the control plane refuses anything else before
 * it spends work on it: unknown source, bad signature, stale or future clock, replayed or reordered sequence.
 */
import { b64u, canonicalBytesLenient, sign, utf8, verifyB64u } from '@atlasauth/pca';
import { OUTCOMES, type ControlEvent } from './types';

export const INGEST_DOMAIN = 'atlas-pca/control-plane/ingest/v1\0';
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;

export interface IngestEnvelopeClaim {
  v: 1;
  /** The source id the operator pinned a key for. */
  source: string;
  /** Strictly increasing per source. */
  seq: number;
  sent_at: number;
  events: unknown[];
}
export interface IngestEnvelope extends IngestEnvelopeClaim {
  sig: string;
}

const messageOf = (c: IngestEnvelopeClaim): Uint8Array => {
  const pre = utf8(INGEST_DOMAIN);
  const body = canonicalBytesLenient(c);
  const m = new Uint8Array(pre.length + body.length);
  m.set(pre);
  m.set(body, pre.length);
  return m;
};

/** Sign a batch as a source. Throws if the events cannot be canonicalised (e.g. a non-finite number): a source cannot sign garbage. */
export function signIngest(secret: Uint8Array, c: Omit<IngestEnvelopeClaim, 'v'>): IngestEnvelope {
  const claim: IngestEnvelopeClaim = { v: 1, ...c };
  return { ...claim, sig: b64u(sign(secret, messageOf(claim))) };
}

export type EnvelopeCheck = { ok: true; envelope: IngestEnvelope } | { ok: false; reason: 'malformed' | 'source' | 'signature' | 'too_large' };

/** Shape, source and signature. Replay and clock are checked by the engine, after this and before any work. */
export function verifyEnvelope(e: unknown, sources: Readonly<Record<string, string>>, maxBatch: number): EnvelopeCheck {
  try {
    if (e === null || typeof e !== 'object') return { ok: false, reason: 'malformed' };
    const x = e as IngestEnvelope;
    if (x.v !== 1 || typeof x.source !== 'string' || x.source.length === 0 || x.source.length > 128 || typeof x.sig !== 'string' || !SIG_RE.test(x.sig)) return { ok: false, reason: 'malformed' };
    if (!Number.isSafeInteger(x.seq) || x.seq < 1 || !Number.isFinite(x.sent_at) || !Array.isArray(x.events)) return { ok: false, reason: 'malformed' };
    if (x.events.length > maxBatch) return { ok: false, reason: 'too_large' };
    const key = Object.prototype.hasOwnProperty.call(sources, x.source) ? sources[x.source] : undefined;
    if (key === undefined) return { ok: false, reason: 'source' };
    const { sig, ...claim } = x;
    if (!verifyB64u(key, messageOf(claim as IngestEnvelopeClaim), sig)) return { ok: false, reason: 'signature' };
    return { ok: true, envelope: x };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

/** The event's shape, or the reason it is not one. An event that fails is still counted as a violation: fail closed. */
export function eventError(e: unknown): string | null {
  if (e === null || typeof e !== 'object' || Array.isArray(e)) return 'not an object';
  const x = e as Partial<ControlEvent>;
  if (typeof x.id !== 'string' || x.id.length === 0 || x.id.length > 128) return 'id';
  if (typeof x.agent !== 'string' || x.agent.length === 0 || x.agent.length > 256) return 'agent';
  if (typeof x.verb !== 'string' || x.verb.length > 256 || typeof x.resource !== 'string' || x.resource.length > 512) return 'verb/resource';
  if (!OUTCOMES.includes(x.outcome as never)) return 'outcome';
  if (typeof x.r !== 'number' || !Number.isFinite(x.r) || x.r < 0 || x.r > 1) return 'r';
  if (typeof x.at !== 'number' || !Number.isFinite(x.at) || x.at < 0) return 'at';
  if (x.mode !== undefined && x.mode !== 'observe' && x.mode !== 'enforce') return 'mode';
  if (x.observed !== undefined && (x.observed === null || typeof x.observed !== 'object' || Array.isArray(x.observed) || JSON.stringify(x.observed).length > 4096)) return 'observed';
  for (const k of ['session', 'grant'] as const) if (x[k] !== undefined && (typeof x[k] !== 'string' || (x[k] as string).length > 256)) return k;
  return null;
}
