/**
 * SSF STREAM MANAGEMENT API (OpenID Shared Signals Framework 1.0, section 8.1 and 7.1): create / read / update (PATCH) / replace (PUT) /
 * delete a stream, read / update its status, add / remove subjects, request a verification event, and the transmitter configuration
 * metadata. Source: https://openid.net/specs/openid-sharedsignals-framework-1_0.html (fetched; sections cited per function).
 *
 * Framework-neutral like the AuthZEN handler: `{method, path, query, body}` in, `{status, body}` out. The HOST authenticates the
 * receiver (SSF 8: "standard HTTP authentication") and passes `{id, aud}`; a stream belongs to exactly one receiver and anyone else
 * sees 404, never 403 (the spec's "no stream with that stream_id for this Receiver").
 */
import { randomBytes } from 'node:crypto';
import {
  DELIVERY_POLL, DELIVERY_PUSH, STREAM_STATUSES, handleVerificationRequest, validateStreamConfig,
  type SigningKey, type StreamConfig, type StreamStatusValue,
} from './index';

export interface StreamRecord {
  receiver: string;
  config: StreamConfig;
  /** What the receiver asked for (kept so a change of `events_supported` recomputes `events_delivered`). */
  events_requested?: string[];
  status: StreamStatusValue;
  status_reason?: string;
  /** Canonical-JSON key -> verified flag. */
  subjects: Record<string, boolean>;
  lastVerification?: number;
}
export interface StreamStore {
  get(id: string): Promise<StreamRecord | undefined>;
  put(id: string, r: StreamRecord): Promise<void>;
  delete(id: string): Promise<void>;
  listByReceiver(receiver: string): Promise<Array<[string, StreamRecord]>>;
}
export class MemoryStreamStore implements StreamStore {
  private readonly m = new Map<string, StreamRecord>();
  async get(id: string) { const r = this.m.get(id); return r && structuredClone(r); }
  async put(id: string, r: StreamRecord) { this.m.set(id, structuredClone(r)); }
  async delete(id: string) { this.m.delete(id); }
  async listByReceiver(receiver: string) { return [...this.m].filter(([, r]) => r.receiver === receiver).map(([i, r]) => [i, structuredClone(r)] as [string, StreamRecord]); }
}

export interface Receiver {
  id: string;
  aud: string | string[];
}
export interface SsfManageOptions {
  store: StreamStore;
  /** The transmitter's issuer URL: equals the `iss` of every SET (SSF 7.1 `issuer`). */
  issuer: string;
  /** Event type URIs the transmitter can emit. */
  eventsSupported: string[];
  /** Delivery methods offered; default both. */
  deliveryMethods?: string[];
  /** Poll endpoint the transmitter assigns to a stream (RFC 8936: transmitter-set). */
  pollEndpoint: (streamId: string) => string;
  /** Verification SETs are signed with this key (SSF 8.1.4). */
  signingKey: SigningKey;
  /** Hand the verification SET to the stream's delivery (enqueue for poll, POST for push). */
  deliver: (stream: StreamRecord, set: string) => void | Promise<void>;
  /** 1 (default) = one stream per receiver: the second create is 409 (SSF 8.1.1.1). */
  maxStreamsPerReceiver?: number;
  maxSubjectsPerStream?: number;
  now: () => number;
  newId?: () => string;
}
export interface SsfRequest {
  method: string;
  /** Path as registered by the host (the metadata's endpoints); matched on its last segment. */
  path: string;
  query?: Record<string, string | undefined>;
  body?: unknown;
}
export interface SsfResponse {
  status: number;
  body?: unknown;
}

const isRec = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const bad = (m: string): SsfResponse => ({ status: 400, body: { error: 'invalid_request', description: m } });
const ENDPOINTS = ['configuration', 'status', 'add_subject', 'remove_subject', 'verification'] as const;
const RECEIVER_SUPPLIED = ['events_requested', 'delivery', 'description'];
const TRANSMITTER_SUPPLIED = ['stream_id', 'iss', 'aud', 'events_supported', 'events_delivered', 'min_verification_interval'];
const subjectKey = (s: unknown): string | null => {
  if (!isRec(s) || typeof s.format !== 'string' || s.format.length === 0) return null;
  try {
    return JSON.stringify(Object.fromEntries(Object.entries(s).sort(([a], [b]) => (a < b ? -1 : 1))));
  } catch {
    return null;
  }
};

/** SSF 7.1 transmitter configuration metadata (served at `/.well-known/ssf-configuration`). */
export function transmitterMetadata(o: Pick<SsfManageOptions, 'issuer' | 'deliveryMethods'>, base: string, jwksUri?: string) {
  return {
    spec_version: '1_0',
    issuer: o.issuer,
    ...(jwksUri ? { jwks_uri: jwksUri } : {}),
    delivery_methods_supported: o.deliveryMethods ?? [DELIVERY_PUSH, DELIVERY_POLL],
    configuration_endpoint: `${base}/ssf/configuration`,
    status_endpoint: `${base}/ssf/status`,
    add_subject_endpoint: `${base}/ssf/add_subject`,
    remove_subject_endpoint: `${base}/ssf/remove_subject`,
    verification_endpoint: `${base}/ssf/verification`,
    default_subjects: 'NONE',
  };
}

export function ssfManagementHandler(o: SsfManageOptions, authenticate: (req: SsfRequest) => Receiver | null | Promise<Receiver | null>): (req: SsfRequest) => Promise<SsfResponse> {
  const methods = o.deliveryMethods ?? [DELIVERY_PUSH, DELIVERY_POLL];
  const newId = o.newId ?? (() => randomBytes(12).toString('base64url'));
  const maxStreams = o.maxStreamsPerReceiver ?? 1;

  const own = async (rcv: Receiver, id: unknown): Promise<StreamRecord | undefined> => {
    if (typeof id !== 'string') return undefined;
    const r = await o.store.get(id);
    return r && r.receiver === rcv.id ? r : undefined;
  };
  const delivered = (requested: string[] | undefined): string[] => (requested === undefined ? [...o.eventsSupported] : o.eventsSupported.filter((e) => requested.includes(e)));
  const eventsRequestedOk = (v: unknown): v is string[] => Array.isArray(v) && v.length > 0 && v.every((e) => typeof e === 'string' && e.length > 0);
  const deliveryFor = (id: string, d: unknown): { ok: true; delivery: StreamConfig['delivery'] } | { ok: false; why: string } => {
    if (d === undefined) {
      if (!methods.includes(DELIVERY_POLL)) return { ok: false, why: 'delivery is required: this transmitter does not support poll' };
      return { ok: true, delivery: { method: DELIVERY_POLL, endpoint_url: o.pollEndpoint(id) } };
    }
    if (!isRec(d) || typeof d.method !== 'string' || !methods.includes(d.method)) return { ok: false, why: 'delivery.method is not supported by this transmitter' };
    if (d.method === DELIVERY_POLL) return { ok: true, delivery: { method: DELIVERY_POLL, endpoint_url: o.pollEndpoint(id) } }; // transmitter-set; a receiver value is ignored
    if (typeof d.endpoint_url !== 'string' || !/^https:\/\/[^\s]+$/.test(d.endpoint_url)) return { ok: false, why: 'push delivery needs an https endpoint_url' };
    return { ok: true, delivery: { method: DELIVERY_PUSH, endpoint_url: d.endpoint_url } };
  };
  const build = (id: string, rcv: Receiver, requested: string[] | undefined, delivery: StreamConfig['delivery'], description: string | undefined): StreamConfig => ({
    stream_id: id, iss: o.issuer, aud: rcv.aud, events_supported: [...o.eventsSupported], events_delivered: delivered(requested), delivery,
    ...(description !== undefined ? { description: description.slice(0, 256) } : {}),
  });

  async function route(req: SsfRequest, rcv: Receiver): Promise<SsfResponse> {
    const seg = req.path.split('/').filter(Boolean).pop() ?? '';
    const q = req.query ?? {};
    const b = isRec(req.body) ? req.body : undefined;
    const m = req.method.toUpperCase();
    if (!(ENDPOINTS as readonly string[]).includes(seg)) return { status: 404, body: { error: 'not_found' } };

    if (seg === 'configuration') {
      if (m === 'POST') { // 8.1.1.1
        if (!b) return bad('a JSON object body is required');
        for (const k of Object.keys(b)) if (!RECEIVER_SUPPLIED.includes(k)) return bad(`'${k}' is not a receiver-supplied member`);
        if (b.events_requested !== undefined && !eventsRequestedOk(b.events_requested)) return bad('events_requested must be a non-empty array of event type URIs');
        if (b.description !== undefined && typeof b.description !== 'string') return bad('description must be a string');
        if ((await o.store.listByReceiver(rcv.id)).length >= maxStreams) return { status: 409, body: { error: 'conflict', description: 'this receiver already has the maximum number of streams' } };
        const id = newId();
        const d = deliveryFor(id, b.delivery);
        if (!d.ok) return bad(d.why);
        const events = delivered(b.events_requested as string[] | undefined);
        if (events.length === 0) return bad('none of events_requested is supported by this transmitter');
        const config = build(id, rcv, b.events_requested as string[] | undefined, d.delivery, b.description as string | undefined);
        const problems = validateStreamConfig(config);
        if (problems.length) return bad(problems.join('; '));
        await o.store.put(id, { receiver: rcv.id, config, ...(b.events_requested ? { events_requested: b.events_requested as string[] } : {}), status: 'enabled', subjects: {} });
        return { status: 201, body: config };
      }
      if (m === 'GET') { // 8.1.1.2
        if (q.stream_id === undefined) return { status: 200, body: (await o.store.listByReceiver(rcv.id)).map(([, r]) => r.config) };
        const s = await own(rcv, q.stream_id);
        return s ? { status: 200, body: s.config } : { status: 404, body: { error: 'not_found' } };
      }
      if (m === 'PATCH' || m === 'PUT') { // 8.1.1.3 / 8.1.1.4
        if (!b) return bad('a JSON object body is required');
        const s = await own(rcv, b.stream_id);
        if (typeof b.stream_id !== 'string') return bad('stream_id is required');
        if (!s) return { status: 404, body: { error: 'not_found' } };
        for (const k of Object.keys(b)) if (!RECEIVER_SUPPLIED.includes(k) && !TRANSMITTER_SUPPLIED.includes(k)) return bad(`unknown member '${k}'`);
        // Transmitter-supplied members may be present but must equal the expected value, checked BEFORE any update is applied.
        for (const k of TRANSMITTER_SUPPLIED) {
          if (b[k] === undefined) continue;
          const expected = (s.config as unknown as Record<string, unknown>)[k];
          if (JSON.stringify(b[k]) !== JSON.stringify(expected)) return bad(`'${k}' is transmitter-supplied and does not match`);
        }
        if (b.events_requested !== undefined && !eventsRequestedOk(b.events_requested)) return bad('events_requested must be a non-empty array of event type URIs');
        if (b.description !== undefined && typeof b.description !== 'string') return bad('description must be a string');
        let delivery = s.config.delivery;
        if (b.delivery !== undefined || m === 'PUT') { // PUT: a missing delivery is a deleted one, i.e. the default
          const d = deliveryFor(s.config.stream_id, b.delivery);
          if (!d.ok) return bad(d.why);
          if (d.delivery.method !== s.config.delivery.method) return bad('delivery.method cannot be changed: create a new stream');
          delivery = d.delivery;
        }
        const requested = m === 'PUT' ? (b.events_requested as string[] | undefined) : b.events_requested !== undefined ? (b.events_requested as string[]) : s.events_requested;
        const description = m === 'PUT' ? (b.description as string | undefined) : b.description !== undefined ? (b.description as string) : s.config.description;
        if (delivered(requested).length === 0) return bad('none of events_requested is supported by this transmitter');
        const next = build(s.config.stream_id, rcv, requested, delivery, description);
        if (s.config.min_verification_interval !== undefined) next.min_verification_interval = s.config.min_verification_interval;
        s.config = next;
        if (requested) s.events_requested = requested; else delete s.events_requested;
        await o.store.put(next.stream_id, s);
        return { status: 200, body: next };
      }
      if (m === 'DELETE') { // 8.1.1.5
        const s = await own(rcv, q.stream_id);
        if (!s) return { status: 404, body: { error: 'not_found' } };
        await o.store.delete(q.stream_id as string);
        return { status: 204 };
      }
      return { status: 405, body: { error: 'method_not_allowed' } };
    }

    if (seg === 'status') { // 8.1.2
      if (m === 'GET') {
        const s = await own(rcv, q.stream_id);
        if (!s) return q.stream_id === undefined ? bad('stream_id is required') : { status: 404, body: { error: 'not_found' } };
        return { status: 200, body: { stream_id: q.stream_id, status: s.status, ...(s.status_reason !== undefined ? { reason: s.status_reason } : {}) } };
      }
      if (m === 'POST') {
        if (!b || typeof b.stream_id !== 'string') return bad('stream_id is required');
        if (!(STREAM_STATUSES as readonly unknown[]).includes(b.status)) return bad("status must be 'enabled', 'paused' or 'disabled'");
        if (b.reason !== undefined && typeof b.reason !== 'string') return bad('reason must be a string');
        const s = await own(rcv, b.stream_id);
        if (!s) return { status: 404, body: { error: 'not_found' } };
        s.status = b.status as StreamStatusValue;
        if (b.reason !== undefined) s.status_reason = b.reason as string; else delete s.status_reason;
        await o.store.put(b.stream_id, s);
        return { status: 200, body: { stream_id: b.stream_id, status: s.status, ...(s.status_reason !== undefined ? { reason: s.status_reason } : {}) } };
      }
      return { status: 405, body: { error: 'method_not_allowed' } };
    }

    if (seg === 'add_subject' || seg === 'remove_subject') { // 8.1.3
      if (m !== 'POST') return { status: 405, body: { error: 'method_not_allowed' } };
      if (!b || typeof b.stream_id !== 'string') return bad('stream_id is required');
      const key = subjectKey(b.subject);
      if (key === null) return bad('subject must be a Subject Identifier object with a format');
      if (b.verified !== undefined && typeof b.verified !== 'boolean') return bad('verified must be a boolean');
      const s = await own(rcv, b.stream_id);
      if (!s) return { status: 404, body: { error: 'not_found' } };
      if (seg === 'add_subject') {
        if (!(key in s.subjects) && Object.keys(s.subjects).length >= (o.maxSubjectsPerStream ?? 10_000)) return { status: 429, body: { error: 'too_many_requests', description: 'subject limit reached' } };
        s.subjects[key] = b.verified ?? true; // SSF: SHOULD assume verified when omitted
        await o.store.put(b.stream_id, s);
        return { status: 200 };
      }
      delete s.subjects[key]; // an unknown subject is silently ignored (204)
      await o.store.put(b.stream_id, s);
      return { status: 204 };
    }

    // verification (8.1.4.2)
    if (m !== 'POST') return { status: 405, body: { error: 'method_not_allowed' } };
    if (!b) return bad('a JSON object body is required');
    const s = await own(rcv, b.stream_id);
    if (!s) return typeof b.stream_id === 'string' ? { status: 404, body: { error: 'not_found' } } : bad('stream_id is required');
    if (s.status === 'disabled') return bad('the stream is disabled');
    const view = new Map([[s.config.stream_id, { config: s.config, ...(s.lastVerification !== undefined ? { lastVerification: s.lastVerification } : {}) }]]);
    const out = await handleVerificationRequest(view, { stream_id: b.stream_id, ...(b.state !== undefined ? { state: b.state } : {}) }, o.now(), o.signingKey);
    if (out.status !== 204) return { status: out.status, body: { error: out.status === 429 ? 'too_many_requests' : 'invalid_request', description: out.error } };
    s.lastVerification = o.now();
    await o.store.put(s.config.stream_id, s);
    await o.deliver(s, out.set);
    return { status: 204 };
  }

  return async (req) => {
    try {
      const rcv = await authenticate(req);
      if (!rcv) return { status: 401, body: { error: 'unauthenticated' } };
      return await route(req, rcv);
    } catch {
      return { status: 500, body: { error: 'server_error' } };
    }
  };
}
