import { generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  DELIVERY_POLL, DELIVERY_PUSH, EVENT_TYPES, MemoryStreamStore, ssfManagementHandler, transmitterMetadata,
  type Receiver, type SsfManageOptions, type SsfRequest, type StreamRecord, type StreamStore,
} from './index';

const ISS = 'https://tx.example';
const A = EVENT_TYPES.grantRevoked;
const B = EVENT_TYPES.killSwitch;
const V = EVENT_TYPES.verification;
const NEED_BODY = 'a JSON object body is required';
const err = (description: string) => ({ status: 400, body: { error: 'invalid_request', description } });
const NOT_FOUND = { status: 404, body: { error: 'not_found' } };
const NOT_ALLOWED = { status: 405, body: { error: 'method_not_allowed' } };

async function mk(over: Partial<SsfManageOptions> = {}, opts: { aud?: string | string[]; defaultId?: boolean; store?: StreamStore; auth?: (req: SsfRequest) => Receiver | null | Promise<Receiver | null> } = {}) {
  const { privateKey } = await generateKeyPair('EdDSA');
  const store = new MemoryStreamStore();
  const delivered: string[] = [];
  let n = 0;
  let t = 1000;
  const rcv: Receiver = { id: 'r1', aud: opts.aud ?? 'https://rs.example' };
  const o: SsfManageOptions = {
    store: opts.store ?? store, issuer: ISS, eventsSupported: [A, B, V], pollEndpoint: (id) => `https://tx.example/ssf/poll/${id}`, signingKey: privateKey,
    deliver: (_s, set) => { delivered.push(set); }, now: () => t, newId: () => `s${++n}`, ...over,
  };
  if (opts.defaultId) delete o.newId;
  const h = ssfManagementHandler(o, opts.auth ?? (() => rcv));
  const call = (method: string, path: string, body?: unknown, query: Record<string, string | undefined> = {}) => h({ method, path: `/ssf/${path}`, query, body });
  return { h, call, store: o.store as MemoryStreamStore, delivered, setNow: (x: number) => { t = x; } };
}

describe('ssf management: construction and routing', () => {
  it('default stream ids are 16 base64url characters and differ per stream', async () => {
    const m = await mk({ maxStreamsPerReceiver: 2 }, { defaultId: true });
    const a = (await m.call('POST', 'configuration', {})).body as { stream_id: string };
    const b = (await m.call('POST', 'configuration', {})).body as { stream_id: string };
    expect(a.stream_id).toMatch(/^[A-Za-z0-9_-]{16}$/);
    expect(b.stream_id).toMatch(/^[A-Za-z0-9_-]{16}$/);
    expect(a.stream_id).not.toBe(b.stream_id);
  });
  it('a push-only transmitter requires an explicit delivery', async () => {
    const m = await mk({ deliveryMethods: [DELIVERY_PUSH] });
    expect(await m.call('POST', 'configuration', {})).toEqual(err('delivery is required: this transmitter does not support poll'));
    expect((await m.call('POST', 'configuration', { delivery: { method: DELIVERY_PUSH, endpoint_url: 'https://rs.example/e' } })).status).toBe(201);
  });
  it('unknown or empty paths are an exact 404; a trailing slash still routes', async () => {
    const m = await mk();
    expect(await m.h({ method: 'GET', path: '/' })).toEqual(NOT_FOUND);
    expect(await m.h({ method: 'GET', path: '' })).toEqual(NOT_FOUND);
    expect(await m.call('GET', 'nonsense')).toEqual(NOT_FOUND);
    expect(await m.h({ method: 'GET', path: '/ssf/configuration/' })).toEqual({ status: 200, body: [] });
  });
  it('authentication failure is 401 and any thrown error is an exact 500', async () => {
    const none = await mk({}, { auth: () => null });
    expect(await none.call('GET', 'configuration')).toEqual({ status: 401, body: { error: 'unauthenticated' } });
    const boom = await mk({}, { auth: () => { throw new Error('x'); } });
    expect(await boom.call('GET', 'configuration')).toEqual({ status: 500, body: { error: 'server_error' } });
    const mem = new MemoryStreamStore();
    const broken: StreamStore = { get: mem.get.bind(mem), put: mem.put.bind(mem), delete: mem.delete.bind(mem), listByReceiver: async () => { throw new Error('db'); } };
    const bs = await mk({}, { store: broken });
    expect(await bs.call('GET', 'configuration')).toEqual({ status: 500, body: { error: 'server_error' } });
  });
  it('metadata is exact with and without jwks_uri and custom delivery methods', () => {
    expect(transmitterMetadata({ issuer: ISS }, 'https://b.example')).toEqual({
      spec_version: '1_0', issuer: ISS, delivery_methods_supported: [DELIVERY_PUSH, DELIVERY_POLL], configuration_endpoint: 'https://b.example/ssf/configuration',
      status_endpoint: 'https://b.example/ssf/status', add_subject_endpoint: 'https://b.example/ssf/add_subject', remove_subject_endpoint: 'https://b.example/ssf/remove_subject',
      verification_endpoint: 'https://b.example/ssf/verification', default_subjects: 'NONE',
    });
    const withJwks = transmitterMetadata({ issuer: ISS, deliveryMethods: [DELIVERY_POLL] }, 'https://b.example', 'https://b.example/jwks');
    expect(withJwks.jwks_uri).toBe('https://b.example/jwks');
    expect(withJwks.delivery_methods_supported).toEqual([DELIVERY_POLL]);
    expect('jwks_uri' in transmitterMetadata({ issuer: ISS }, 'https://b.example')).toBe(false);
  });
});

describe('memory stream store', () => {
  it('returns and stores copies, never the held object', async () => {
    const s = new MemoryStreamStore();
    const rec = { receiver: 'r', config: { stream_id: 'x' }, status: 'enabled', subjects: {} } as unknown as StreamRecord;
    await s.put('x', rec);
    rec.status = 'disabled';
    const got = (await s.get('x'))!;
    expect(got.status).toBe('enabled');
    got.status = 'paused';
    expect((await s.get('x'))!.status).toBe('enabled');
    expect(await s.get('y')).toBeUndefined();
    const listed = await s.listByReceiver('r');
    listed[0]![1].status = 'paused';
    expect((await s.get('x'))!.status).toBe('enabled');
  });
});

describe('ssf management: create', () => {
  it('a body that is not a JSON object is refused', async () => {
    const m = await mk();
    for (const body of [undefined, null, 'abc', 5, true, [], ['x']]) expect(await m.call('POST', 'configuration', body)).toEqual(err(NEED_BODY));
    expect(await m.store.listByReceiver('r1')).toEqual([]);
  });
  it('refuses transmitter-supplied members and malformed receiver-supplied members with exact messages', async () => {
    const m = await mk();
    expect(await m.call('POST', 'configuration', { stream_id: 'x' })).toEqual(err("'stream_id' is not a receiver-supplied member"));
    expect(await m.call('POST', 'configuration', { description: 'ok', iss: 'x' })).toEqual(err("'iss' is not a receiver-supplied member"));
    const EVM = 'events_requested must be a non-empty array of event type URIs';
    for (const v of [[], 'abc', 5, null, [A, 5], [A, ''], [A, ['y']], { length: 1 }]) expect(await m.call('POST', 'configuration', { events_requested: v })).toEqual(err(EVM));
    expect(await m.call('POST', 'configuration', { description: 5 })).toEqual(err('description must be a string'));
    expect(await m.call('POST', 'configuration', { events_requested: ['https://x/unsupported'] })).toEqual(err('none of events_requested is supported by this transmitter'));
    expect(await m.store.listByReceiver('r1')).toEqual([]);
  });
  it('refuses unsupported or insecure delivery with exact messages', async () => {
    const m = await mk({ deliveryMethods: [DELIVERY_POLL] });
    const NS = 'delivery.method is not supported by this transmitter';
    for (const d of ['str', null, [], {}, { method: 5 }, { method: 'urn:x' }, { method: DELIVERY_PUSH, endpoint_url: 'https://a.example/e' }]) expect(await m.call('POST', 'configuration', { delivery: d })).toEqual(err(NS));
    const p = await mk();
    const NEEDS = 'push delivery needs an https endpoint_url';
    for (const u of [undefined, ['https://a.example/e'], 'http://a.example/e', 'xhttps://a.example/e', 'https://a b', 'https://']) {
      expect(await p.call('POST', 'configuration', { delivery: { method: DELIVERY_PUSH, endpoint_url: u } })).toEqual(err(NEEDS));
    }
    expect(await p.store.listByReceiver('r1')).toEqual([]);
  });
  it('a poll delivery ignores a receiver-supplied endpoint', async () => {
    const m = await mk();
    const r = await m.call('POST', 'configuration', { delivery: { method: DELIVERY_POLL, endpoint_url: 'http://evil.example/x' } });
    expect(r.status).toBe(201);
    expect((r.body as { delivery: unknown }).delivery).toEqual({ method: DELIVERY_POLL, endpoint_url: 'https://tx.example/ssf/poll/s1' });
  });
  it('the description is truncated to 256 characters', async () => {
    const m = await mk();
    const r = await m.call('POST', 'configuration', { description: 'x'.repeat(300) });
    expect((r.body as { description: string }).description).toBe('x'.repeat(256));
  });
  it('a config that fails the shape check is refused with all problems joined and nothing stored', async () => {
    const bad = await mk({ issuer: '' }, { aud: '' });
    expect(await bad.call('POST', 'configuration', {})).toEqual(err('iss is required; aud must be a non-empty string or array'));
    expect(await bad.store.listByReceiver('r1')).toEqual([]);
    const http = await mk({ pollEndpoint: (id) => `http://x.example/${id}` });
    expect(await http.call('POST', 'configuration', {})).toEqual(err('delivery.endpoint_url must be an https URL'));
    expect(await http.store.listByReceiver('r1')).toEqual([]);
  });
  it('the second stream is an exact 409 and the requested events are remembered', async () => {
    const m = await mk();
    await m.call('POST', 'configuration', { events_requested: [B] });
    expect(await m.call('POST', 'configuration', {})).toEqual({ status: 409, body: { error: 'conflict', description: 'this receiver already has the maximum number of streams' } });
    expect((await m.store.get('s1'))!.events_requested).toEqual([B]);
    const n = await mk();
    await n.call('POST', 'configuration', {});
    expect('events_requested' in (await n.store.get('s1'))!).toBe(false);
  });
});

describe('ssf management: read', () => {
  it('lists the receiver configs exactly and reads one by id', async () => {
    const m = await mk({ maxStreamsPerReceiver: 2 });
    const a = (await m.call('POST', 'configuration', { description: 'one' })).body;
    const b = (await m.call('POST', 'configuration', { description: 'two' })).body;
    expect((await m.call('GET', 'configuration')).body).toEqual([a, b]);
    expect(await m.call('GET', 'configuration', undefined, { stream_id: 's2' })).toEqual({ status: 200, body: b });
    expect(await m.call('GET', 'configuration', undefined, { stream_id: 'zz' })).toEqual(NOT_FOUND);
  });
  it('an unsupported method on configuration is an exact 405', async () => {
    const m = await mk();
    expect(await m.call('OPTIONS', 'configuration', undefined, { stream_id: 'zz' })).toEqual(NOT_ALLOWED);
    expect(await m.call('HEAD', 'configuration')).toEqual(NOT_ALLOWED);
  });
  it('DELETE removes the stream and an unknown or missing id is an exact 404', async () => {
    const m = await mk();
    await m.call('POST', 'configuration', {});
    expect(await m.call('DELETE', 'configuration')).toEqual(NOT_FOUND);
    expect(await m.call('DELETE', 'configuration', undefined, { stream_id: 'zz' })).toEqual(NOT_FOUND);
    expect(await m.call('DELETE', 'configuration', undefined, { stream_id: 's1' })).toEqual({ status: 204 });
    expect(await m.store.get('s1')).toBeUndefined();
  });
});

describe('ssf management: update', () => {
  const seed = async () => {
    const m = await mk();
    await m.call('POST', 'configuration', { events_requested: [B], description: 'a' });
    return m;
  };
  it('refuses a bad body, a missing or unknown stream, and unknown members with exact messages', async () => {
    const m = await seed();
    for (const meth of ['PATCH', 'PUT']) {
      for (const body of [undefined, null, 'abc', []]) expect(await m.call(meth, 'configuration', body)).toEqual(err(NEED_BODY));
      expect(await m.call(meth, 'configuration', {})).toEqual(err('stream_id is required'));
      expect(await m.call(meth, 'configuration', { stream_id: 5 })).toEqual(err('stream_id is required'));
      expect(await m.call(meth, 'configuration', { stream_id: 'nope' })).toEqual(NOT_FOUND);
      expect(await m.call(meth, 'configuration', { stream_id: 's1', zzz: 1 })).toEqual(err("unknown member 'zzz'"));
    }
  });
  it('transmitter-supplied members must match; matching ones are accepted', async () => {
    const m = await seed();
    const cfg = (await m.call('GET', 'configuration', undefined, { stream_id: 's1' })).body as Record<string, unknown>;
    expect(await m.call('PATCH', 'configuration', { stream_id: 's1', iss: 'https://evil' })).toEqual(err("'iss' is transmitter-supplied and does not match"));
    expect(await m.call('PATCH', 'configuration', { stream_id: 's1', min_verification_interval: 5 })).toEqual(err("'min_verification_interval' is transmitter-supplied and does not match"));
    const ok = await m.call('PATCH', 'configuration', { stream_id: 's1', iss: cfg.iss, aud: cfg.aud, events_supported: cfg.events_supported, events_delivered: cfg.events_delivered, description: 'z' });
    expect(ok.status).toBe(200);
  });
  it('validates events_requested, description, delivery and supported events with exact messages', async () => {
    const m = await seed();
    const EVM = 'events_requested must be a non-empty array of event type URIs';
    for (const v of [[], 'abc', 5, null, [A, 5], [A, ''], [A, ['y']]]) expect(await m.call('PATCH', 'configuration', { stream_id: 's1', events_requested: v })).toEqual(err(EVM));
    expect(await m.call('PATCH', 'configuration', { stream_id: 's1', description: 5 })).toEqual(err('description must be a string'));
    expect(await m.call('PATCH', 'configuration', { stream_id: 's1', delivery: { method: 'urn:x' } })).toEqual(err('delivery.method is not supported by this transmitter'));
    expect(await m.call('PATCH', 'configuration', { stream_id: 's1', delivery: { method: DELIVERY_PUSH, endpoint_url: 'https://a.example/e' } })).toEqual(err('delivery.method cannot be changed: create a new stream'));
    expect(await m.call('PATCH', 'configuration', { stream_id: 's1', events_requested: ['https://x/unsupported'] })).toEqual(err('none of events_requested is supported by this transmitter'));
    expect((await m.store.get('s1'))!.events_requested).toEqual([B]);
  });
  it('PATCH keeps what is absent and replaces what is present, in the config and the stored record', async () => {
    const m = await seed();
    const d = (await m.call('PATCH', 'configuration', { stream_id: 's1', description: 'b' })).body as { events_delivered: string[]; description: string };
    expect(d.events_delivered).toEqual([B]);
    expect(d.description).toBe('b');
    expect((await m.store.get('s1'))!.events_requested).toEqual([B]);
    const e = (await m.call('PATCH', 'configuration', { stream_id: 's1', events_requested: [A] })).body as { events_delivered: string[]; description: string };
    expect(e.events_delivered).toEqual([A]);
    expect(e.description).toBe('b');
    expect((await m.store.get('s1'))!.events_requested).toEqual([A]);
    const poll = (await m.call('PATCH', 'configuration', { stream_id: 's1', delivery: { method: DELIVERY_POLL } })).body as { delivery: unknown };
    expect(poll.delivery).toEqual({ method: DELIVERY_POLL, endpoint_url: 'https://tx.example/ssf/poll/s1' });
  });
  it('PUT drops every receiver-supplied member that is absent and replaces those present', async () => {
    const m = await seed();
    const r = (await m.call('PUT', 'configuration', { stream_id: 's1' })).body as Record<string, unknown>;
    expect(r.events_delivered).toEqual([A, B, V]);
    expect('description' in r).toBe(false);
    expect('events_requested' in (await m.store.get('s1'))!).toBe(false);
    const w = (await m.call('PUT', 'configuration', { stream_id: 's1', events_requested: [V], description: 'c' })).body as Record<string, unknown>;
    expect(w.events_delivered).toEqual([V]);
    expect(w.description).toBe('c');
    expect((await m.store.get('s1'))!.events_requested).toEqual([V]);
  });
  it('min_verification_interval survives an update only when the stream has one', async () => {
    const m = await seed();
    const none = (await m.call('PATCH', 'configuration', { stream_id: 's1', description: 'q' })).body as Record<string, unknown>;
    expect('min_verification_interval' in none).toBe(false);
    const rec = (await m.store.get('s1'))!;
    rec.config.min_verification_interval = 30;
    await m.store.put('s1', rec);
    const kept = (await m.call('PATCH', 'configuration', { stream_id: 's1', description: 'q2' })).body as Record<string, unknown>;
    expect(kept.min_verification_interval).toBe(30);
    expect((await m.store.get('s1'))!.config.min_verification_interval).toBe(30);
  });
});

describe('ssf management: status', () => {
  it('reads status with exact errors and omits reason when none is set', async () => {
    const m = await mk();
    await m.call('POST', 'configuration', {});
    expect(await m.call('GET', 'status')).toEqual(err('stream_id is required'));
    expect(await m.call('GET', 'status', undefined, { stream_id: 'zz' })).toEqual(NOT_FOUND);
    const g = await m.call('GET', 'status', undefined, { stream_id: 's1' });
    expect(Object.keys(g.body as object)).toEqual(['stream_id', 'status']);
    expect(await m.call('DELETE', 'status')).toEqual(NOT_ALLOWED);
    expect(await m.call('PUT', 'status', {})).toEqual(NOT_ALLOWED);
  });
  it('POST validates with exact messages and sets and clears the reason', async () => {
    const m = await mk();
    await m.call('POST', 'configuration', {});
    for (const body of [undefined, null, {}, { stream_id: 5, status: 'paused' }]) expect(await m.call('POST', 'status', body)).toEqual(err('stream_id is required'));
    expect(await m.call('POST', 'status', { stream_id: 's1', status: 'on' })).toEqual(err("status must be 'enabled', 'paused' or 'disabled'"));
    expect(await m.call('POST', 'status', { stream_id: 's1', status: 'paused', reason: 5 })).toEqual(err('reason must be a string'));
    expect((await m.store.get('s1'))!.status).toBe('enabled');
    expect(await m.call('POST', 'status', { stream_id: 'zz', status: 'paused' })).toEqual(NOT_FOUND);
    expect(await m.call('POST', 'status', { stream_id: 's1', status: 'paused', reason: 'why' })).toEqual({ status: 200, body: { stream_id: 's1', status: 'paused', reason: 'why' } });
    expect((await m.store.get('s1'))!.status_reason).toBe('why');
    const cleared = await m.call('POST', 'status', { stream_id: 's1', status: 'enabled' });
    expect(Object.keys(cleared.body as object)).toEqual(['stream_id', 'status']);
    expect('status_reason' in (await m.store.get('s1'))!).toBe(false);
    const g = await m.call('GET', 'status', undefined, { stream_id: 's1' });
    expect(Object.keys(g.body as object)).toEqual(['stream_id', 'status']);
  });
});

describe('ssf management: subjects', () => {
  const subj = { format: 'opaque', id: 'u1' };
  it('only POST is allowed and stream_id must be a string', async () => {
    const m = await mk();
    await m.call('POST', 'configuration', {});
    for (const p of ['add_subject', 'remove_subject']) {
      expect(await m.call('GET', p)).toEqual(NOT_ALLOWED);
      for (const body of [undefined, null, { subject: subj }, { stream_id: 5, subject: subj }]) expect(await m.call('POST', p, body)).toEqual(err('stream_id is required'));
      expect(await m.call('POST', p, { stream_id: 'zz', subject: subj })).toEqual(NOT_FOUND);
    }
  });
  it('refuses a subject without a usable format and a non-boolean verified', async () => {
    const m = await mk();
    await m.call('POST', 'configuration', {});
    const MSG = 'subject must be a Subject Identifier object with a format';
    for (const s of [undefined, null, 'str', [], {}, { format: '' }, { format: 5 }, { format: 'x', n: 10n }]) {
      for (const p of ['add_subject', 'remove_subject']) expect(await m.call('POST', p, { stream_id: 's1', subject: s })).toEqual(err(MSG));
    }
    expect(await m.call('POST', 'add_subject', { stream_id: 's1', subject: subj, verified: 'yes' })).toEqual(err('verified must be a boolean'));
    expect((await m.store.get('s1'))!.subjects).toEqual({});
  });
  it('remove_subject removes and the subject key is canonical whatever the member order', async () => {
    const m = await mk();
    await m.call('POST', 'configuration', {});
    const canon = '{"a":"1","b":"2","format":"complex"}';
    for (const s of [{ format: 'complex', b: '2', a: '1' }, { a: '1', b: '2', format: 'complex' }, { b: '2', format: 'complex', a: '1' }, { format: 'complex', a: '1', b: '2' }, { b: '2', a: '1', format: 'complex' }, { a: '1', format: 'complex', b: '2' }]) {
      expect(await m.call('POST', 'add_subject', { stream_id: 's1', subject: s })).toEqual({ status: 200 });
      expect((await m.store.get('s1'))!.subjects).toEqual({ [canon]: true });
    }
    expect(await m.call('POST', 'remove_subject', { stream_id: 's1', subject: { b: '2', format: 'complex', a: '1' } })).toEqual({ status: 204 });
    expect((await m.store.get('s1'))!.subjects).toEqual({});
  });
  it('enforces the per-stream subject limit but still lets an existing subject be updated', async () => {
    const m = await mk({ maxSubjectsPerStream: 2 });
    await m.call('POST', 'configuration', {});
    const s = (id: string) => ({ stream_id: 's1', subject: { format: 'opaque', id } });
    expect((await m.call('POST', 'add_subject', s('x1'))).status).toBe(200);
    expect((await m.call('POST', 'add_subject', s('x2'))).status).toBe(200);
    expect(await m.call('POST', 'add_subject', s('x3'))).toEqual({ status: 429, body: { error: 'too_many_requests', description: 'subject limit reached' } });
    expect(await m.call('POST', 'add_subject', { ...s('x1'), verified: false })).toEqual({ status: 200 });
    expect((await m.store.get('s1'))!.subjects['{"format":"opaque","id":"x1"}']).toBe(false);
    expect(Object.keys((await m.store.get('s1'))!.subjects)).toHaveLength(2);
  });
  it('the default limit is 10000 subjects', async () => {
    const m = await mk();
    await m.call('POST', 'configuration', {});
    const rec = (await m.store.get('s1'))!;
    for (let i = 0; i < 10_000; i++) rec.subjects[JSON.stringify({ format: 'opaque', id: `i${i}` })] = true;
    await m.store.put('s1', rec);
    const add = (id: string) => m.call('POST', 'add_subject', { stream_id: 's1', subject: { format: 'opaque', id } });
    expect((await add('new')).status).toBe(429);
    expect((await m.call('POST', 'remove_subject', { stream_id: 's1', subject: { format: 'opaque', id: 'i0' } })).status).toBe(204);
    expect((await add('new')).status).toBe(200);
    expect((await add('new2')).status).toBe(429);
  });
});

describe('ssf management: verification', () => {
  it('refuses with exact messages and does not look up a non-string stream id', async () => {
    const mem = new MemoryStreamStore();
    const gets: unknown[] = [];
    const spy: StreamStore = { get: async (id) => { gets.push(id); return mem.get(id); }, put: mem.put.bind(mem), delete: mem.delete.bind(mem), listByReceiver: mem.listByReceiver.bind(mem) };
    const m = await mk({}, { store: spy });
    await m.call('POST', 'configuration', {});
    expect(await m.call('GET', 'verification')).toEqual(NOT_ALLOWED);
    expect(await m.call('POST', 'verification', undefined)).toEqual(err(NEED_BODY));
    gets.length = 0;
    expect(await m.call('POST', 'verification', { stream_id: 5 })).toEqual(err('stream_id is required'));
    expect(await m.call('POST', 'verification', {})).toEqual(err('stream_id is required'));
    expect(gets).toEqual([]);
    expect(await m.call('POST', 'verification', { stream_id: 'zz' })).toEqual(NOT_FOUND);
    expect(await m.call('POST', 'verification', { stream_id: 's1', state: 5 })).toEqual(err('stream_id (string) is required; state must be a string'));
    expect(m.delivered).toEqual([]);
    expect('lastVerification' in (await m.store.get('s1'))!).toBe(false);
    await m.call('POST', 'status', { stream_id: 's1', status: 'disabled' });
    expect(await m.call('POST', 'verification', { stream_id: 's1' })).toEqual(err('the stream is disabled'));
  });
  it('a request inside min_verification_interval is an exact 429 and delivers nothing', async () => {
    const m = await mk();
    await m.call('POST', 'configuration', {});
    const rec = (await m.store.get('s1'))!;
    rec.config.min_verification_interval = 30;
    await m.store.put('s1', rec);
    expect(await m.call('POST', 'verification', { stream_id: 's1', state: 'a' })).toEqual({ status: 204 });
    expect((await m.store.get('s1'))!.lastVerification).toBe(1000);
    m.setNow(1010);
    expect(await m.call('POST', 'verification', { stream_id: 's1', state: 'b' })).toEqual({ status: 429, body: { error: 'too_many_requests', description: 'verification requested too soon' } });
    expect(m.delivered).toHaveLength(1);
    expect((await m.store.get('s1'))!.lastVerification).toBe(1000);
    m.setNow(1030);
    expect(await m.call('POST', 'verification', { stream_id: 's1', state: 'c' })).toEqual({ status: 204 });
    expect(m.delivered).toHaveLength(2);
    expect((await m.store.get('s1'))!.lastVerification).toBe(1030);
  });
});
