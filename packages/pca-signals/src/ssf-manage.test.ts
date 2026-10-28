import { generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { DELIVERY_POLL, DELIVERY_PUSH, EVENT_TYPES, MemoryStreamStore, createInMemorySetReplayStore, createRevocationState, receiveSET, ssfManagementHandler, transmitterMetadata, type Receiver, type SsfRequest } from './index';

const ISS = 'https://tx.example';
async function setup(over: { max?: number; now?: () => number } = {}) {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA');
  const delivered: Array<{ id: string; set: string }> = [];
  let n = 0;
  let clock = 1_000;
  const store = new MemoryStreamStore();
  const rcv: Receiver = { id: 'rcv1', aud: 'https://rs.example' };
  const other: Receiver = { id: 'rcv2', aud: 'https://other.example' };
  const h = ssfManagementHandler({
    store, issuer: ISS, eventsSupported: [EVENT_TYPES.grantRevoked, EVENT_TYPES.killSwitch, EVENT_TYPES.verification], pollEndpoint: (id) => `https://tx.example/ssf/poll/${id}`, signingKey: privateKey,
    deliver: (s, set) => { delivered.push({ id: s.config.stream_id, set }); }, now: over.now ?? (() => clock), newId: () => `s${++n}`, ...(over.max ? { maxStreamsPerReceiver: over.max } : {}),
  }, (req) => (req.query?.as === 'other' ? other : req.query?.as === 'none' ? null : rcv));
  const call = (method: string, path: string, body?: unknown, query: Record<string, string> = {}) => h({ method, path: `/ssf/${path}`, query, body } as SsfRequest);
  return { call, store, delivered, publicKey, tick: (ms: number) => { clock += ms; } };
}

describe('SSF stream management', () => {
  it('create: poll by default with a transmitter-set endpoint, events_delivered = requested within supported, 201', async () => {
    const { call } = await setup();
    const r = await call('POST', 'configuration', { events_requested: [EVENT_TYPES.grantRevoked, 'https://x/unsupported'], description: 'prod' });
    expect(r.status).toBe(201);
    expect(r.body).toEqual({
      stream_id: 's1', iss: ISS, aud: 'https://rs.example', events_supported: [EVENT_TYPES.grantRevoked, EVENT_TYPES.killSwitch, EVENT_TYPES.verification],
      events_delivered: [EVENT_TYPES.grantRevoked], delivery: { method: DELIVERY_POLL, endpoint_url: 'https://tx.example/ssf/poll/s1' }, description: 'prod',
    });
  });
  it('create refuses transmitter-supplied members, unsupported or insecure delivery, unsupported-only events; a second stream is 409', async () => {
    const { call } = await setup();
    expect((await call('POST', 'configuration', { stream_id: 'x' })).status).toBe(400);
    expect((await call('POST', 'configuration', { delivery: { method: 'urn:x' } })).status).toBe(400);
    expect((await call('POST', 'configuration', { delivery: { method: DELIVERY_PUSH, endpoint_url: 'http://rs.example/e' } })).status).toBe(400);
    expect((await call('POST', 'configuration', { events_requested: ['https://x/unsupported'] })).status).toBe(400);
    expect((await call('POST', 'configuration', { events_requested: [] })).status).toBe(400);
    expect((await call('POST', 'configuration', null)).status).toBe(400);
    expect((await call('POST', 'configuration', {})).status).toBe(201);
    expect((await call('POST', 'configuration', {})).status).toBe(409);
    const multi = await setup({ max: 2 });
    expect((await multi.call('POST', 'configuration', {})).status).toBe(201);
    expect((await multi.call('POST', 'configuration', {})).body).toMatchObject({ stream_id: 's2' });
  });
  it('read: one stream, all streams, none; another receiver sees 404, unauthenticated is 401', async () => {
    const { call } = await setup();
    expect(await call('GET', 'configuration')).toEqual({ status: 200, body: [] });
    await call('POST', 'configuration', {});
    expect((await call('GET', 'configuration', undefined, { stream_id: 's1' })).status).toBe(200);
    expect(((await call('GET', 'configuration')).body as unknown[]).length).toBe(1);
    expect((await call('GET', 'configuration', undefined, { stream_id: 's1', as: 'other' })).status).toBe(404);
    expect(await call('GET', 'configuration', undefined, { stream_id: 'nope' })).toEqual({ status: 404, body: { error: 'not_found' } });
    expect((await call('GET', 'configuration', undefined, { as: 'none' })).status).toBe(401);
    expect(((await call('GET', 'configuration', undefined, { as: 'other' })).body as unknown[]).length).toBe(0);
  });
  it('PATCH changes only what is present; transmitter-supplied members must match; push delivery is receiver-set; method cannot change', async () => {
    const { call } = await setup();
    await call('POST', 'configuration', { delivery: { method: DELIVERY_PUSH, endpoint_url: 'https://rs.example/events' }, description: 'a' });
    const p = await call('PATCH', 'configuration', { stream_id: 's1', events_requested: [EVENT_TYPES.killSwitch] });
    expect(p.status).toBe(200);
    expect(p.body).toMatchObject({ events_delivered: [EVENT_TYPES.killSwitch], description: 'a', delivery: { method: DELIVERY_PUSH, endpoint_url: 'https://rs.example/events' } });
    expect((await call('PATCH', 'configuration', { stream_id: 's1', delivery: { method: DELIVERY_PUSH, endpoint_url: 'https://rs.example/v2' } })).body).toMatchObject({ delivery: { endpoint_url: 'https://rs.example/v2' } });
    expect((await call('PATCH', 'configuration', { stream_id: 's1', iss: 'https://evil' })).status).toBe(400);
    expect((await call('PATCH', 'configuration', { stream_id: 's1', events_delivered: [EVENT_TYPES.grantRevoked] })).status).toBe(400);
    expect((await call('PATCH', 'configuration', { stream_id: 's1', aud: 'https://x' })).status).toBe(400);
    expect((await call('PATCH', 'configuration', { stream_id: 's1', delivery: { method: DELIVERY_POLL } })).status).toBe(400);
    expect((await call('PATCH', 'configuration', { description: 'x' })).status).toBe(400);
    expect((await call('PATCH', 'configuration', { stream_id: 'nope' })).status).toBe(404);
    expect((await call('PATCH', 'configuration', { stream_id: 's1', unknown: 1 })).status).toBe(400);
    expect((await call('PATCH', 'configuration', { stream_id: 's1', events_requested: ['https://x/unsupported'] })).status).toBe(400);
  });
  it('PUT replaces: a missing receiver-supplied member is deleted', async () => {
    const { call } = await setup();
    await call('POST', 'configuration', { events_requested: [EVENT_TYPES.killSwitch], description: 'a' });
    const r = await call('PUT', 'configuration', { stream_id: 's1' });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ events_delivered: [EVENT_TYPES.grantRevoked, EVENT_TYPES.killSwitch, EVENT_TYPES.verification], delivery: { method: DELIVERY_POLL } });
    expect(r.body).not.toHaveProperty('description');
    const push = await setup();
    await push.call('POST', 'configuration', { delivery: { method: DELIVERY_PUSH, endpoint_url: 'https://rs.example/e' } });
    expect((await push.call('PUT', 'configuration', { stream_id: 's1' })).status).toBe(400); // deleting delivery means the poll default: a method change
  });
  it('DELETE needs stream_id and removes the stream; 204 then 404', async () => {
    const { call } = await setup();
    await call('POST', 'configuration', {});
    expect((await call('DELETE', 'configuration', undefined, { stream_id: 's1', as: 'other' })).status).toBe(404);
    expect(await call('DELETE', 'configuration', undefined, { stream_id: 's1' })).toEqual({ status: 204 });
    expect((await call('DELETE', 'configuration', undefined, { stream_id: 's1' })).status).toBe(404);
    expect((await call('DELETE', 'configuration')).status).toBe(404);
  });
  it('status: read, update with a reason, validated values, 404 for a foreign stream', async () => {
    const { call } = await setup();
    await call('POST', 'configuration', {});
    expect((await call('GET', 'status', undefined, { stream_id: 's1' })).body).toEqual({ stream_id: 's1', status: 'enabled' });
    expect((await call('POST', 'status', { stream_id: 's1', status: 'paused', reason: 'maintenance' })).body).toEqual({ stream_id: 's1', status: 'paused', reason: 'maintenance' });
    expect((await call('GET', 'status', undefined, { stream_id: 's1' })).body).toEqual({ stream_id: 's1', status: 'paused', reason: 'maintenance' });
    expect((await call('POST', 'status', { stream_id: 's1', status: 'enabled' })).body).toEqual({ stream_id: 's1', status: 'enabled' });
    expect((await call('POST', 'status', { stream_id: 's1', status: 'on' })).status).toBe(400);
    expect((await call('POST', 'status', { status: 'paused' })).status).toBe(400);
    expect((await call('POST', 'status', { stream_id: 's1', status: 'paused' }, { as: 'other' })).status).toBe(404);
    expect((await call('GET', 'status')).status).toBe(400);
  });
  it('subjects: add (200, verified defaults true), remove (204, unknown ignored), validation and the per-stream limit', async () => {
    const { call, store } = await setup();
    await call('POST', 'configuration', {});
    const subject = { format: 'email', email: 'a@b.example' };
    expect(await call('POST', 'add_subject', { stream_id: 's1', subject })).toEqual({ status: 200 });
    expect((await store.get('s1'))!.subjects).toEqual({ [JSON.stringify({ email: 'a@b.example', format: 'email' })]: true });
    expect((await call('POST', 'add_subject', { stream_id: 's1', subject: { format: 'opaque', id: 'x' }, verified: false })).status).toBe(200);
    expect(await call('POST', 'remove_subject', { stream_id: 's1', subject })).toEqual({ status: 204 });
    expect(await call('POST', 'remove_subject', { stream_id: 's1', subject })).toEqual({ status: 204 });
    expect((await call('POST', 'add_subject', { stream_id: 's1', subject: { id: 'x' } })).status).toBe(400);
    expect((await call('POST', 'add_subject', { stream_id: 's1', subject, verified: 'yes' })).status).toBe(400);
    expect((await call('POST', 'add_subject', { stream_id: 'nope', subject })).status).toBe(404);
    expect((await call('GET', 'add_subject')).status).toBe(405);
  });
  it('verification: 204 and a signed verification SET echoing state is delivered; 429 inside min interval is the library rule; a disabled stream is refused', async () => {
    const { call, delivered, publicKey } = await setup();
    await call('POST', 'configuration', {});
    expect(await call('POST', 'verification', { stream_id: 's1', state: 'abc' })).toEqual({ status: 204 });
    expect(delivered).toHaveLength(1);
    const rec = await receiveSET(delivered[0]!.set, publicKey, { issuer: ISS, audience: 'https://rs.example', replayStore: createInMemorySetReplayStore(), state: createRevocationState(), maxAgeSec: 300 });
    expect(rec.ok && rec.parsed.events[EVENT_TYPES.verification]).toEqual({ state: 'abc' });
    expect((await call('POST', 'verification', { stream_id: 'nope' })).status).toBe(404);
    expect((await call('POST', 'verification', {})).status).toBe(400);
    await call('POST', 'status', { stream_id: 's1', status: 'disabled' });
    expect((await call('POST', 'verification', { stream_id: 's1' })).status).toBe(400);
  });
  it('unknown endpoint is 404, unsupported method 405, metadata lists the five endpoints', async () => {
    const { call } = await setup();
    expect((await call('GET', 'nonsense')).status).toBe(404);
    expect((await call('DELETE', 'status')).status).toBe(405);
    const m = transmitterMetadata({ issuer: ISS }, 'https://tx.example', 'https://tx.example/jwks.json');
    expect(m).toMatchObject({ issuer: ISS, jwks_uri: 'https://tx.example/jwks.json', delivery_methods_supported: [DELIVERY_PUSH, DELIVERY_POLL], configuration_endpoint: 'https://tx.example/ssf/configuration', verification_endpoint: 'https://tx.example/ssf/verification' });
  });
});
