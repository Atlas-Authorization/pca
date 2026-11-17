import { existsSync, mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { b64u } from '@atlasauth/pca';
import { verifyEnvelope } from '@atlasauth/pca-control-plane';
import { describe, expect, it } from 'vitest';
import { QUEUE_MAX, Reporter, connect, parseSetupToken } from './connect';
import { ConfigError } from './config';

const tokenFor = (o: Record<string, unknown> = {}): string => `pcs1.${Buffer.from(JSON.stringify({ o: 'https://api.example.com', i: 'ins_1', s: 'support-bot', k: 'secretsecretsecretsecret', ...o })).toString('base64url')}`;
const dir = (): string => mkdtempSync(join(tmpdir(), 'pcap-connect-'));
const SIGNER = 'S'.repeat(43);
type Call = { url: string; body: Record<string, unknown> };
function api(answer: (url: string, body: Record<string, any>) => { status: number; json?: unknown }) {
  const calls: Call[] = [];
  const f = (async (url: string, init: { body: string }) => {
    const body = JSON.parse(init.body) as Record<string, any>;
    calls.push({ url, body });
    const r = answer(url, body);
    return { status: r.status, ok: r.status < 300, json: async () => r.json, text: async () => '' } as Response;
  }) as unknown as typeof fetch;
  return { f, calls };
}
const registers = (url: string) => (url.endsWith('/connect') ? { status: 200, json: { instance_id: 'ins_1', source: 'support-bot', signer: SIGNER, ingest_key: 'sk_test_abc' } } : { status: 202 });

describe('the setup token', () => {
  it('names the API, the instance and the source', () => {
    expect(parseSetupToken(tokenFor())).toEqual({ origin: 'https://api.example.com', instanceId: 'ins_1', source: 'support-bot' });
  });
  it('is refused when it is not one, or points at a cleartext API', () => {
    for (const t of ['nope', 'pcs1.!!!', tokenFor({ o: 'http://api.example.com' }), tokenFor({ o: 'not a url' }), tokenFor({ i: 7 })]) expect(() => parseSetupToken(t)).toThrow(ConfigError);
    expect(parseSetupToken(tokenFor({ o: 'http://localhost:4000' })).origin).toBe('http://localhost:4000');
  });
});

describe('connect: make a key, register it, remember it', () => {
  it('registers the public half only, keeps the secret in a private file, and resumes without a token', async () => {
    const d = dir();
    const { f, calls } = api(registers);
    const c = await connect({ token: tokenFor(), dir: d, fetch: f });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://api.example.com/v1/pca/control/connect');
    expect(calls[0]!.body).toEqual({ token: tokenFor(), source: 'support-bot', public_key: c.publicKey, agent: 'support-bot' });
    expect(JSON.stringify(calls[0]!.body)).not.toContain(b64u(c.secret));
    expect(statSync(join(d, 'source.key')).mode & 0o077).toBe(0);
    expect(c).toMatchObject({ source: 'support-bot', instanceId: 'ins_1', signer: SIGNER, ingestKey: 'sk_test_abc' });
    expect(statSync(join(d, 'connection.json')).mode & 0o077).toBe(0);
    const again = await connect({ dir: d, fetch: f });
    expect(calls).toHaveLength(1);
    expect(again.publicKey).toBe(c.publicKey);
    expect(b64u(again.secret)).toBe(b64u(c.secret));
  });

  it('a token for another source starts a new connection with a new key', async () => {
    const d = dir();
    const { f, calls } = api(registers);
    const first = await connect({ token: tokenFor(), dir: d, fetch: f });
    const { f: f2, calls: c2 } = api((_u, _b) => ({ status: 200, json: { instance_id: 'ins_1', source: 'other-bot', signer: SIGNER, ingest_key: 'sk_test_def' } }));
    const second = await connect({ token: tokenFor({ s: 'other-bot' }), dir: d, fetch: f2 });
    expect(c2).toHaveLength(1);
    expect(second.publicKey).not.toBe(first.publicKey);
    expect(calls).toHaveLength(1);
  });

  it('says to make a new token when the control plane refuses it, and saves no connection', async () => {
    const d = dir();
    const { f } = api(() => ({ status: 401 }));
    await expect(connect({ token: tokenFor(), dir: d, fetch: f })).rejects.toThrow(/expires after ten minutes/);
    expect(existsSync(join(d, 'connection.json'))).toBe(false);
  });

  it('refuses an answer for a different setup', async () => {
    const { f } = api(() => ({ status: 200, json: { instance_id: 'ins_2', source: 'support-bot', signer: SIGNER, ingest_key: 'sk_test_abc' } }));
    await expect(connect({ token: tokenFor(), dir: dir(), fetch: f })).rejects.toThrow(/different setup/);
  });

  it('needs a token the first time', async () => {
    await expect(connect({ dir: dir() })).rejects.toThrow(/needs the setup token/);
  });

  it('keeps the same key when the first registration failed halfway, so the same token can be retried', async () => {
    const d = dir();
    let n = 0;
    const { f, calls } = api((u) => (++n === 1 ? { status: 503 } : registers(u)));
    await expect(connect({ token: tokenFor(), dir: d, fetch: f })).rejects.toThrow(/answered 503/);
    const c = await connect({ token: tokenFor(), dir: d, fetch: f });
    expect(calls[0]!.body.public_key).toBe(calls[1]!.body.public_key);
    expect(c.publicKey).toBe(calls[1]!.body.public_key);
  });
});

const receipt = (seq: number, extra: Record<string, unknown> = {}) => ({ seq, at: 1_800_000_000_000 + seq, actionDigest: 'd', verb: 'gh.create_issue', resource: `issue/${seq}`, outcome: 'allow', checks: { mode: 'observe', allowed: 'true' }, prev: '', hash: `h${seq}`, ...extra }) as never;

describe('the reporter', () => {
  async function conn() {
    const { f, calls } = api(registers);
    const c = await connect({ token: tokenFor(), dir: dir(), fetch: f });
    return { c, calls };
  }

  it('sends signed batches the control plane accepts, with the observed parameters', async () => {
    const { c } = await conn();
    const { f, calls } = api(() => ({ status: 202 }));
    const r = new Reporter(c, { fetch: f, now: () => 1_800_000_100_000 });
    r.push(receipt(1, { checks: { mode: 'observe', allowed: 'true', obs1: 'a'.repeat(22), obs2: 'b'.repeat(21) } }), { params: { amount: 5 }, omitted: ['note'], digest: `${'a'.repeat(22)}${'b'.repeat(21)}` });
    r.push(receipt(2));
    await r.close();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://api.example.com/v1/pca/control/events');
    expect(Object.keys(calls[0]!.body)).toEqual(['envelope']);
    const env = calls[0]!.body.envelope as { events: Array<Record<string, unknown>>; source: string };
    expect(verifyEnvelope(env, { 'support-bot': c.publicKey }, 256).ok).toBe(true);
    expect(env.events[0]).toMatchObject({ id: 'h1', mode: 'observe', observed: { seq: 1, params: { amount: 5 }, omitted: ['note'] } });
    expect(env.events[1]!.observed).toBeUndefined();
  });

  it('keeps the batch and retries on a network failure, with a rising sequence number', async () => {
    const { c } = await conn();
    let n = 0;
    const seqs: number[] = [];
    const { f } = api((_u, b) => {
      seqs.push(b.envelope.seq);
      return ++n === 1 ? { status: 503 } : { status: 202 };
    });
    const r = new Reporter(c, { fetch: f, now: () => 1_800_000_100_000 });
    r.push(receipt(1));
    await r.flush();
    await r.flush();
    expect(seqs).toHaveLength(2);
    expect(seqs[1]!).toBeGreaterThan(seqs[0]!);
    await r.close();
  });

  it('drops a batch the control plane refuses, says so, and keeps going', async () => {
    const { c } = await conn();
    const logs: string[] = [];
    let n = 0;
    const { f, calls } = api(() => (++n === 1 ? { status: 403 } : { status: 202 }));
    const r = new Reporter(c, { fetch: f, log: (s) => logs.push(s) });
    r.push(receipt(1));
    await r.flush();
    r.push(receipt(2));
    await r.close();
    expect(calls).toHaveLength(2);
    expect(logs.join()).toMatch(/refused a batch \(403\)/);
  });

  it('is bounded: a long outage drops the oldest events, not memory', async () => {
    const { c } = await conn();
    const { f } = api(() => ({ status: 503 }));
    const logs: string[] = [];
    const r = new Reporter(c, { fetch: f, log: (s) => logs.push(s) });
    for (let i = 0; i < QUEUE_MAX + 10; i++) r.push(receipt(i));
    expect((r as unknown as { queue: unknown[] }).queue).toHaveLength(QUEUE_MAX);
    expect(logs.join()).toMatch(/unreachable/);
    (r as unknown as { closed: boolean }).closed = true;
  });

  it('a receipt that is not one is skipped, never guessed', async () => {
    const { c } = await conn();
    const r = new Reporter(c, { fetch: api(() => ({ status: 202 })).f });
    r.push({ verb: 'x' } as never);
    expect((r as unknown as { queue: unknown[] }).queue).toHaveLength(0);
    (r as unknown as { closed: boolean }).closed = true;
  });
});
