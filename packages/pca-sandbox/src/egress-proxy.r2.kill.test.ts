import dns from 'node:dns';
import http from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';
import { authFixture } from './test-auth';
import { EgressPolicy, ReceiptLog, createEgressProxy, type EgressTemplate } from './index';

const get = { verb: 'http.get', resource: 'api', params: { path: '/v1/items' } };
const closers: (() => void)[] = [];
afterEach(() => {
  closers.splice(0).forEach((c) => c());
  vi.restoreAllMocks();
});
const listen = (s: net.Server, host = '127.0.0.1'): Promise<number | null> =>
  new Promise((r) => {
    s.once('error', () => r(null));
    s.listen(0, host, () => {
      closers.push(() => s.close());
      r((s.address() as AddressInfo).port);
    });
  });

function viaProxy(port: number, method: string, url: string): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method, path: url, headers: { host: new URL(url).host } }, (res) => {
      const c: Buffer[] = [];
      res.on('data', (d) => c.push(d));
      res.on('end', () => resolve({ status: res.statusCode!, text: Buffer.concat(c).toString() }));
    });
    r.on('error', reject);
    r.end();
  });
}

async function setup(over: Partial<EgressTemplate>, proxyOpts: Partial<Parameters<typeof createEgressProxy>[0]> = {}) {
  const f = authFixture(['api']);
  const policy = new EgressPolicy();
  policy.admit(await f.allow(get), get, () => ({ method: 'GET', scheme: 'http', host: '127.0.0.1', path: '/v1/items', ...over }));
  const log = new ReceiptLog({ now: () => 1 });
  const server = createEgressProxy({ policy, log, allowPrivate: true, ...proxyOpts });
  const port = (await listen(server))!;
  return { port, log, server };
}

describe('egress admission without an operation id', () => {
  it('a result whose operation carries no id is admitted and claimed with an empty op_id', async () => {
    const f = authFixture(['api']);
    const result = await f.allow(get);
    const bound = (result as unknown as { operation: Record<string, unknown> }).operation;
    const noId = { ...result, operation: { ...bound, id: undefined } } as unknown as typeof result;
    const policy = new EgressPolicy();
    policy.admit(noId, get, () => ({ method: 'GET', scheme: 'http', host: '127.0.0.1', path: '/v1/items' }));
    expect(policy.claim({ method: 'GET', url: 'http://127.0.0.1/v1/items' })).toEqual({
      allow: true,
      op_id: '',
      admission: { verb: 'http.get', resource: 'api', params_digest: hashCanonical(get.params) },
    });
  });
});

describe('egress proxy upstream address guard', () => {
  it('a hostname with one private and one public answer is refused, not dialled', async () => {
    const realLookup = dns.lookup;
    vi.spyOn(dns, 'lookup').mockImplementation(((h: string, options: dns.LookupOptions | undefined, cb: (...a: unknown[]) => void) => {
      if (net.isIP(h)) return (realLookup as (...a: unknown[]) => void)(h, options, cb);
      if (options?.all === true) cb(null, [{ address: '93.184.216.34', family: 4 }, { address: '127.0.0.1', family: 4 }]);
      else cb(null, '127.0.0.1', 4);
    }) as never);
    const seen: string[] = [];
    const origin = http.createServer((req, res) => { seen.push(req.url!); res.end('from-origin'); });
    const op = (await listen(origin))!;
    const { port, log } = await setup({ host: 'mixed.example', port: op }, { allowPrivate: false, upstreamTimeoutMs: 300 });
    const r = await viaProxy(port, 'GET', `http://mixed.example:${op}/v1/items`);
    expect(r.status).toBe(502);
    expect(log.entries[0]).toMatchObject({ outcome: 'error', reason: 'upstream:EACCES' });
    expect(seen).toEqual([]);
  });
});

describe('egress proxy reaches an IPv6 literal', () => {
  it('forwards a plain request to a bracketed IPv6 origin', async () => {
    const origin = http.createServer((_req, res) => res.end('from-v6'));
    const op = await listen(origin, '::1');
    if (op === null) return; // no IPv6 loopback on this machine
    const { port } = await setup({ host: '::1', port: op });
    const r = await viaProxy(port, 'GET', `http://[::1]:${op}/v1/items`);
    expect(r).toEqual({ status: 200, text: 'from-v6' });
  });
  it('opens a tunnel to a bracketed IPv6 target', async () => {
    const echo = net.createServer((s) => s.on('data', (d) => s.write(d)));
    const op = await listen(echo, '::1');
    if (op === null) return;
    const f = authFixture(['api']);
    const policy = new EgressPolicy();
    policy.admit(await f.allow(get), get, () => ({ method: 'CONNECT', scheme: 'https', host: '::1', port: op, path: '/', tunnel: true }));
    const proxy = (await listen(createEgressProxy({ policy, log: new ReceiptLog(), allowPrivate: true })))!;
    const head = await new Promise<string>((resolve) => {
      const sock = net.connect(proxy, '127.0.0.1', () => sock.write(`CONNECT [::1]:${op} HTTP/1.1\r\nhost: x\r\n\r\n`));
      sock.once('data', (d) => { sock.destroy(); resolve(d.toString()); });
    });
    expect(head).toBe('HTTP/1.1 200 Connection Established\r\n\r\n');
  });
});

describe('egress proxy tunnel teardown', () => {
  it('closes the client connection once the upstream closes, even if the client never hangs up', async () => {
    const origin = net.createServer((s) => s.end());
    const op = (await listen(origin))!;
    const f = authFixture(['api']);
    const policy = new EgressPolicy();
    policy.admit(await f.allow(get), get, () => ({ method: 'CONNECT', scheme: 'https', host: '127.0.0.1', port: op, path: '/', tunnel: true }));
    const server = createEgressProxy({ policy, log: new ReceiptLog(), allowPrivate: true });
    const proxySide: net.Socket[] = [];
    server.on('connection', (s) => proxySide.push(s));
    const proxy = (await listen(server))!;
    const client = net.connect({ port: proxy, host: '127.0.0.1', allowHalfOpen: true }, () => client.write(`CONNECT 127.0.0.1:${op} HTTP/1.1\r\nhost: x\r\n\r\n`));
    closers.push(() => client.destroy());
    await new Promise<void>((r) => client.once('data', () => r()));
    const s = proxySide[0]!;
    if (!s.destroyed) await new Promise<void>((r) => s.once('close', () => r()));
    expect(s.destroyed).toBe(true);
  });
});
