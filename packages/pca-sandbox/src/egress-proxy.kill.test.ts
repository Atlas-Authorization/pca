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
const listen = (s: net.Server): Promise<number> => new Promise((r) => s.listen(0, '127.0.0.1', () => { closers.push(() => s.close()); r((s.address() as AddressInfo).port); }));

async function origin(handler?: http.RequestListener) {
  const seen: { method: string; url: string; headers: http.IncomingHttpHeaders }[] = [];
  const s = http.createServer(handler ?? ((req, res) => { seen.push({ method: req.method!, url: req.url!, headers: req.headers }); res.writeHead(200, { 'x-origin': '1', 'proxy-authenticate': 'secret', 'keep-alive': 'timeout=77' }).end('from-origin'); }));
  s.on('request', (req) => { if (handler) seen.push({ method: req.method!, url: req.url!, headers: req.headers }); });
  return { seen, port: await listen(s) };
}

function viaProxy(port: number, method: string, url: string, body?: string, headers: http.OutgoingHttpHeaders = {}): Promise<{ status: number; text: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method, path: url, headers: { host: new URL(url).host, ...headers } }, (res) => {
      const c: Buffer[] = [];
      res.on('data', (d) => c.push(d));
      res.on('end', () => resolve({ status: res.statusCode!, text: Buffer.concat(c).toString(), headers: res.headers }));
    });
    r.on('error', reject);
    r.end(body);
  });
}

async function setup(over: Partial<EgressTemplate>, proxyOpts: Partial<Parameters<typeof createEgressProxy>[0]> = {}) {
  const f = authFixture(['api']);
  const policy = new EgressPolicy();
  const result = await f.allow(get);
  policy.admit(result, get, () => ({ method: 'GET', scheme: 'http', host: '127.0.0.1', path: '/v1/items', ...over }));
  const log = new ReceiptLog({ now: () => 1 });
  const port = await listen(createEgressProxy({ policy, log, allowPrivate: true, ...proxyOpts }));
  return { port, log, policy, opId: (result as unknown as { operation: { id: string } }).operation.id };
}

describe('egress proxy receipts and responses', () => {
  it('a refusal is a JSON 403 with a receipt whose resource is the truncated request line', async () => {
    const o = await origin();
    const { port, log } = await setup({ port: o.port });
    const url = `http://127.0.0.1:${o.port}/${'x'.repeat(400)}`;
    const r = await viaProxy(port, 'GET', url);
    expect(r.status).toBe(403);
    expect(r.headers['content-type']).toBe('application/json');
    expect(JSON.parse(r.text)).toEqual({ error: 'egress_denied', reason: 'no_admission' });
    expect(log.entries).toHaveLength(1);
    expect(log.entries[0]).toMatchObject({
      kind: 'egress',
      outcome: 'refused',
      reason: 'no_admission',
      subject: { op_id: '', verb: '', resource: `GET ${url}`.slice(0, 256), params_digest: '' },
    });
    expect(log.entries[0]!.subject.resource).toHaveLength(256);
  });
  it('an allowed request is receipted with the operation it was admitted for', async () => {
    const o = await origin();
    const { port, log, opId } = await setup({ port: o.port });
    expect((await viaProxy(port, 'GET', `http://127.0.0.1:${o.port}/v1/items`)).status).toBe(200);
    expect(log.entries[0]!.subject).toEqual({ op_id: opId, verb: 'http.get', resource: 'api', params_digest: hashCanonical(get.params) });
  });
  it('a body exactly at the cap passes, one byte over is 413 with a JSON reason', async () => {
    const o = await origin();
    const f = authFixture(['api']);
    const post = { verb: 'http.post', resource: 'api', params: { a: 1 } };
    const sha = (await import('./egress')).sha256b64u;
    const mk = async (body: string) => {
      const policy = new EgressPolicy();
      policy.admit(await f.allow(post), post, () => ({ method: 'POST', scheme: 'http', host: '127.0.0.1', port: o.port, path: '/p', body_sha256: sha(new TextEncoder().encode(body)) }));
      const log = new ReceiptLog();
      return { port: await listen(createEgressProxy({ policy, log, allowPrivate: true, maxBodyBytes: 4 })), log };
    };
    const ok = await mk('abcd');
    expect((await viaProxy(ok.port, 'POST', `http://127.0.0.1:${o.port}/p`, 'abcd')).status).toBe(200);
    const over = await mk('abcde');
    const r = await viaProxy(over.port, 'POST', `http://127.0.0.1:${o.port}/p`, 'abcde');
    expect(r.status).toBe(413);
    expect(r.headers['content-type']).toBe('application/json');
    expect(JSON.parse(r.text)).toEqual({ error: 'egress_denied', reason: 'body_too_large' });
    expect(over.log.entries[0]).toMatchObject({ outcome: 'refused', reason: 'body_too_large' });
  });
  it('hop-by-hop headers are dropped in both directions, others pass', async () => {
    const o = await origin();
    const { port } = await setup({ port: o.port });
    const r = await viaProxy(port, 'GET', `http://127.0.0.1:${o.port}/v1/items`, undefined, { 'x-keep': 'yes', 'proxy-authorization': 'Basic c2VjcmV0', te: 'trailers' });
    expect(o.seen[0]!.headers['x-keep']).toBe('yes');
    expect(o.seen[0]!.headers['proxy-authorization']).toBeUndefined();
    expect(o.seen[0]!.headers.te).toBeUndefined();
    expect(o.seen[0]!.headers.host).toBe(`127.0.0.1:${o.port}`);
    expect(r.headers['x-origin']).toBe('1');
    expect(r.headers['proxy-authenticate']).toBeUndefined();
    // the origin's own value is dropped (the proxy's server may add its own keep-alive header on a persistent connection)
    expect(r.headers['keep-alive']).not.toBe('timeout=77');
  });
  it('an https admission is spoken over TLS to the upstream', async () => {
    const firstBytes: number[] = [];
    const raw = net.createServer((s) => { s.once('data', (d) => { firstBytes.push(d[0]!); s.destroy(); }); });
    const p = await listen(raw);
    const { port, log } = await setup({ scheme: 'https', port: p });
    await viaProxy(port, 'GET', `https://127.0.0.1:${p}/v1/items`);
    expect(firstBytes).toEqual([0x16]);
    expect(log.entries[0]).toMatchObject({ outcome: 'error' });
  });
  it('an upstream that never answers is cut at upstreamTimeoutMs and receipted', async () => {
    const hang = net.createServer(() => undefined);
    const p = await listen(hang);
    const { port, log } = await setup({ port: p }, { upstreamTimeoutMs: 150 });
    const r = await viaProxy(port, 'GET', `http://127.0.0.1:${p}/v1/items`);
    expect(r.status).toBe(502);
    expect(log.entries[0]).toMatchObject({ outcome: 'error', reason: 'upstream:timeout' });
  });
});

describe('egress proxy private-address guard', () => {
  it('a private IPv4 or bracketed IPv6 literal is refused with 502 and never contacted', async () => {
    for (const host of ['127.0.0.1', '::1']) {
      const hits: number[] = [];
      const s = net.createServer((c) => { hits.push(1); c.destroy(); });
      const p = await new Promise<number | null>((r) => {
        s.once('error', () => r(null));
        s.listen(0, host, () => { closers.push(() => s.close()); r((s.address() as AddressInfo).port); });
      });
      if (p === null) continue; // no IPv6 loopback on this machine
      const { port, log } = await setup({ host, port: p }, { allowPrivate: false });
      const url = host === '::1' ? `http://[::1]:${p}/v1/items` : `http://127.0.0.1:${p}/v1/items`;
      const r = await viaProxy(port, 'GET', url);
      expect(r.status, host).toBe(502);
      expect(r.text).toBe('');
      expect(hits).toEqual([]);
      expect(log.entries[0]).toMatchObject({ outcome: 'error', reason: 'upstream:EACCES' });
    }
  });
  it('a hostname that resolves to a private address is refused; to a public one it is not', async () => {
    const answers: Array<{ all: boolean; kind: 'array-private' | 'plain-private' | 'array-public' }> = [];
    let kind: 'array-private' | 'plain-private' | 'array-public' = 'array-private';
    const realLookup = dns.lookup;
    vi.spyOn(dns, 'lookup').mockImplementation(((_h: string, options: dns.LookupOptions | undefined, cb: (...a: unknown[]) => void) => {
      // IP literals (the test's own listeners go through lookup too) resolve for real
      if (net.isIP(_h)) return (realLookup as (...a: unknown[]) => void)(_h, options, cb);
      const all = options?.all === true;
      answers.push({ all, kind });
      const addr = kind === 'array-public' ? '93.184.216.34' : '127.0.0.1';
      if (kind === 'plain-private') cb(null, addr, 4);
      else if (all) cb(null, [{ address: addr, family: 4 }]);
      else cb(null, addr, 4);
    }) as never);
    const run = async (k: typeof kind, allowPrivate: boolean, up: number) => {
      kind = k;
      const { port, log } = await setup({ host: 'internal.example', port: up }, { allowPrivate, upstreamTimeoutMs: 300 });
      const r = await viaProxy(port, 'GET', `http://internal.example:${up}/v1/items`);
      return { r, entry: log.entries[0]! };
    };
    const o = await origin();
    for (const k of ['array-private', 'plain-private'] as const) {
      const { r, entry } = await run(k, false, o.port);
      expect(r.status, k).toBe(502);
      expect(entry.reason, k).toBe('upstream:EACCES');
    }
    expect(o.seen).toEqual([]);
    const pub = await run('array-public', false, o.port);
    expect(pub.entry.reason).not.toBe('upstream:EACCES');
    const allowed = await run('array-private', true, o.port);
    expect(allowed.r.status).toBe(200);
    expect(allowed.r.text).toBe('from-origin');
  });
});

describe('egress proxy CONNECT', () => {
  async function connectSetup(host: string, port: number, proxyOpts: Partial<Parameters<typeof createEgressProxy>[0]> = {}) {
    const f = authFixture(['api']);
    const policy = new EgressPolicy();
    policy.admit(await f.allow(get), get, () => ({ method: 'CONNECT', scheme: 'https', host, port, path: '/', tunnel: true }));
    const log = new ReceiptLog();
    const proxy = await listen(createEgressProxy({ policy, log, allowPrivate: true, ...proxyOpts }));
    return { proxy, log };
  }
  const rawConnect = (proxy: number, target: string, extra = ''): Promise<{ head: string; sock: net.Socket }> =>
    new Promise((resolve) => {
      const sock = net.connect(proxy, '127.0.0.1', () => sock.write(`CONNECT ${target} HTTP/1.1\r\nhost: ${target}\r\n\r\n${extra}`));
      sock.once('data', (d) => resolve({ head: d.toString(), sock }));
    });
  const readAll = (sock: net.Socket): Promise<string> => new Promise((r) => { const c: Buffer[] = []; sock.on('data', (d) => c.push(d)); sock.on('close', () => r(Buffer.concat(c).toString())); });

  it('a private literal target answers the exact 502 bytes, receipts EACCES and is never dialled', async () => {
    const hits: number[] = [];
    const echo = net.createServer((c) => { hits.push(1); c.destroy(); });
    const p = await listen(echo);
    const { proxy, log } = await connectSetup('127.0.0.1', p, { allowPrivate: false });
    const sock = net.connect(proxy, '127.0.0.1', () => sock.write(`CONNECT 127.0.0.1:${p} HTTP/1.1\r\nhost: x\r\n\r\n`));
    expect(await readAll(sock)).toBe('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n');
    expect(hits).toEqual([]);
    expect(log.entries[0]).toMatchObject({ outcome: 'error', reason: 'upstream:EACCES' });
  });
  it('an unreachable target answers the exact 502 bytes and receipts the error code', async () => {
    const dead = net.createServer();
    const p = await listen(dead);
    dead.close();
    const { proxy, log } = await connectSetup('127.0.0.1', p);
    const sock = net.connect(proxy, '127.0.0.1', () => sock.write(`CONNECT 127.0.0.1:${p} HTTP/1.1\r\nhost: x\r\n\r\n`));
    expect(await readAll(sock)).toBe('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n');
    expect(log.entries[0]).toMatchObject({ kind: 'egress', outcome: 'error', reason: 'upstream:ECONNREFUSED' });
  });
  it('bytes sent right behind the CONNECT headers reach the target, and a refusal is receipted as CONNECT host:port', async () => {
    const echo = net.createServer((s) => s.on('data', (d) => s.write(Buffer.concat([Buffer.from('echo:'), d]))));
    const p = await listen(echo);
    const { proxy, log } = await connectSetup('127.0.0.1', p);
    const ok = await rawConnect(proxy, `127.0.0.1:${p}`, 'HELLO');
    expect(ok.head.startsWith('HTTP/1.1 200 Connection Established')).toBe(true);
    const got = ok.head.includes('echo:HELLO') ? ok.head : await new Promise<string>((r) => ok.sock.once('data', (d) => r(d.toString())));
    expect(got).toContain('echo:HELLO');
    ok.sock.destroy();
    const denied = await rawConnect(proxy, '127.0.0.1:9');
    expect(denied.head.startsWith('HTTP/1.1 403')).toBe(true);
    denied.sock.destroy();
    await new Promise((r) => setTimeout(r, 20));
    const refusal = log.entries.find((e) => e.outcome === 'refused')!;
    expect(refusal.subject).toEqual({ op_id: '', verb: '', resource: 'CONNECT 127.0.0.1:9', params_digest: '' });
  });
  it('an idle tunnel is closed at the timeout and the failure is receipted', async () => {
    const idle = net.createServer(() => undefined);
    const p = await listen(idle);
    const { proxy, log } = await connectSetup('127.0.0.1', p, { upstreamTimeoutMs: 150 });
    const ok = await rawConnect(proxy, `127.0.0.1:${p}`);
    expect(ok.head.startsWith('HTTP/1.1 200')).toBe(true);
    await readAll(ok.sock);
    expect(log.entries.map((e) => [e.outcome, e.reason])).toEqual([['ok', 'tunnel'], ['error', 'upstream:error']]);
  });
  it('a client that resets the connection tears the upstream down', async () => {
    const closedUpstream = new Promise<void>((resolve) => {
      const echo = net.createServer((s) => { s.on('close', () => resolve()); s.on('error', () => undefined); });
      void listen(echo).then((p) => { (globalThis as { __p?: number }).__p = p; });
    });
    await new Promise((r) => setTimeout(r, 20));
    const p = (globalThis as { __p?: number }).__p!;
    const { proxy } = await connectSetup('127.0.0.1', p);
    const ok = await rawConnect(proxy, `127.0.0.1:${p}`);
    ok.sock.resetAndDestroy();
    await closedUpstream;
  });
});
