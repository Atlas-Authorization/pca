import http from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { authFixture } from './test-auth';
import { EgressPolicy, ReceiptLog, createEgressProxy, isPrivateAddress, sha256b64u, verifyReceiptChain, type EgressTemplate } from './index';

const get = { verb: 'http.get', resource: 'api', params: { path: '/v1/items' } };
const tmpl = (over: Partial<EgressTemplate> = {}) => (): EgressTemplate => ({ method: 'GET', scheme: 'https', host: 'api.example.com', path: '/v1/items', ...over });

async function policyWith(t: () => EgressTemplate | null = tmpl(), opts: { uses?: number; expiresAt?: number } = {}, now?: () => number) {
  const f = authFixture(['api']);
  const p = new EgressPolicy(now);
  p.admit(await f.allow(get), get, t, opts);
  return { p, f };
}

describe('EgressPolicy: default deny, allow only what was admitted', () => {
  it('denies everything when nothing is admitted', () => {
    expect(new EgressPolicy().claim({ method: 'GET', url: 'https://api.example.com/v1/items' })).toEqual({ allow: false, reason: 'no_admission' });
  });

  it('allows exactly the admitted request, once', async () => {
    const { p } = await policyWith();
    expect(p.claim({ method: 'GET', url: 'https://api.example.com/v1/items' })).toMatchObject({ allow: true, admission: { verb: 'http.get', resource: 'api' } });
    expect(p.claim({ method: 'GET', url: 'https://api.example.com/v1/items' })).toEqual({ allow: false, reason: 'spent' });
  });

  it('each deviation is refused: host, port, scheme, method, path, query, userinfo, fragment, relative', async () => {
    const bad = [
      ['GET', 'https://evil.example.com/v1/items'],
      ['GET', 'https://api.example.com.evil.com/v1/items'],
      ['GET', 'https://api.example.com:8443/v1/items'],
      ['GET', 'http://api.example.com/v1/items'],
      ['POST', 'https://api.example.com/v1/items'],
      ['GET', 'https://api.example.com/v1/items/extra'],
      ['GET', 'https://api.example.com/v1/other'],
      ['GET', 'https://api.example.com/v1/items?x=1'],
      ['GET', 'https://user:pw@api.example.com/v1/items'],
      ['GET', 'https://api.example.com/v1/items#frag'],
      ['GET', '/v1/items'],
      ['GET', 'ftp://api.example.com/v1/items'],
      ['CONNECT', 'api.example.com:443'], // a tunnel was not admitted
    ] as const;
    for (const [method, url] of bad) {
      const { p } = await policyWith();
      expect(p.claim({ method, url }).allow, `${method} ${url}`).toBe(false);
    }
  });

  it('host and method case are normalized, an exact match still passes', async () => {
    const { p } = await policyWith();
    expect(p.claim({ method: 'get', url: 'https://API.Example.COM/v1/items' }).allow).toBe(true);
  });

  it('path prefix admits children only on a segment boundary and never encoded dot-walks', async () => {
    const mk = () => policyWith(tmpl({ path: '/v1/items', path_prefix: true }));
    expect((await mk()).p.claim({ method: 'GET', url: 'https://api.example.com/v1/items/9' }).allow).toBe(true);
    expect((await mk()).p.claim({ method: 'GET', url: 'https://api.example.com/v1/items' }).allow).toBe(true);
    expect((await mk()).p.claim({ method: 'GET', url: 'https://api.example.com/v1/itemsX' }).allow).toBe(false);
    expect((await mk()).p.claim({ method: 'GET', url: 'https://api.example.com/v1/items/%2e%2e/admin' }).allow).toBe(false); // parsed as /v1/admin
    expect((await mk()).p.claim({ method: 'GET', url: 'https://api.example.com/v1/items/..%2Fadmin' })).toEqual({ allow: false, reason: 'encoded_path' });
    expect((await mk()).p.claim({ method: 'GET', url: 'https://api.example.com/v1/items/../admin' }).allow).toBe(false); // the URL parser resolves it first
    expect((await mk()).p.claim({ method: 'GET', url: 'https://api.example.com/v1/items\\..\\admin' }).allow).toBe(false);
  });

  it('the query must equal the admitted one', async () => {
    const { p } = await policyWith(tmpl({ query: 'a=1' }));
    expect(p.claim({ method: 'GET', url: 'https://api.example.com/v1/items?a=2' })).toEqual({ allow: false, reason: 'query_mismatch' });
    expect(p.claim({ method: 'GET', url: 'https://api.example.com/v1/items?a=1' }).allow).toBe(true);
  });

  it('a body is allowed only with a matching body hash', async () => {
    const body = new TextEncoder().encode('{"amount":5}');
    const mk = () => policyWith(tmpl({ method: 'POST', body_sha256: sha256b64u(body) }));
    const u = 'https://api.example.com/v1/items';
    expect((await mk()).p.claim({ method: 'POST', url: u, body }).allow).toBe(true);
    expect((await mk()).p.claim({ method: 'POST', url: u, body: new TextEncoder().encode('{"amount":6}') })).toEqual({ allow: false, reason: 'body_mismatch' });
    expect((await mk()).p.claim({ method: 'POST', url: u })).toEqual({ allow: false, reason: 'body_mismatch' }); // template wants a body, none sent
    const nobody = await policyWith(tmpl({ method: 'POST' }));
    expect(nobody.p.claim({ method: 'POST', url: u, body })).toEqual({ allow: false, reason: 'body_mismatch' }); // body without a template hash
    expect(nobody.p.claim({ method: 'POST', url: u }).allow).toBe(true);
  });

  it('a tunnel admission matches CONNECT host:port only, and never a plain request', async () => {
    const { p } = await policyWith(tmpl({ tunnel: true, port: 443, method: 'CONNECT' }));
    expect(p.claim({ method: 'GET', url: 'https://api.example.com/v1/items' }).allow).toBe(false);
    expect(p.claim({ method: 'CONNECT', url: 'api.example.com:444' }).allow).toBe(false);
    expect(p.claim({ method: 'CONNECT', url: 'evil.com:443' }).allow).toBe(false);
    expect(p.claim({ method: 'CONNECT', url: 'not a target' })).toEqual({ allow: false, reason: 'bad_connect_target' });
    expect(p.claim({ method: 'CONNECT', url: 'API.example.com:443' }).allow).toBe(true);
  });

  it('uses and expiry', async () => {
    let now = 10;
    const { p } = await policyWith(tmpl(), { uses: 2, expiresAt: 20 }, () => now);
    expect(p.claim({ method: 'GET', url: 'https://api.example.com/v1/items' }).allow).toBe(true);
    now = 20;
    expect(p.claim({ method: 'GET', url: 'https://api.example.com/v1/items' })).toEqual({ allow: false, reason: 'spent' });
  });

  it('admit refuses an unauthorized operation, a null mapping and malformed templates', async () => {
    const f = authFixture(['api']);
    const ok = await f.allow(get);
    const p = new EgressPolicy();
    expect(() => p.admit(ok, { ...get, params: { path: '/other' } }, tmpl())).toThrow(/not_authorized/);
    expect(() => p.admit(ok, get, () => null)).toThrow('no_egress_for_operation');
    const bad: [Partial<EgressTemplate>, string][] = [
      [{ host: 'API.example.com' }, 'bad_template_host'],
      [{ host: 'a b' }, 'bad_template_host'],
      [{ host: '' }, 'bad_template_host'],
      [{ scheme: 'ftp' as never }, 'bad_template_scheme'],
      [{ port: 0 }, 'bad_template_port'],
      [{ port: 70000 }, 'bad_template_port'],
      [{ method: 'get' }, 'bad_template_method'],
      [{ path: 'v1' }, 'bad_template_path'],
      [{ path: '/a/../b' }, 'bad_template_path'],
      [{ path: '/a%2eb' }, 'bad_template_path'],
      [{ path: '/a?x' }, 'bad_template_path'],
      [{ path: '/a\\b' }, 'bad_template_path'],
    ];
    for (const [over, msg] of bad) expect(() => p.admit(ok, get, tmpl(over)), JSON.stringify(over)).toThrow(msg);
    expect(() => p.admit(ok, get, tmpl(), { uses: 0 })).toThrow('bad_uses');
    expect(() => p.admit(ok, get, tmpl({ host: '10.0.0.1' }))).not.toThrow();
  });

  it('a proof the verifier denied admits nothing', async () => {
    const f = authFixture(['api']);
    const denied = await f.allow(get, { ...get, params: { path: '/signed-for-something-else' } });
    expect(() => new EgressPolicy().admit(denied, get, tmpl())).toThrow(/not_authorized/);
  });
});

describe('isPrivateAddress', () => {
  it('flags private, loopback, link-local, CGNAT, multicast and mapped forms', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', '::', 'fd00::1', 'fe80::1', 'ff02::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1', 'garbage']) expect(isPrivateAddress(ip), ip).toBe(true);
    for (const ip of ['8.8.8.8', '172.32.0.1', '172.15.0.1', '100.63.0.1', '100.128.0.1', '2606:4700::1111', '::ffff:8.8.8.8', '169.253.0.1']) expect(isPrivateAddress(ip), ip).toBe(false);
  });
});

describe('createEgressProxy (real sockets on loopback)', () => {
  const closers: (() => void)[] = [];
  afterEach(() => { closers.splice(0).forEach((c) => c()); });

  const listen = (s: net.Server): Promise<number> => new Promise((r) => s.listen(0, '127.0.0.1', () => { closers.push(() => s.close()); r((s.address() as AddressInfo).port); }));

  async function origin() {
    const seen: { method: string; url: string; body: string }[] = [];
    const s = http.createServer((req, res) => {
      const c: Buffer[] = [];
      req.on('data', (d) => c.push(d));
      req.on('end', () => { seen.push({ method: req.method!, url: req.url!, body: Buffer.concat(c).toString() }); res.writeHead(200, { 'x-origin': '1' }).end('from-origin'); });
    });
    return { seen, port: await listen(s) };
  }

  function viaProxy(port: number, method: string, url: string, body?: string): Promise<{ status: number; text: string; headers: http.IncomingHttpHeaders }> {
    return new Promise((resolve, reject) => {
      const r = http.request({ host: '127.0.0.1', port, method, path: url, headers: { host: new URL(url).host } }, (res) => {
        const c: Buffer[] = [];
        res.on('data', (d) => c.push(d));
        res.on('end', () => resolve({ status: res.statusCode!, text: Buffer.concat(c).toString(), headers: res.headers }));
      });
      r.on('error', reject);
      r.end(body);
    });
  }

  const setup = async (originPort: number, over: Partial<EgressTemplate> = {}, proxyOpts: Partial<Parameters<typeof createEgressProxy>[0]> = {}) => {
    const f = authFixture(['api']);
    const policy = new EgressPolicy();
    policy.admit(await f.allow(get), get, () => ({ method: 'GET', scheme: 'http', host: '127.0.0.1', port: originPort, path: '/v1/items', ...over }));
    const log = new ReceiptLog({ now: () => 1 });
    const port = await listen(createEgressProxy({ policy, log, allowPrivate: true, ...proxyOpts }));
    return { port, log, policy };
  };

  it('forwards the admitted request once and receipts both outcomes; the origin never sees anything else', async () => {
    const o = await origin();
    const { port, log } = await setup(o.port);
    const ok = await viaProxy(port, 'GET', `http://127.0.0.1:${o.port}/v1/items`);
    expect(ok).toMatchObject({ status: 200, text: 'from-origin' });
    const again = await viaProxy(port, 'GET', `http://127.0.0.1:${o.port}/v1/items`);
    expect(again.status).toBe(403);
    expect(JSON.parse(again.text)).toEqual({ error: 'egress_denied', reason: 'spent' });
    const other = await viaProxy(port, 'GET', `http://127.0.0.1:${o.port}/admin`);
    expect(other.status).toBe(403);
    expect(o.seen).toEqual([{ method: 'GET', url: '/v1/items', body: '' }]);
    expect(log.entries.map((e) => [e.kind, e.outcome, e.reason])).toEqual([['egress', 'ok', 'status:200'], ['egress', 'refused', 'spent'], ['egress', 'refused', 'no_admission']].map((x) => x) );
    expect(log.entries[0]!.subject).toMatchObject({ verb: 'http.get', resource: 'api' });
    expect(log.entries[0]!.subject.params_digest).not.toBe('');
    expect(log.entries[0]!.runtime_class).toBe('egress_default_deny');
    expect(verifyReceiptChain(log.entries)).toEqual({ ok: true });
  });

  it('refuses a non-proxy (origin-form) request and a path-confusion attempt', async () => {
    const o = await origin();
    const { port, log } = await setup(o.port, { path_prefix: true });
    const r = await new Promise<number>((res) => http.get({ host: '127.0.0.1', port, path: '/v1/items' }, (x) => { x.resume(); res(x.statusCode!); }));
    expect(r).toBe(403);
    expect((await viaProxy(port, 'GET', `http://127.0.0.1:${o.port}/v1/items/%2e%2e/secret`)).status).toBe(403);
    expect(o.seen).toEqual([]);
    expect(log.entries.every((e) => e.outcome === 'refused')).toBe(true);
  });

  it('forwards a POST body that matches the admitted hash and refuses one that does not', async () => {
    const o = await origin();
    const body = '{"a":1}';
    const f = authFixture(['api']);
    const post = { verb: 'http.post', resource: 'api', params: { a: 1 } };
    const policy = new EgressPolicy();
    policy.admit(await f.allow(post), post, () => ({ method: 'POST', scheme: 'http', host: '127.0.0.1', port: o.port, path: '/p', body_sha256: sha256b64u(new TextEncoder().encode(body)) }));
    const port = await listen(createEgressProxy({ policy, log: new ReceiptLog(), allowPrivate: true }));
    expect((await viaProxy(port, 'POST', `http://127.0.0.1:${o.port}/p`, '{"a":2}')).status).toBe(403);
    expect((await viaProxy(port, 'POST', `http://127.0.0.1:${o.port}/p`, body)).status).toBe(200);
    expect(o.seen).toEqual([{ method: 'POST', url: '/p', body }]);
  });

  it('413s a body over the cap, before any admission is spent', async () => {
    const o = await origin();
    const { port, policy } = await setup(o.port, {}, { maxBodyBytes: 4 });
    expect((await viaProxy(port, 'POST', `http://127.0.0.1:${o.port}/v1/items`, 'x'.repeat(10))).status).toBe(413);
    expect(policy.claim({ method: 'GET', url: `http://127.0.0.1:${o.port}/v1/items` }).allow).toBe(true);
  });

  it('SSRF guard: with allowPrivate off, an admitted host that resolves to loopback is not reached', async () => {
    const o = await origin();
    const { port, log } = await setup(o.port, {}, { allowPrivate: false });
    const r = await viaProxy(port, 'GET', `http://127.0.0.1:${o.port}/v1/items`);
    expect(r.status).toBe(502);
    expect(o.seen).toEqual([]);
    expect(log.entries[0]).toMatchObject({ outcome: 'error', reason: 'upstream:EACCES' });
  });

  it('an upstream that is down is a receipted 502', async () => {
    const dead = net.createServer();
    const deadPort = await listen(dead);
    dead.close();
    const { port, log } = await setup(deadPort);
    expect((await viaProxy(port, 'GET', `http://127.0.0.1:${deadPort}/v1/items`)).status).toBe(502);
    expect(log.entries[0]).toMatchObject({ outcome: 'error', reason: 'upstream:ECONNREFUSED' });
  });

  it('CONNECT: tunnels only to an admitted host:port; the tunnel carries bytes', async () => {
    const echo = net.createServer((s) => s.on('data', (d) => s.write(Buffer.concat([Buffer.from('echo:'), d]))));
    const echoPort = await listen(echo);
    const f = authFixture(['api']);
    const policy = new EgressPolicy();
    policy.admit(await f.allow(get), get, () => ({ method: 'CONNECT', scheme: 'https', host: '127.0.0.1', port: echoPort, path: '/', tunnel: true }));
    const log = new ReceiptLog();
    const port = await listen(createEgressProxy({ policy, log, allowPrivate: true }));
    const connect = (target: string) => new Promise<{ status: number; sock: net.Socket }>((resolve) => {
      http.request({ host: '127.0.0.1', port, method: 'CONNECT', path: target }).on('connect', (res, sock) => resolve({ status: res.statusCode!, sock })).end();
    });
    const denied = await connect('127.0.0.1:9');
    expect(denied.status).toBe(403);
    denied.sock.destroy();
    const ok = await connect(`127.0.0.1:${echoPort}`);
    expect(ok.status).toBe(200);
    const got = await new Promise<string>((r) => { ok.sock.once('data', (d) => r(d.toString())); ok.sock.write('hi'); });
    expect(got).toBe('echo:hi');
    ok.sock.destroy();
    const again = await connect(`127.0.0.1:${echoPort}`);
    expect(again.status).toBe(403); // single use
    again.sock.destroy();
    expect(log.entries.map((e) => [e.outcome, e.reason])).toEqual([['refused', 'no_admission'], ['ok', 'tunnel'], ['refused', 'spent']]);
  });
});
