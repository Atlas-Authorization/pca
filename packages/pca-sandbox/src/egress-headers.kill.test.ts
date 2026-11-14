import http from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { authFixture } from './test-auth';
import { EgressPolicy, ReceiptLog, createEgressProxy } from './index';

const get = { verb: 'http.get', resource: 'api', params: { path: '/v1/items' } };
const closers: (() => void)[] = [];
afterEach(() => closers.splice(0).forEach((c) => c()));
const listen = (s: net.Server): Promise<number> => new Promise((r) => s.listen(0, '127.0.0.1', () => { closers.push(() => s.close()); r((s.address() as AddressInfo).port); }));

describe('egress proxy: an upstream that stalls after it has sent its headers', () => {
  it('the client sees the status, then the connection is torn down; the stall is receipted as an upstream timeout', async () => {
    const origin = http.createServer((_req, res) => { res.writeHead(200, { 'content-length': '100' }); res.write('partial'); });
    origin.on('connection', (s) => closers.push(() => s.destroy()));
    const op = await listen(origin);
    const f = authFixture(['api']);
    const policy = new EgressPolicy();
    policy.admit(await f.allow(get), get, () => ({ method: 'GET', scheme: 'http', host: '127.0.0.1', port: op, path: '/v1/items' }));
    const log = new ReceiptLog({ now: () => 1 });
    const proxy = createEgressProxy({ policy, log, allowPrivate: true, upstreamTimeoutMs: 150 });
    const port = await listen(proxy);
    const outcome = await new Promise<{ status: number; ended: string }>((resolve) => {
      const r = http.request({ host: '127.0.0.1', port, method: 'GET', path: `http://127.0.0.1:${op}/v1/items`, headers: { host: `127.0.0.1:${op}` } }, (res) => {
        res.on('data', () => undefined);
        res.on('error', () => resolve({ status: res.statusCode!, ended: 'error' }));
        res.on('aborted', () => resolve({ status: res.statusCode!, ended: 'aborted' }));
        res.on('close', () => resolve({ status: res.statusCode!, ended: 'close' }));
      });
      r.on('error', () => undefined);
      r.end();
    });
    expect(outcome.status).toBe(200);
    await new Promise((r) => setTimeout(r, 30));
    expect(log.entries.map((e) => [e.kind, e.outcome, e.reason])).toEqual([['egress', 'error', 'upstream:timeout']]);
  });
});
