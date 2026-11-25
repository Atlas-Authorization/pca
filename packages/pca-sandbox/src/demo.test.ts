import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it } from 'vitest';
import { authFixture, claimFixture } from './test-auth';

import { EgressPolicy, ReceiptLog, buildTool, createEgressProxy, createSandbox as rawSandbox, verifyReceiptChain, USE_ERR } from './index';

const listen = (s: http.Server) => new Promise<number>((r) => s.listen(0, '127.0.0.1', () => r((s.address() as AddressInfo).port)));

describe('demo agent: a sandboxed tool cannot reach an unlisted host', () => {
  it('the tool fetches through its one handle; the executor leaves only through the admitting proxy; nothing else is reachable', async () => {
    const hits: string[] = [];
    const mkOrigin = (name: string) => http.createServer((req, res) => { hits.push(`${name}${req.url}`); res.end(name); });
    const listed = mkOrigin('listed');
    const unlisted = mkOrigin('unlisted');
    const [listedPort, unlistedPort] = [await listen(listed), await listen(unlisted)];

    const f = authFixture(['api']);
    const log = new ReceiptLog();
    const op = { verb: 'http.get', resource: 'api', params: { path: '/v1/items' } };
    const result = await f.allow(op);

    // one authorization feeds both the egress admission and the capability handle
    const policy = new EgressPolicy();
    policy.admit(result, op, () => ({ method: 'GET', scheme: 'http', host: '127.0.0.1', port: listedPort, path: '/v1/items' }));
    const proxy = createEgressProxy({ policy, log, allowPrivate: true });
    const proxyPort = await listen(proxy);

    // the executor is host code; its only route out is the proxy
    const viaProxy = (url: string) => new Promise<Uint8Array>((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: proxyPort, path: url }, (res) => {
        const c: Buffer[] = [];
        res.on('data', (d) => c.push(d));
        res.on('end', () => (res.statusCode === 200 ? resolve(Buffer.concat(c)) : reject(new Error(`status ${res.statusCode}`))));
      }).on('error', reject);
    });
    const sb = createSandbox({ log, executors: { 'http.get': (o) => viaProxy(`http://127.0.0.1:${listedPort}${(o.params as { path: string }).path}`) } });
    sb.table.mint(result, op);

    try {
      // the tool: invoke handle 1 and return the first byte of what came back ('l' of "listed")
      expect(await sb.runAsync(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 64 }], returns: 'byte0' }))).toEqual({ ok: true, value: 'l'.charCodeAt(0) });
      // asking for another handle (another host) finds nothing; the single-use handle is spent
      expect(await sb.runAsync(buildTool({ calls: [{ handle: 2, ptr: 0, cap: 64 }] }))).toEqual({ ok: true, value: USE_ERR.unknown_handle });
      expect(await sb.runAsync(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 64 }] }))).toEqual({ ok: true, value: USE_ERR.spent });
      // and the tool has no other import: it cannot even ask for a socket
      expect(await sb.runAsync(buildTool({ calls: [], extraImports: [{ module: 'wasi:sockets/tcp', name: 'connect' }] }))).toEqual({ ok: false, reason: 'ambient_import:wasi:sockets/tcp.connect' });
      // a non-WASM tool behind the same proxy asking for the unlisted host is refused
      await expect(viaProxy(`http://127.0.0.1:${unlistedPort}/v1/items`)).rejects.toThrow('status 403');
      expect(hits).toEqual(['listed/v1/items']);
      expect(verifyReceiptChain(log.entries)).toEqual({ ok: true });
      expect(log.entries.map((e) => `${e.kind}:${e.outcome}`)).toEqual(['egress:ok', 'handle_use:ok', 'handle_use:refused', 'handle_use:refused', 'egress:refused']);
    } finally {
      listed.close(); unlisted.close(); proxy.close();
    }
  });
});

function createSandbox(o: Parameters<typeof rawSandbox>[0]) {
  return rawSandbox({ runtimeClaim: claimFixture().runtimeClaim, ...o });
}
