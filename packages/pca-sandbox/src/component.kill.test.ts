import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { authFixture } from './test-auth';
import { HandleTable, ReceiptLog, defaultHostBinary, runComponent } from './index';

// A scripted stand-in for the wasmtime host (a small node program speaking the same line protocol), so the protocol,
// the failure reasons and the cleanup are pinned without a Rust toolchain.
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'pca-comp-kill-'));
afterAll(() => fs.rmSync(scratch, { recursive: true, force: true }));
let n = 0;
const fakeHost = (body: string): string => {
  const file = path.join(scratch, `host-${n++}.js`);
  fs.writeFileSync(file, `#!${process.execPath}\nconst out = (o) => process.stdout.write(JSON.stringify(o) + '\\n');\n${body}\n`, { mode: 0o755 });
  return file;
};
// sends each request in turn, waits for the reply, and finally reports every reply as the failure reason
const conversation = (requests: unknown[]): string => `
const replies = []; const reqs = ${JSON.stringify(requests)}; let i = 0;
const next = () => (i < reqs.length ? out(reqs[i++]) : out({ fail: JSON.stringify(replies) }));
require('node:readline').createInterface({ input: process.stdin }).on('line', (l) => { replies.push(JSON.parse(l)); next(); });
next();`;

const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };
const tableWith = async (exec: () => Uint8Array, uses = 1) => {
  const f = authFixture(['notes']);
  const t = new HandleTable('wasi_no_ambient', new ReceiptLog(), { 'notes.read': exec });
  t.mint(await f.allow(op), op, { uses });
  return t;
};
const empty = () => new HandleTable('none', new ReceiptLog(), {});

describe('defaultHostBinary', () => {
  it('is the environment override when set, else the built release binary', () => {
    const prev = process.env.PCA_WASMTIME_HOST;
    try {
      process.env.PCA_WASMTIME_HOST = '/opt/custom-host';
      expect(defaultHostBinary()).toBe('/opt/custom-host');
      delete process.env.PCA_WASMTIME_HOST;
      expect(defaultHostBinary().endsWith(path.join('wasmtime-host', 'target', 'release', 'pca-wasmtime-host'))).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.PCA_WASMTIME_HOST;
      else process.env.PCA_WASMTIME_HOST = prev;
    }
  });
});

describe('runComponent against a scripted host', () => {
  it('refuses a budget that is not a positive safe integer before starting anything', async () => {
    for (const fuel of [0, -1, 1.5, Number.NaN, 2 ** 53]) expect(await runComponent(empty(), 'x', { fuel, host: '/nonexistent/host' }), String(fuel)).toEqual({ ok: false, reason: 'bad_fuel' });
    expect(await runComponent(empty(), 'x', { fuel: 1, host: '/nonexistent/host' })).toEqual({ ok: false, reason: 'host_unavailable' });
  });

  it('hands the host the component file and the fuel, and removes the temp directory afterwards', async () => {
    const host = fakeHost(`out({ fail: [process.argv[2], process.argv[3], require('node:fs').readFileSync(process.argv[2], 'utf8')].join('|') });`);
    const r = await runComponent(empty(), '(component)', { fuel: 500, host });
    expect(r.ok).toBe(false);
    const [file, fuel, content] = (r as { reason: string }).reason.split('|') as [string, string, string];
    expect([path.basename(file), fuel, content]).toEqual(['tool.component', '500', '(component)']);
    expect(path.basename(path.dirname(file)).startsWith('pca-comp-')).toBe(true);
    expect(fs.existsSync(path.dirname(file))).toBe(false);
  });

  it('reports done with the value, and the fuel used only when the host says so', async () => {
    expect(await runComponent(empty(), 'x', { fuel: 1, host: fakeHost(`out({ done: 7, fuel_used: 3 });`) })).toStrictEqual({ ok: true, value: 7, fuelUsed: 3 });
    expect(await runComponent(empty(), 'x', { fuel: 1, host: fakeHost(`out({ done: 7 });`) })).toStrictEqual({ ok: true, value: 7 });
    expect(await runComponent(empty(), 'x', { fuel: 1, host: fakeHost(`out({ fail: 'fuel_exhausted' });`) })).toEqual({ ok: false, reason: 'fuel_exhausted' });
  });

  it('answers count, verb and invoke requests in order from the table', async () => {
    const host = fakeHost(conversation([{ op: 'count' }, { op: 'verb', h: 1 }, { op: 'verb', h: 99 }, { op: 'verb', h: 1.5 }, { op: 'invoke', h: 1 }, { op: 'invoke', h: 1 }]));
    const r = await runComponent(await tableWith(() => Uint8Array.of(42, 1, 2)), 'x', { fuel: 1, host });
    expect(JSON.parse((r as { reason: string }).reason)).toEqual([{ n: 1 }, { ok: 'notes.read' }, { err: -1 }, { err: -1 }, { ok: [42, 1, 2] }, { err: -2 }]);
  });

  it('a result above maxResultBytes is out_too_small; one at the limit is delivered', async () => {
    const host = fakeHost(conversation([{ op: 'invoke', h: 1 }]));
    const over = await runComponent(await tableWith(() => Uint8Array.of(1, 2, 3)), 'x', { fuel: 1, host, maxResultBytes: 2 });
    expect(JSON.parse((over as { reason: string }).reason)).toEqual([{ err: -3 }]);
    const at = await runComponent(await tableWith(() => Uint8Array.of(1, 2, 3)), 'x', { fuel: 1, host, maxResultBytes: 3 });
    expect(JSON.parse((at as { reason: string }).reason)).toEqual([{ ok: [1, 2, 3] }]);
  });

  it('a line that is not JSON, or an unknown request, is a protocol failure', async () => {
    expect(await runComponent(empty(), 'x', { fuel: 1, host: fakeHost(`process.stdout.write('not json\\n');`) })).toEqual({ ok: false, reason: 'host_protocol' });
    expect(await runComponent(empty(), 'x', { fuel: 1, host: fakeHost(`out({ op: 'shell' });`) })).toEqual({ ok: false, reason: 'host_protocol' });
    expect(await runComponent(empty(), 'x', { fuel: 1, host: fakeHost(`out({ done: '7' });`) })).toEqual({ ok: false, reason: 'host_protocol' });
  });

  it('a host that exits silently is host_exit; one that never answers is cut at the timeout', async () => {
    expect(await runComponent(empty(), 'x', { fuel: 1, host: fakeHost(`process.exit(0);`) })).toEqual({ ok: false, reason: 'host_exit' });
    expect(await runComponent(empty(), 'x', { fuel: 1, host: fakeHost(`setTimeout(() => undefined, 60000);`), timeoutMs: 100 })).toEqual({ ok: false, reason: 'timeout' });
  });

  it('a chatty stderr does not stall the host (it is not piped back)', async () => {
    const host = fakeHost(`process.stderr.write('x'.repeat(1 << 21)); out({ done: 1 });`);
    expect(await runComponent(empty(), 'x', { fuel: 1, host, timeoutMs: 8000 })).toEqual({ ok: true, value: 1 });
  });

  it('cleanup tolerates the directory already being gone', async () => {
    const host = fakeHost(`require('node:fs').rmSync(require('node:path').dirname(process.argv[2]), { recursive: true, force: true }); out({ done: 2 });`);
    expect(await runComponent(empty(), 'x', { fuel: 1, host })).toEqual({ ok: true, value: 2 });
  });

  it('the timeout timer is cleared once the run settles', async () => {
    const st = vi.spyOn(globalThis, 'setTimeout');
    const ct = vi.spyOn(globalThis, 'clearTimeout');
    try {
      expect(await runComponent(empty(), 'x', { fuel: 1, host: fakeHost(`out({ done: 1 });`), timeoutMs: 4321 })).toEqual({ ok: true, value: 1 });
      const i = st.mock.calls.findIndex((c) => c[1] === 4321);
      expect(i).toBeGreaterThanOrEqual(0);
      expect(ct).toHaveBeenCalledWith(st.mock.results[i]!.value);
    } finally {
      st.mockRestore();
      ct.mockRestore();
    }
  });
});
