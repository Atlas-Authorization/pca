import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { authFixture, claimFixture } from './test-auth';
import { ReceiptLog, USE_ERR, createSandbox, runComponent } from './index';

// The protocol between runComponent and the host, against a scripted fake host (a node script): no Rust toolchain needed, so these
// run everywhere, including under mutation testing.
const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pca-fakehost-'));
function fakeHost(script: string): string {
  const f = path.join(dir, `h${Math.random().toString(36).slice(2)}.js`);
  fs.writeFileSync(f, `#!/usr/bin/env node\nconst rl = require('readline').createInterface({ input: process.stdin });\nconst q = []; let w = null;\nrl.on('line', (l) => { if (w) { const f = w; w = null; f(JSON.parse(l)); } else q.push(JSON.parse(l)); });\nconst next = () => new Promise((r) => (q.length ? r(q.shift()) : (w = r)));\nconst send = (o) => process.stdout.write(JSON.stringify(o) + '\\n');\n(async () => {\n${script}\n})();\n`);
  fs.chmodSync(f, 0o755);
  return f;
}
async function setup(uses = 1) {
  const f = authFixture(['notes']);
  const sb = createSandbox({ executors: { 'notes.read': async () => Uint8Array.of(7, 8, 9) }, runtimeClaim: claimFixture().runtimeClaim, log: new ReceiptLog({ now: () => 1 }) });
  sb.table.mint(await f.allow(op), op, { uses });
  return sb;
}

describe('runComponent protocol (fake host)', () => {
  it('answers count, verb and invoke from the table and returns done with the fuel used', async () => {
    const sb = await setup();
    const host = fakeHost(`send({op:'count'}); const c = await next(); send({op:'verb',h:1}); const v = await next(); send({op:'invoke',h:1}); const r = await next();
      send({done: c.n * 1000 + v.ok.length * 100 + r.ok.length, fuel_used: 55});`);
    expect(await runComponent(sb.table, 'x', { fuel: 10, host })).toEqual({ ok: true, value: 1000 + 1000 + 3 - 0, fuelUsed: 55 } as never);
  });
  it('an unknown handle and a spent handle are error codes, a refused verb is unknown_handle', async () => {
    const sb = await setup();
    const host = fakeHost(`send({op:'invoke',h:5}); const a = await next(); send({op:'verb',h:5}); const b = await next(); send({op:'invoke',h:1}); await next(); send({op:'invoke',h:1}); const c = await next(); send({done: (a.err === ${USE_ERR.unknown_handle} && b.err === ${USE_ERR.unknown_handle} && c.err === ${USE_ERR.spent}) ? 1 : 0});`);
    expect(await runComponent(sb.table, 'x', { fuel: 10, host })).toEqual({ ok: true, value: 1 });
  });
  it('a result over the cap is out_too_small', async () => {
    const sb = await setup();
    const host = fakeHost(`send({op:'invoke',h:1}); const r = await next(); send({done: r.err});`);
    expect(await runComponent(sb.table, 'x', { fuel: 10, host, maxResultBytes: 2 })).toEqual({ ok: true, value: USE_ERR.out_too_small });
    const sb2 = await setup();
    expect(await runComponent(sb2.table, 'x', { fuel: 10, host: fakeHost(`send({op:'invoke',h:1}); const r = await next(); send({done: r.ok.length});`), maxResultBytes: 3 })).toEqual({ ok: true, value: 3 });
  });
  it('a host failure is passed through as the reason', async () => {
    const sb = await setup();
    expect(await runComponent(sb.table, 'x', { fuel: 10, host: fakeHost(`send({fail:'fuel_exhausted'});`) })).toEqual({ ok: false, reason: 'fuel_exhausted' });
  });
  it('garbage, an unknown op and a host that exits silently are refusals', async () => {
    const sb = await setup();
    expect(await runComponent(sb.table, 'x', { fuel: 10, host: fakeHost(`process.stdout.write('not json\\n');`) })).toEqual({ ok: false, reason: 'host_protocol' });
    expect(await runComponent(sb.table, 'x', { fuel: 10, host: fakeHost(`send({op:'shell'});`) })).toEqual({ ok: false, reason: 'host_protocol' });
    expect(await runComponent(sb.table, 'x', { fuel: 10, host: fakeHost(`process.exit(0);`) })).toEqual({ ok: false, reason: 'host_exit' });
  });
  it('a host that never answers is killed at the timeout', async () => {
    const sb = await setup();
    expect(await runComponent(sb.table, 'x', { fuel: 10, host: fakeHost(`await new Promise(() => {});`), timeoutMs: 200 })).toEqual({ ok: false, reason: 'timeout' });
  });
  it('bad fuel is refused without starting the host', async () => {
    const sb = await setup();
    for (const fuel of [0, -5, 2.5, Number.MAX_SAFE_INTEGER + 1]) expect(await runComponent(sb.table, 'x', { fuel, host: '/nonexistent' })).toEqual({ ok: false, reason: 'bad_fuel' });
    expect(await runComponent(sb.table, 'x', { fuel: 1, host: '/nonexistent' })).toEqual({ ok: false, reason: 'host_unavailable' });
  });
  it('the temporary component file is removed', async () => {
    const sb = await setup();
    const before = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('pca-comp-')).length;
    await runComponent(sb.table, 'x', { fuel: 10, host: fakeHost(`send({done: 0});`) });
    expect(fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('pca-comp-')).length).toBe(before);
  });
});
