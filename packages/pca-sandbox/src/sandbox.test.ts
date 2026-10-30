import { describe, expect, it } from 'vitest';
import { generateKeyPair, sign as edSign, verify as edVerify, encodeSig, decodeSig } from '@atlasauth/pca';
import { authFixture, claimFixture } from './test-auth';

import { HandleTable, USE_ERR, createSandbox as rawSandbox, buildTool, buildProbeTool, ReceiptLog, verifyReceiptChain, satisfiesRuntimeClass, RUNTIME_CLASSES, type Executor } from './index';

const enc = (s: string) => new TextEncoder().encode(s);
const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };

describe('runtime classes', () => {
  it('orders the classes and refuses unknown names', () => {
    expect(RUNTIME_CLASSES).toEqual(['none', 'os_confined', 'egress_default_deny', 'wasi_no_ambient']);
    expect(satisfiesRuntimeClass('wasi_no_ambient', 'egress_default_deny')).toBe(true);
    expect(satisfiesRuntimeClass('egress_default_deny', 'wasi_no_ambient')).toBe(false);
    expect(satisfiesRuntimeClass('none', 'none')).toBe(true);
    expect(satisfiesRuntimeClass('wasi_no_ambient', 'bogus')).toBe(false);
    expect(satisfiesRuntimeClass('bogus', 'none')).toBe(false);
  });
});

describe('handle minting', () => {
  it('mints only for exactly the operation the verifier allowed', async () => {
    const f = authFixture(['notes']);
    const t = new HandleTable('wasi_no_ambient', new ReceiptLog(), {});
    const ok = await f.allow(op);
    expect(t.mint(ok, op)).toBe(1);
    expect(() => t.mint(ok, { ...op, params: { id: 'n-8' } })).toThrow(/not_authorized/);
    expect(() => t.mint(ok, { ...op, verb: 'fs.read' })).toThrow(/not_authorized/);
    expect(() => t.mint(ok, { ...op, resource: 'other' })).toThrow(/not_authorized/);
  });

  it('refuses a result the verifier denied (proof signed for other params)', async () => {
    const f = authFixture(['notes']);
    const denied = await f.allow(op, { ...op, params: { id: 'n-other' } });
    expect(denied.allow).toBe(false);
    expect(() => new HandleTable('wasi_no_ambient', new ReceiptLog(), {}).mint(denied, op)).toThrow(/not_authorized/);
  });

  it('refuses a table below the class the grant requires', async () => {
    const f = authFixture(['notes']);
    const ok = await f.allow(op);
    const weak = new HandleTable('os_confined', new ReceiptLog(), {});
    expect(() => weak.mint(ok, op, { requires: 'wasi_no_ambient' })).toThrow(/runtime_class_too_weak/);
    expect(weak.mint(ok, op, { requires: 'os_confined' })).toBe(1);
  });

  it('validates uses', async () => {
    const f = authFixture(['notes']);
    const ok = await f.allow(op);
    const t = new HandleTable('none', new ReceiptLog(), {});
    for (const uses of [0, -1, 1.5, 1e9]) expect(() => t.mint(ok, op, { uses })).toThrow('bad_uses');
  });
});

describe('handle use', () => {
  const setup = async (exec: Executor, uses = 1, now = () => 1000) => {
    const f = authFixture(['notes']);
    const log = new ReceiptLog({ now });
    const t = new HandleTable('wasi_no_ambient', log, { 'notes.read': exec }, now);
    const h = t.mint(await f.allow(op), op, { uses });
    return { t, h, log };
  };

  it('runs the executor on the signed params, once, and receipts it', async () => {
    const seen: unknown[] = [];
    const { t, h, log } = await setup((o) => (seen.push(o), enc('body')));
    expect(t.use(h)).toEqual({ ok: true, result: enc('body') });
    expect(seen).toEqual([op]);
    expect(t.use(h)).toEqual({ ok: false, reason: 'spent' });
    expect(log.entries.map((e) => [e.outcome, e.reason, e.kind])).toEqual([['ok', 'used', 'handle_use'], ['refused', 'spent', 'handle_use']]);
    expect(log.entries[0]!.subject).toMatchObject({ verb: 'notes.read', resource: 'notes' });
    expect(log.entries[0]!.runtime_class).toBe('wasi_no_ambient');
  });

  it('hands the executor a frozen copy: it cannot widen the handle by mutating', async () => {
    const { t, h } = await setup((o) => {
      expect(() => ((o.params as Record<string, unknown>).id = 'other')).toThrow();
      return enc('x');
    }, 2);
    expect(t.use(h).ok).toBe(true);
    expect(t.use(h).ok).toBe(true);
  });

  it('a failing executor still spends the use (no retry on the old authorization)', async () => {
    const { t, h, log } = await setup(() => { throw new Error('boom'); });
    expect(t.use(h)).toEqual({ ok: false, reason: 'executor_error' });
    expect(t.use(h)).toEqual({ ok: false, reason: 'spent' });
    expect(log.entries[0]).toMatchObject({ outcome: 'error', reason: 'executor_error' });
  });

  it('an executor that returns a non-byte value is an error, not a result', async () => {
    const { t, h } = await setup((() => 'text') as unknown as Executor);
    expect(t.use(h)).toEqual({ ok: false, reason: 'executor_error' });
  });

  it('refuses when no executor exists for the verb, and for an unknown handle (receipted)', async () => {
    const f = authFixture(['notes']);
    const log = new ReceiptLog();
    const t = new HandleTable('wasi_no_ambient', log, {});
    const h = t.mint(await f.allow(op), op);
    expect(t.use(h)).toEqual({ ok: false, reason: 'no_executor' });
    expect(t.use(0)).toEqual({ ok: false, reason: 'unknown_handle' });
    expect(t.use(99)).toEqual({ ok: false, reason: 'unknown_handle' });
    expect(log.entries.map((e) => e.reason)).toEqual(['no_executor', 'unknown_handle', 'unknown_handle']);
  });

  it('expires', async () => {
    let t0 = 1000;
    const f = authFixture(['notes']);
    const t = new HandleTable('none', new ReceiptLog(), { 'notes.read': () => enc('x') }, () => t0);
    const h = t.mint(await f.allow(op), op, { expiresAt: 2000 });
    t0 = 1999;
    expect(t.use(h).ok).toBe(true);
    const h2 = t.mint(await f.allow(op), op, { expiresAt: 2000 });
    t0 = 2000;
    expect(t.use(h2)).toEqual({ ok: false, reason: 'spent' });
  });
});

describe('monotone derivation and revoke-by-derivation', () => {
  it('a child takes uses from its parent and can never widen', async () => {
    const f = authFixture(['notes']);
    const t = new HandleTable('none', new ReceiptLog(), { 'notes.read': () => enc('x') }, () => 100);
    const p = t.mint(await f.allow(op), op, { uses: 3, expiresAt: 5000 });
    const c = t.attenuate(p, { uses: 2 });
    expect(() => t.attenuate(p, { uses: 2 })).toThrow('attenuate_widens'); // only 1 left in the parent
    expect(() => t.attenuate(c, { uses: 3 })).toThrow('attenuate_widens');
    expect(() => t.attenuate(c, { expiresAt: 6000 })).toThrow('attenuate_widens');
    expect(() => t.attenuate(c, { uses: 0 })).toThrow('attenuate_widens');
    expect(() => t.attenuate(77)).toThrow('unknown_handle');
    expect(t.use(c).ok && t.use(c).ok).toBe(true);
    expect(t.use(c).ok).toBe(false);
    expect(t.use(p).ok).toBe(true); // the parent kept its remaining use
  });

  it('revoking a parent revokes the whole subtree', async () => {
    const f = authFixture(['notes']);
    const t = new HandleTable('none', new ReceiptLog(), { 'notes.read': () => enc('x') });
    const p = t.mint(await f.allow(op), op, { uses: 4 });
    const c = t.attenuate(p, { uses: 2 });
    const gc = t.attenuate(c, { uses: 1 });
    t.revoke(p);
    for (const h of [p, c, gc]) expect(t.use(h)).toEqual({ ok: false, reason: 'spent' });
    t.revoke(p); // idempotent
    t.revoke(404); // unknown: no-op
  });
});

describe('receipt chain', () => {
  const build = () => {
    const kp = generateKeyPair();
    const log = new ReceiptLog({ now: () => 5, sign: (d) => encodeSig(edSign(kp.secretKey, enc(d))) });
    const body = { kind: 'handle_use' as const, subject: { op_id: 'a', verb: 'v', resource: 'r', params_digest: 'p' }, outcome: 'ok' as const, reason: 'used' };
    for (let i = 0; i < 3; i++) log.append('wasi_no_ambient', body);
    return { log, verifySig: (d: string, s: string) => edVerify(kp.publicKey, enc(d), decodeSig(s)) };
  };
  it('verifies, and fails on every tamper', () => {
    const { log, verifySig } = build();
    expect(verifyReceiptChain(log.entries, verifySig)).toEqual({ ok: true });
    expect(verifyReceiptChain([])).toEqual({ ok: true });
    const e = log.entries;
    expect(verifyReceiptChain([e[0]!, e[2]!])).toEqual({ ok: false, at: 1, reason: 'bad_seq' });
    expect(verifyReceiptChain([e[1]!, e[0]!, e[2]!])).toEqual({ ok: false, at: 0, reason: 'bad_seq' });
    expect(verifyReceiptChain([{ ...e[0]!, outcome: 'refused' }, e[1]!, e[2]!])).toEqual({ ok: false, at: 0, reason: 'bad_digest' });
    expect(verifyReceiptChain([e[0]!, { ...e[1]!, prev: 'genesis' }, e[2]!])).toEqual({ ok: false, at: 1, reason: 'broken_link' });
    expect(verifyReceiptChain([e[0]!, { ...e[1]!, sig: e[2]!.sig! }, e[2]!], verifySig)).toEqual({ ok: false, at: 1, reason: 'bad_sig' });
    const { sig: _s, ...unsigned } = e[0]!;
    expect(verifyReceiptChain([unsigned as never], verifySig)).toEqual({ ok: false, at: 0, reason: 'bad_sig' });
    expect(verifyReceiptChain([{ ...e[0]!, v: 2 as never }])).toEqual({ ok: false, at: 0, reason: 'bad_seq' });
  });
});

describe('WASM host: the only authority is the handles', () => {
  const mkSandbox = async (executors: Record<string, Executor>, extra: Parameters<typeof createSandbox>[0] = { executors }) => {
    const f = authFixture(['notes']);
    const sb = createSandbox({ ...extra, executors, now: () => 1 });
    return { sb, f, mint: async (uses = 1) => sb.table.mint(await f.allow(op), op, { uses }) };
  };

  it('the reference tool reads through its handle; the host wrote the result into guest memory', async () => {
    const { sb, mint } = await mkSandbox({ 'notes.read': () => Uint8Array.of(42, 1, 2) });
    await mint();
    const tool = buildTool({ calls: [{ handle: 1, ptr: 0, cap: 64 }], returns: 'byte0' });
    expect(sb.run(tool)).toEqual({ ok: true, value: 42 });
    expect(sb.log.entries).toHaveLength(1);
    expect(sb.log.entries[0]).toMatchObject({ outcome: 'ok', runtime_class: 'wasi_no_ambient' });
    expect(verifyReceiptChain(sb.log.entries)).toEqual({ ok: true });
  });

  it('returns the invoke code: length on success, negative codes on refusal', async () => {
    const { sb, mint } = await mkSandbox({ 'notes.read': () => Uint8Array.of(1, 2, 3) });
    await mint();
    const code = (calls: { handle: number; ptr: number; cap: number }[]) => sb.run(buildTool({ calls }));
    expect(code([{ handle: 1, ptr: 0, cap: 64 }])).toEqual({ ok: true, value: 3 });
    expect(code([{ handle: 1, ptr: 0, cap: 64 }])).toEqual({ ok: true, value: USE_ERR.spent }); // single use
    expect(code([{ handle: 9, ptr: 0, cap: 64 }])).toEqual({ ok: true, value: USE_ERR.unknown_handle });
    expect(code([{ handle: 1, ptr: 65530, cap: 64 }])).toEqual({ ok: true, value: USE_ERR.bad_memory }); // window outside memory: checked before spending
    expect(code([{ handle: -1, ptr: 0, cap: 64 }])).toEqual({ ok: true, value: USE_ERR.unknown_handle });
  });

  it('a result larger than the guest window is reported as out_too_small', async () => {
    const { sb, mint } = await mkSandbox({ 'notes.read': () => new Uint8Array(100) });
    await mint();
    expect(sb.run(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 10 }] }))).toEqual({ ok: true, value: USE_ERR.out_too_small });
  });

  it('a result above maxResultBytes is refused even if the window fits', async () => {
    const { sb, mint } = await mkSandbox({ 'notes.read': () => new Uint8Array(100) }, { executors: {}, maxResultBytes: 50 });
    await mint();
    expect(sb.run(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 200 }] }))).toEqual({ ok: true, value: USE_ERR.out_too_small });
  });

  it('refuses a tool that imports anything else (no wasi, no env), before it runs', async () => {
    const { sb, mint } = await mkSandbox({ 'notes.read': () => Uint8Array.of(1) });
    await mint();
    for (const imp of [{ module: 'wasi_snapshot_preview1', name: 'fd_write' }, { module: 'env', name: 'anything' }, { module: 'pca:act', name: 'shell' }]) {
      const r = sb.run(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 8 }], extraImports: [imp] }));
      expect(r).toEqual({ ok: false, reason: `ambient_import:${imp.module}.${imp.name}` });
    }
    expect(sb.log.entries).toHaveLength(0); // nothing ran, nothing was used
  });

  it('refuses memory without a declared maximum, above the cap, or shared/64-bit', async () => {
    const { sb } = await mkSandbox({});
    const lim = (memory: { min: number; max: number | null }) => sb.run(buildTool({ calls: [], memory }));
    expect(lim({ min: 1, max: null })).toEqual({ ok: false, reason: 'memory_limits' });
    expect(lim({ min: 1, max: 257 })).toEqual({ ok: false, reason: 'memory_limits' });
    expect(lim({ min: 300, max: 300 })).toEqual({ ok: false, reason: 'memory_limits' });
    expect(lim({ min: 1, max: 256 })).toEqual({ ok: true, value: 0 });
    const shared = buildTool({ calls: [] });
    const at = shared.indexOf(5); // memory section id; flag byte follows count (section id, size, count, flag)
    const patched = Uint8Array.from(shared);
    patched[at + 3] = 0x03; // shared with max
    expect(sb.run(patched)).toEqual({ ok: false, reason: 'memory_limits' });
    patched[at + 3] = 0x05; // 64-bit
    expect(sb.run(patched)).toEqual({ ok: false, reason: 'memory_limits' });
  });

  it('refuses malformed, empty and oversized modules and a missing entry', async () => {
    const { sb } = await mkSandbox({}, { executors: {}, maxModuleBytes: 200 });
    expect(sb.run(new Uint8Array(0))).toEqual({ ok: false, reason: 'module_size' });
    expect(sb.run(new Uint8Array(201))).toEqual({ ok: false, reason: 'module_size' });
    expect(sb.run(enc('not wasm at all'))).toEqual({ ok: false, reason: 'malformed_module' });
    expect(sb.run(Uint8Array.of(0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 5, 9))).toEqual({ ok: false, reason: 'malformed_module' }); // section overruns the file
    expect(sb.run(buildTool({ calls: [] }), 'nope')).toEqual({ ok: false, reason: 'no_entry' });
    const cut = buildTool({ calls: [] }).slice(0, 40);
    expect(sb.run(cut).ok).toBe(false);
  });

  it('a trap is contained and reported', async () => {
    const { sb } = await mkSandbox({});
    // unreachable body: replace `i32.const 0` (0x41 0x00) in run with `unreachable` (0x00 0x00)
    const t = Uint8Array.from(buildTool({ calls: [] }));
    const i = t.lastIndexOf(0x41);
    t[i] = 0x00;
    expect(sb.run(t)).toEqual({ ok: false, reason: 'trap:RuntimeError' });
  });

  it('two sandboxes are separate capability spaces', async () => {
    const a = await mkSandbox({ 'notes.read': () => Uint8Array.of(7) });
    const b = await mkSandbox({ 'notes.read': () => Uint8Array.of(7) });
    await a.mint();
    const tool = buildTool({ calls: [{ handle: 1, ptr: 0, cap: 8 }] });
    expect(b.sb.run(tool)).toEqual({ ok: true, value: USE_ERR.unknown_handle });
    expect(a.sb.run(tool)).toEqual({ ok: true, value: 1 });
  });

  it('revoking a handle before the tool runs makes the tool see it as spent', async () => {
    const { sb, mint } = await mkSandbox({ 'notes.read': () => Uint8Array.of(7) });
    const h = await mint(3);
    sb.table.revoke(h);
    expect(sb.run(buildTool({ calls: [{ handle: h, ptr: 0, cap: 8 }] }))).toEqual({ ok: true, value: USE_ERR.spent });
  });
});

describe('WASM host on a worker: async executors, timeout, same refusals', () => {
  const mk = async (executors: Record<string, Executor>, n = 1) => {
    const f = authFixture(['notes']);
    const sb = createSandbox({ executors, now: () => 1, maxResultBytes: 1024 });
    for (let i = 0; i < n; i++) sb.table.mint(await f.allow(op), op);
    return sb;
  };

  it('the tool sees the table (count and verb) and uses an asynchronous executor', async () => {
    const sb = await mk({ 'notes.read': async () => { await new Promise((r) => setTimeout(r, 20)); return Uint8Array.of(9, 9); } }, 2);
    expect(await sb.runAsync(buildProbeTool())).toEqual({ ok: true, value: 2 * 256 + 'n'.charCodeAt(0) });
    expect(sb.run(buildProbeTool())).toEqual({ ok: true, value: 2 * 256 + 'n'.charCodeAt(0) });
    expect(await sb.runAsync(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 64 }], returns: 'byte0' }))).toEqual({ ok: true, value: 9 });
    expect(sb.log.entries.map((e) => e.outcome)).toEqual(['ok']);
    expect(await sb.runAsync(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 64 }] }))).toEqual({ ok: true, value: USE_ERR.spent });
  });

  it('async refusals match the sync host: unknown handle, bad window (not spent), small window, oversize result, executor failure', async () => {
    const sb = await mk({ 'notes.read': async () => new Uint8Array(100) }, 3);
    const code = async (h: number, ptr: number, cap: number) => (await sb.runAsync(buildTool({ calls: [{ handle: h, ptr, cap }] })));
    expect(await code(9, 0, 8)).toEqual({ ok: true, value: USE_ERR.unknown_handle });
    expect(await code(1, 65530, 64)).toEqual({ ok: true, value: USE_ERR.bad_memory });
    expect(sb.log.entries).toHaveLength(1); // the unknown handle only; the bad window never reached the table
    expect(await code(1, 0, 10)).toEqual({ ok: true, value: USE_ERR.out_too_small });
    const big = createSandbox({ executors: { 'notes.read': async () => new Uint8Array(2000) }, maxResultBytes: 1024 });
    const f = authFixture(['notes']);
    big.table.mint(await f.allow(op), op);
    expect(await big.runAsync(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 4000 }] }))).toEqual({ ok: true, value: USE_ERR.out_too_small });
    const bad = createSandbox({ executors: { 'notes.read': async () => { throw new Error('x'); } } });
    bad.table.mint(await f.allow(op), op);
    expect(await bad.runAsync(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 8 }] }))).toEqual({ ok: true, value: USE_ERR.executor_error });
  });

  it('a sync use() of a promise-returning executor is an executor error, never a result', async () => {
    const sb = await mk({ 'notes.read': async () => Uint8Array.of(1) });
    expect(sb.table.use(1)).toEqual({ ok: false, reason: 'executor_error' });
    expect(sb.table.use(1)).toEqual({ ok: false, reason: 'spent' });
  });

  it('refuses ambient imports, traps and a missing entry without running', async () => {
    const sb = await mk({});
    expect(await sb.runAsync(buildTool({ calls: [], extraImports: [{ module: 'wasi_snapshot_preview1', name: 'fd_write' }] }))).toEqual({ ok: false, reason: 'ambient_import:wasi_snapshot_preview1.fd_write' });
    expect(await sb.runAsync(buildTool({ calls: [], memory: { min: 1, max: null } }))).toEqual({ ok: false, reason: 'memory_limits' });
    expect(await sb.runAsync(buildTool({ calls: [] }), 'nope')).toEqual({ ok: false, reason: 'no_entry' });
    const t = Uint8Array.from(buildTool({ calls: [] }));
    t[t.lastIndexOf(0x41)] = 0x00;
    expect(await sb.runAsync(t)).toEqual({ ok: false, reason: 'trap:RuntimeError' });
  });

  it('kills a tool that never returns at the timeout', async () => {
    const sb = await mk({});
    const t0 = Date.now();
    expect(await sb.runAsync(buildTool({ calls: [], spin: true }), 'run', 300)).toEqual({ ok: false, reason: 'timeout' });
    expect(Date.now() - t0).toBeLessThan(3000);
  });
});

function createSandbox(o: Parameters<typeof rawSandbox>[0]) {
  return rawSandbox({ runtimeClaim: claimFixture().runtimeClaim, ...o });
}
