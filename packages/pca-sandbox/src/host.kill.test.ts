import { describe, expect, it, vi } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';
import { authFixture, claimFixture } from './test-auth';
import { USE_ERR, buildProbeTool, buildTool, createSandbox, type Executor } from './index';
import type { RuntimeClass } from './index';

// Exact-outcome tests for the WebAssembly host: raw modules pin the pre-flight parser, the entry result and the trap report.
const u = (n: number): number[] => {
  const o: number[] = [];
  do {
    let b = n & 0x7f;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    o.push(b);
  } while (n > 0);
  return o;
};
const s = (x: string): number[] => [...u(x.length), ...new TextEncoder().encode(x)];
const sec = (id: number, body: number[]): number[] => [id, ...u(body.length), ...body];
const HDR = [0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];
const mod = (...parts: number[][]): Uint8Array => Uint8Array.from([...HDR, ...parts.flat()]);
const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };

const sandbox = (o: Partial<Parameters<typeof createSandbox>[0]> = {}) => createSandbox({ executors: {}, ...o });

describe('memory section pre-flight', () => {
  it('a header-only module is valid and has no entry; a magic byte off by one is malformed, whatever follows', () => {
    const sb = sandbox();
    expect(sb.run(Uint8Array.from(HDR))).toEqual({ ok: false, reason: 'no_entry' });
    const noMax = buildTool({ calls: [], memory: { min: 1, max: null } });
    expect(sb.run(noMax)).toEqual({ ok: false, reason: 'memory_limits' });
    for (let i = 0; i < 4; i++) {
      const p = Uint8Array.from(noMax);
      p[i] = p[i]! ^ 1;
      expect(sb.run(p), `magic byte ${i}`).toEqual({ ok: false, reason: 'malformed_module' });
    }
  });
  it('a memory section that ends exactly at the end of the file is read; one that overruns it is malformed', () => {
    const sb = sandbox();
    expect(sb.run(mod([5, 4, 1, 1, 1, 1]))).toEqual({ ok: false, reason: 'no_entry' });
    expect(sb.run(mod([5, 9, 1, 0, 1]))).toEqual({ ok: false, reason: 'malformed_module' });
  });
  it('an empty memory section declares no memory', () => {
    expect(sandbox().run(mod([5, 1, 0]))).toEqual({ ok: false, reason: 'no_entry' });
  });
  it('a LEB128 longer than five bytes, or cut off by the end of the file, is malformed', () => {
    const sb = sandbox();
    expect(sb.run(mod([5, 8, 0x81, 0x80, 0x80, 0x80, 0x80, 0x00, 0, 1]))).toEqual({ ok: false, reason: 'malformed_module' });
    expect(sb.run(mod([5, 2, 1, 0]))).toEqual({ ok: false, reason: 'malformed_module' });
  });
  it('a module with a well-formed section list but invalid contents is malformed', () => {
    expect(sandbox().run(mod([1, 2, 0xff, 0xff]))).toEqual({ ok: false, reason: 'malformed_module' });
  });
  it('a shared memory is cut off by its truncated limits (malformed), not mistaken for a refused memory', () => {
    expect(sandbox().run(mod([5, 2, 1, 3]))).toEqual({ ok: false, reason: 'malformed_module' });
    expect(sandbox().run(mod([5, 4, 1, 3, 1, 1]))).toEqual({ ok: false, reason: 'memory_limits' });
  });
  it('more than one memory is refused', () => {
    expect(sandbox().run(mod([5, 7, 2, 1, 1, 1, 1, 1, 1]))).toEqual({ ok: false, reason: 'memory_limits' });
  });
  it('a declared minimum above the cap is refused even when the maximum is within it', () => {
    expect(sandbox({ maxMemoryPages: 4 }).run(mod([5, 4, 1, 1, 5, 3]))).toEqual({ ok: false, reason: 'memory_limits' });
  });
});

describe('imports', () => {
  it('only pca:act functions are allowed: same name in another module, or a non-function import, is ambient', () => {
    const sb = sandbox();
    expect(sb.run(buildTool({ calls: [], extraImports: [{ module: 'env', name: 'invoke' }] }))).toEqual({ ok: false, reason: 'ambient_import:env.invoke' });
    expect(sb.run(mod(sec(2, [1, ...s('pca:act'), ...s('invoke'), 3, 0x7f, 0])))).toEqual({ ok: false, reason: 'ambient_import:pca:act.invoke' });
  });
});

describe('entry results and traps', () => {
  it('an entry that returns nothing reports value 0', () => {
    const t = mod(sec(1, [1, 0x60, 0, 0]), sec(3, [1, 0]), sec(7, [1, ...s('run'), 0, 0]), sec(10, [1, 2, 0, 0x0b]));
    expect(sandbox().run(t)).toEqual({ ok: true, value: 0 });
  });
  it('a thrown wasm exception that is not an Error is reported as trap:unknown', () => {
    const t = mod(sec(1, [1, 0x60, 0, 0]), sec(3, [1, 0]), sec(13, [1, 0, 0]), sec(7, [1, ...s('run'), 0, 0]), sec(10, [1, 4, 0, 8, 0, 0x0b]));
    expect(sandbox().run(t)).toEqual({ ok: false, reason: 'trap:unknown' });
  });
  it('a tool with two calls returns the last call code; an extra import shifts the entry index correctly', async () => {
    const f = authFixture(['notes']);
    const sb = sandbox({ executors: { 'notes.read': () => Uint8Array.of(1, 2, 3) } });
    sb.table.mint(await f.allow(op), op);
    expect(sb.run(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 8 }, { handle: 1, ptr: 0, cap: 8 }] }))).toEqual({ ok: true, value: USE_ERR.spent });
    expect(sb.run(buildTool({ calls: [], extraImports: [{ module: 'pca:act', name: 'handle_count' }] }))).toEqual({ ok: true, value: 0 });
  });
  it('a negative pointer is encoded as a negative constant (outside memory), not a small positive one', async () => {
    const f = authFixture(['notes']);
    const sb = sandbox({ executors: { 'notes.read': () => Uint8Array.of(1, 2, 3) } });
    sb.table.mint(await f.allow(op), op);
    expect(sb.run(buildTool({ calls: [{ handle: 1, ptr: -65, cap: 8 }] }))).toEqual({ ok: true, value: USE_ERR.bad_memory });
  });
  it('the memory section of a no-maximum memory carries the flag byte and the minimum', () => {
    const t = buildTool({ calls: [], memory: { min: 1, max: null } });
    const at = t.indexOf(5);
    expect([...t.slice(at, at + 5)]).toEqual([5, 3, 1, 0, 1]);
  });
});

describe('guest memory access', () => {
  const renamed = (kind: number | null): Uint8Array => {
    const t = Uint8Array.from(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 0 }] }));
    const name = [6, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79];
    const at = t.findIndex((_, i) => name.every((b, j) => t[i + j] === b));
    if (kind === null) t[at + 6] = 0x78; // export "memorx": no export called memory
    else t[at + 7] = kind; // export "memory" as a function: not a memory
    return t;
  };
  it.each([null, 0])('a module whose memory export is absent or not a memory has no memory: invoke reports bad_memory (%s)', async (kind) => {
    const f = authFixture(['notes']);
    const sb = sandbox({ executors: { 'notes.read': () => Uint8Array.of(1, 2, 3) } });
    sb.table.mint(await f.allow(op), op);
    expect(sb.run(renamed(kind))).toEqual({ ok: true, value: USE_ERR.bad_memory });
    expect(await sb.runAsync(renamed(kind))).toEqual({ ok: true, value: USE_ERR.bad_memory });
  });
  it('handle_verb with an unknown handle writes nothing; with a window outside memory it reports instead of trapping', async () => {
    const sb = sandbox();
    expect(sb.run(buildProbeTool())).toEqual({ ok: true, value: 0 }); // no handles: count 0, and nothing was written at byte 0
    const f = authFixture(['notes']);
    const sb2 = sandbox({ executors: { 'notes.read': () => Uint8Array.of(1) } });
    sb2.table.mint(await f.allow(op), op);
    expect(sb2.run(buildProbeTool(70_000))).toEqual({ ok: true, value: 256 });
  });
});

describe('runtime class of the table', () => {
  it('is none without a verified claim and the proven class otherwise', () => {
    expect(sandbox().table.runtimeClass).toBe('none');
    const unverified = claimFixture('wasi_no_ambient');
    expect(sandbox({ runtimeClaim: { claim: unverified.claim, trust: { ...unverified.trust, now: 99_999 } } }).table.runtimeClass).toBe('none');
    for (const cls of ['os_confined', 'egress_default_deny', 'wasi_no_ambient'] as RuntimeClass[]) {
      expect(sandbox({ runtimeClaim: claimFixture(cls).runtimeClaim }).table.runtimeClass, cls).toBe(cls);
    }
    expect(sandbox({ runtimeClaim: claimFixture('none').runtimeClaim }).table.runtimeClass).toBe('none');
  });
  it('receipts carry the host clock', async () => {
    const f = authFixture(['notes']);
    const sb = sandbox({ executors: { 'notes.read': () => Uint8Array.of(1) }, now: () => 777 });
    sb.table.mint(await f.allow(op), op);
    sb.run(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 8 }] }));
    expect(sb.log.entries[0]!.at).toBe(777);
  });
});

describe('runAsync', () => {
  const exec: Executor = () => Uint8Array.of(9, 8, 7, 6, 5, 4, 3, 2);
  it('a result exactly at maxResultBytes is delivered; one byte over is out_too_small', async () => {
    const f = authFixture(['notes']);
    const sb = sandbox({ executors: { 'notes.read': exec }, maxResultBytes: 8 });
    sb.table.mint(await f.allow(op), op);
    expect(await sb.runAsync(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 64 }] }))).toEqual({ ok: true, value: 8 });
    const over = sandbox({ executors: { 'notes.read': exec }, maxResultBytes: 7 });
    over.table.mint(await f.allow(op), op);
    expect(await over.runAsync(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 64 }] }))).toEqual({ ok: true, value: USE_ERR.out_too_small });
  });
  it('the timer is cleared once the run settles', async () => {
    const st = vi.spyOn(globalThis, 'setTimeout');
    const ct = vi.spyOn(globalThis, 'clearTimeout');
    try {
      expect(await sandbox().runAsync(buildTool({ calls: [] }), 'run', 4321)).toEqual({ ok: true, value: 0 });
      const i = st.mock.calls.findIndex((c) => c[1] === 4321);
      expect(i).toBeGreaterThanOrEqual(0);
      expect(ct).toHaveBeenCalledWith(st.mock.results[i]!.value);
    } finally {
      st.mockRestore();
      ct.mockRestore();
    }
  });
  it('a receipt for the handle use records the operation digest', async () => {
    const f = authFixture(['notes']);
    const sb = sandbox({ executors: { 'notes.read': exec } });
    sb.table.mint(await f.allow(op), op);
    await sb.runAsync(buildTool({ calls: [{ handle: 1, ptr: 0, cap: 64 }] }));
    expect(sb.log.entries[0]!.subject).toMatchObject({ verb: 'notes.read', resource: 'notes', params_digest: hashCanonical(op.params) });
  });
});
