import { Worker } from 'node:worker_threads';
import { HandleTable, USE_ERR, type Executor } from './handles';
import { ReceiptLog, type RuntimeClass } from './receipts';
import { verifiedRuntimeClass, type ClaimTrust } from './runtime-claim';

/** The only import module a sandboxed tool may name, and the only functions in it. Anything else is ambient authority. */
export const IMPORT_MODULE = 'pca:act';
export const ALLOWED_IMPORTS = ['invoke', 'handle_count', 'handle_verb'] as const;

export interface SandboxOptions {
  executors: Readonly<Record<string, Executor>>;
  log?: ReceiptLog;
  now?: () => number;
  /** Largest tool binary accepted. Default 1 MiB. */
  maxModuleBytes?: number;
  /** Largest linear memory a tool may declare (64 KiB pages). Default 256 (16 MiB). A memory without a declared maximum is refused. */
  maxMemoryPages?: number;
  /** Largest result one handle use may return to the tool. Default 1 MiB. */
  maxResultBytes?: number;
  /** Evidence for the runtime class. Without a claim that verifies, the table is class `none`: an operator's say-so does not count. */
  runtimeClaim?: { claim: unknown; trust: ClaimTrust };
}

export type RunResult = { ok: true; value: number } | { ok: false; reason: string };

/**
 * A WebAssembly host whose only authority is the handles minted into `table`. The tool is a core module that imports
 * nothing but `pca:act.{invoke,handle_count,handle_verb}` (a lowering of the WIT in `wit/pca-act.wit`: a component built
 * for that world has no other import, so it has no filesystem, network, clock, random or environment access). Any other
 * import, a memory with no declared maximum, or a shared/64-bit memory is refused before anything runs.
 *
 * `run` is synchronous and in-thread (synchronous executors only, no time limit). `runAsync` runs the tool on a worker:
 * executors may be asynchronous and a tool that never returns is killed at the timeout.
 * shortcut: the limit is wall-clock, not instructions; use a fuel-metered engine when a tool must be bounded by work done.
 */
export function createSandbox(opts: SandboxOptions) {
  const log = opts.log ?? new ReceiptLog({ ...(opts.now ? { now: opts.now } : {}) });
  // a WASM host cannot prove more than wasi_no_ambient, so a stronger claim is capped there
  const proven = opts.runtimeClaim ? verifiedRuntimeClass(opts.runtimeClaim.claim, opts.runtimeClaim.trust) : 'none';
  const tableClass: RuntimeClass = proven === 'wasi_no_ambient' || proven === 'egress_default_deny' || proven === 'os_confined' ? proven : 'none';
  const table = new HandleTable(tableClass, log, opts.executors, opts.now);
  const maxModuleBytes = opts.maxModuleBytes ?? 1 << 20;
  const maxPages = opts.maxMemoryPages ?? 256;
  const maxResult = opts.maxResultBytes ?? 1 << 20;

  /** Everything that can be decided before a single instruction runs. */
  function validate(bytes: Uint8Array): { ok: true; module: WebAssembly.Module } | { ok: false; reason: string } {
    if (bytes.length === 0 || bytes.length > maxModuleBytes) return { ok: false, reason: 'module_size' };
    const mem = memoryLimits(bytes);
    if (mem === 'bad') return { ok: false, reason: 'malformed_module' };
    if (mem && (mem.count > 1 || mem.max === null || mem.shared || mem.min > maxPages || mem.max > maxPages)) return { ok: false, reason: 'memory_limits' };
    let module: WebAssembly.Module;
    try {
      module = new WebAssembly.Module(bytes as BufferSource);
    } catch {
      return { ok: false, reason: 'malformed_module' };
    }
    for (const i of WebAssembly.Module.imports(module)) {
      if (i.module !== IMPORT_MODULE || i.kind !== 'function' || !(ALLOWED_IMPORTS as readonly string[]).includes(i.name)) return { ok: false, reason: `ambient_import:${i.module}.${i.name}` };
    }
    return { ok: true, module };
  }

  function run(bytes: Uint8Array, entry = 'run'): RunResult {
    const v = validate(bytes);
    if (!v.ok) return v;
    const module = v.module;
    let memory: WebAssembly.Memory | undefined;
    const view = (ptr: number, len: number): Uint8Array | null => {
      if (!memory) return null;
      const b = new Uint8Array(memory.buffer);
      const p = ptr >>> 0;
      const l = len >>> 0;
      return p + l <= b.length ? b.subarray(p, p + l) : null;
    };
    const imports = {
      [IMPORT_MODULE]: {
        handle_count: () => table.size,
        handle_verb: (h: number, ptr: number, cap: number) => {
          const verb = table.verbOf(h);
          if (verb === null) return USE_ERR.unknown_handle;
          const enc = new TextEncoder().encode(verb);
          const out = view(ptr, cap);
          if (!out) return USE_ERR.bad_memory;
          if (enc.length > out.length) return USE_ERR.out_too_small;
          out.set(enc);
          return enc.length;
        },
        invoke: (h: number, ptr: number, cap: number) => {
          // validate the guest's output window before spending the use
          if (!view(ptr, cap)) return USE_ERR.bad_memory;
          const r = table.use(h);
          if (!r.ok) return USE_ERR[r.reason];
          if (r.result.length > maxResult || r.result.length > (cap >>> 0)) return USE_ERR.out_too_small;
          view(ptr, cap)!.set(r.result);
          return r.result.length;
        },
      },
    };
    try {
      const instance = new WebAssembly.Instance(module, imports);
      const m = instance.exports.memory;
      if (m instanceof WebAssembly.Memory) memory = m;
      const fn = instance.exports[entry];
      if (typeof fn !== 'function') return { ok: false, reason: 'no_entry' };
      const value = (fn as () => unknown)();
      return typeof value === 'number' ? { ok: true, value } : { ok: true, value: 0 };
    } catch (e) {
      return { ok: false, reason: `trap:${e instanceof Error ? e.constructor.name : 'unknown'}` };
    }
  }

  /**
   * Run the tool on a worker thread so handles can use asynchronous executors (the guest blocks on a shared buffer while the
   * host awaits the executor) and so a tool that never returns is killed at `timeoutMs`. Validation is identical to `run`.
   */
  function runAsync(bytes: Uint8Array, entry = 'run', timeoutMs = 5000): Promise<RunResult> {
    const v = validate(bytes);
    if (!v.ok) return Promise.resolve(v);
    const ctl = new SharedArrayBuffer(8);
    const data = new SharedArrayBuffer(maxResult);
    const c = new Int32Array(ctl);
    const d = new Uint8Array(data);
    const verbs = Array.from({ length: table.size }, (_, i) => table.verbOf(i + 1) ?? '');
    return new Promise((resolve) => {
      const w = new Worker(WORKER_SOURCE, { eval: true, workerData: { bytes, entry, verbs, ctl, data } });
      let settled = false;
      const done = (r: RunResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        void w.terminate();
        resolve(r);
      };
      const timer = setTimeout(() => done({ ok: false, reason: 'timeout' }), timeoutMs);
      w.on('message', (m: { t: string; h?: number; value?: number; reason?: string }) => {
        if (m.t === 'done') return done({ ok: true, value: m.value ?? 0 });
        if (m.t === 'fail') return done({ ok: false, reason: m.reason ?? 'trap' });
        void table.useAsync(m.h ?? 0).then((r) => {
          let n: number = r.ok ? r.result.length : USE_ERR[r.reason];
          if (r.ok) {
            if (r.result.length > maxResult) n = USE_ERR.out_too_small;
            else d.set(r.result);
          }
          Atomics.store(c, 1, n);
          Atomics.store(c, 0, 1);
          Atomics.notify(c, 0);
        });
      });
      w.on('error', () => done({ ok: false, reason: 'worker_error' }));
      w.on('exit', () => done({ ok: false, reason: 'worker_exit' }));
    });
  }

  return { table, log, run, runAsync };
}

/**
 * The worker body: the same imports as `run`, with `invoke` bridged to the host over a shared buffer. It owns no authority
 * either: the host's table decides every use, and the bounds of the guest's output window are checked here before the host
 * is asked (so a bad window never spends a use).
 */
const WORKER_SOURCE = `
const { workerData, parentPort } = require('node:worker_threads');
const { bytes, entry, verbs, ctl, data } = workerData;
const c = new Int32Array(ctl);
const d = new Uint8Array(data);
let memory;
const view = (ptr, len) => { if (!memory) return null; const b = new Uint8Array(memory.buffer); const p = ptr >>> 0, l = len >>> 0; return p + l <= b.length ? b.subarray(p, p + l) : null; };
const imports = { 'pca:act': {
  handle_count: () => verbs.length,
  handle_verb: (h, ptr, cap) => { const v = verbs[h - 1]; if (v === undefined) return ${USE_ERR.unknown_handle}; const e = new TextEncoder().encode(v); const o = view(ptr, cap); if (!o) return ${USE_ERR.bad_memory}; if (e.length > o.length) return ${USE_ERR.out_too_small}; o.set(e); return e.length; },
  invoke: (h, ptr, cap) => {
    const o = view(ptr, cap); if (!o) return ${USE_ERR.bad_memory};
    Atomics.store(c, 0, 0); parentPort.postMessage({ t: 'invoke', h }); Atomics.wait(c, 0, 0);
    const n = c[1]; if (n < 0) return n; if (n > o.length) return ${USE_ERR.out_too_small};
    o.set(d.subarray(0, n)); return n;
  },
} };
try {
  const inst = new WebAssembly.Instance(new WebAssembly.Module(bytes), imports);
  if (inst.exports.memory instanceof WebAssembly.Memory) memory = inst.exports.memory;
  const fn = inst.exports[entry];
  if (typeof fn !== 'function') parentPort.postMessage({ t: 'fail', reason: 'no_entry' });
  else { const v = fn(); parentPort.postMessage({ t: 'done', value: typeof v === 'number' ? v : 0 }); }
} catch (e) { parentPort.postMessage({ t: 'fail', reason: 'trap:' + (e && e.constructor ? e.constructor.name : 'unknown') }); }
`;

/** Parse only the memory section: count and the first memory's limits. `null` = no memory section, 'bad' = unparseable. */
function memoryLimits(b: Uint8Array): { count: number; min: number; max: number | null; shared: boolean } | null | 'bad' {
  let o = 8;
  if (b.length < 8 || b[0] !== 0 || b[1] !== 0x61 || b[2] !== 0x73 || b[3] !== 0x6d) return 'bad';
  const leb = (): number => {
    let r = 0;
    for (let shift = 0; shift < 35; shift += 7) {
      const x = b[o++];
      if (x === undefined) throw new Error('eof');
      r += (x & 0x7f) * 2 ** shift;
      if ((x & 0x80) === 0) return r;
    }
    throw new Error('leb');
  };
  try {
    while (o < b.length) {
      const id = b[o++]!;
      const size = leb();
      const end = o + size;
      if (end > b.length) return 'bad';
      if (id === 5) {
        const count = leb();
        if (count === 0) return null;
        const flag = b[o++]!;
        if (flag > 3) return { count, min: Infinity, max: null, shared: true }; // memory64 and anything newer: refused
        const min = leb();
        const max = flag & 1 ? leb() : null;
        return { count, min, max, shared: (flag & 2) !== 0 };
      }
      o = end;
    }
    return null;
  } catch {
    return 'bad';
  }
}
