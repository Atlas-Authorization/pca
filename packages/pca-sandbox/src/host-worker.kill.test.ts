import { EventEmitter } from 'node:events';
import { describe, expect, it, vi } from 'vitest';
import { authFixture } from './test-auth';
import { buildTool, createSandbox } from './index';

// The worker thread is replaced by a scripted stand-in so each event the host listens for can be driven directly.
const w = vi.hoisted(() => ({ script: (_: EventEmitter): void => undefined, opts: undefined as { ctl: SharedArrayBuffer; data: SharedArrayBuffer } | undefined }));
vi.mock('node:worker_threads', async () => {
  const { EventEmitter: EE } = await import('node:events');
  class Worker extends EE {
    constructor(_src: string, o: { workerData: { ctl: SharedArrayBuffer; data: SharedArrayBuffer } }) {
      super();
      w.opts = o.workerData;
      queueMicrotask(() => w.script(this));
    }
    terminate(): Promise<number> {
      return Promise.resolve(0);
    }
  }
  return { Worker };
});

const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };
const tool = buildTool({ calls: [] });
const run = (script: (e: EventEmitter) => void, timeoutMs = 3000) => {
  w.script = script;
  return createSandbox({ executors: {} }).runAsync(tool, 'run', timeoutMs);
};

describe('runAsync worker events', () => {
  it('an error event from the worker is worker_error', async () => {
    expect(await run((e) => e.emit('error', new Error('x')))).toEqual({ ok: false, reason: 'worker_error' });
  });
  it('a worker that exits without a result is worker_exit', async () => {
    expect(await run((e) => e.emit('exit', 1))).toEqual({ ok: false, reason: 'worker_exit' });
  });
  it('done and fail messages: defaults and carried values', async () => {
    expect(await run((e) => e.emit('message', { t: 'done' }))).toEqual({ ok: true, value: 0 });
    expect(await run((e) => e.emit('message', { t: 'done', value: 5 }))).toEqual({ ok: true, value: 5 });
    expect(await run((e) => e.emit('message', { t: 'fail' }))).toEqual({ ok: false, reason: 'trap' });
    expect(await run((e) => e.emit('message', { t: 'fail', reason: 'trap:RuntimeError' }))).toEqual({ ok: false, reason: 'trap:RuntimeError' });
  });
  it('a worker that never answers is cut at the timeout', async () => {
    expect(await run(() => undefined, 40)).toEqual({ ok: false, reason: 'timeout' });
  });
  it('an invoke request is answered through the shared buffers: length in slot 1, bytes in the data buffer, flag raised', async () => {
    const f = authFixture(['notes']);
    const sb = createSandbox({ executors: { 'notes.read': () => Uint8Array.of(9, 8, 7) }, maxResultBytes: 3 });
    sb.table.mint(await f.allow(op), op);
    w.script = (e) => {
      e.emit('message', { t: 'invoke', h: 1 });
      setTimeout(() => e.emit('message', { t: 'done', value: 1 }), 50);
    };
    expect(await sb.runAsync(tool)).toEqual({ ok: true, value: 1 });
    const c = new Int32Array(w.opts!.ctl);
    expect([Atomics.load(c, 0), Atomics.load(c, 1)]).toEqual([1, 3]);
    expect([...new Uint8Array(w.opts!.data)]).toEqual([9, 8, 7]);
  });
});
