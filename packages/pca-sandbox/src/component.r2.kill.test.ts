import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { HandleTable, ReceiptLog, runComponent } from './index';

const hoisted = vi.hoisted(() => ({ closed: [] as Promise<void>[] }));
vi.mock('node:child_process', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:child_process')>();
  const spawn = ((...a: Parameters<typeof real.spawn>) => {
    const c = real.spawn(...a);
    hoisted.closed.push(new Promise<void>((r) => c.once('close', () => r())));
    return c;
  }) as typeof real.spawn;
  return { ...real, spawn };
});

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'pca-comp-r2-'));
afterAll(() => fs.rmSync(scratch, { recursive: true, force: true }));
let n = 0;
const fakeHost = (body: string): string => {
  const file = path.join(scratch, `host-${n++}.js`);
  fs.writeFileSync(file, `#!${process.execPath}\nconst out = (o) => process.stdout.write(JSON.stringify(o) + '\\n');\n${body}\n`, { mode: 0o755 });
  return file;
};
const empty = () => new HandleTable('none', new ReceiptLog(), {});

describe('runComponent host process plumbing', () => {
  it('the host stderr is discarded, so a host that writes a lot there is never blocked', async () => {
    const host = fakeHost(`require('node:fs').writeSync(2, Buffer.alloc(1 << 20, 97)); out({ done: 1 });`);
    expect(await runComponent(empty(), 'x', { fuel: 1, host, timeoutMs: 8000 })).toEqual({ ok: true, value: 1 });
  });

  it('settling is final: the later close of the killed host does not settle the run a second time', async () => {
    const before = hoisted.closed.length;
    const st = vi.spyOn(globalThis, 'setTimeout');
    const ct = vi.spyOn(globalThis, 'clearTimeout');
    try {
      const host = fakeHost(`out({ done: 1 }); setTimeout(() => undefined, 60000);`);
      expect(await runComponent(empty(), 'x', { fuel: 1, host, timeoutMs: 4322 })).toEqual({ ok: true, value: 1 });
      await hoisted.closed[before];
      await new Promise<void>((r) => setImmediate(r));
      const i = st.mock.calls.findIndex((c) => c[1] === 4322);
      expect(i).toBeGreaterThanOrEqual(0);
      expect(ct.mock.calls.filter((c) => c[0] === st.mock.results[i]!.value)).toHaveLength(1);
    } finally {
      st.mockRestore();
      ct.mockRestore();
    }
  });
});
