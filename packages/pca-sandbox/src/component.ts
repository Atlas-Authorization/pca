import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import type { HandleTable } from './handles';
import { USE_ERR } from './handles';
import type { RunResult } from './host';

/** Where the reference wasmtime host lives after `cargo build --release` in `wasmtime-host/`. */
export const defaultHostBinary = (): string => process.env.PCA_WASMTIME_HOST ?? path.join(__dirname, '../wasmtime-host/target/release/pca-wasmtime-host');

export type ComponentRun = RunResult & { fuelUsed?: number };

/**
 * Run a WebAssembly COMPONENT (canonical ABI, the `tool` world of `wit/pca-act.wit`) under wasmtime with an instruction budget
 * (`fuel`) and a wall-clock timeout. The component's only import is the handle interface, served from `table`; any other import
 * is refused before instantiation (`ambient_import:<name>`); running out of fuel is `fuel_exhausted`. Bytes may be a binary
 * component or WAT text. `fuel` has no default: a budget is a decision.
 */
export async function runComponent(table: HandleTable, component: Uint8Array | string, o: { fuel: number; timeoutMs?: number; host?: string; maxResultBytes?: number }): Promise<ComponentRun> {
  if (!Number.isSafeInteger(o.fuel) || o.fuel < 1) return { ok: false, reason: 'bad_fuel' };
  const maxResult = o.maxResultBytes ?? 1 << 20;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pca-comp-'));
  const file = path.join(dir, 'tool.component');
  fs.writeFileSync(file, component);
  const child = spawn(o.host ?? defaultHostBinary(), [file, String(o.fuel)], { stdio: ['pipe', 'pipe', 'ignore'] });
  const reply = (v: unknown) => child.stdin.write(`${JSON.stringify(v)}\n`);
  return new Promise<ComponentRun>((resolve) => {
    let settled = false;
    let chain: Promise<void> = Promise.resolve();
    const done = (r: ComponentRun) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill('SIGKILL');
      fs.rmSync(dir, { recursive: true, force: true });
      resolve(r);
    };
    const timer = setTimeout(() => done({ ok: false, reason: 'timeout' }), o.timeoutMs ?? 10_000);
    child.on('error', () => done({ ok: false, reason: 'host_unavailable' }));
    // 'close' (not 'exit'): stdout is drained first, so the host's final {fail}/{done} line wins over a bare exit
    child.on('close', () => void chain.then(() => done({ ok: false, reason: 'host_exit' })));
    // requests are answered strictly one at a time, in order
    createInterface({ input: child.stdout }).on('line', (line) => {
      chain = chain.then(async () => {
        let m: { op?: string; h?: number; done?: number; fuel_used?: number; fail?: string };
        try {
          m = JSON.parse(line);
        } catch {
          return done({ ok: false, reason: 'host_protocol' });
        }
        if (typeof m.fail === 'string') return done({ ok: false, reason: m.fail });
        if (typeof m.done === 'number') return done({ ok: true, value: m.done, ...(typeof m.fuel_used === 'number' ? { fuelUsed: m.fuel_used } : {}) });
        const h = Number.isInteger(m.h) ? (m.h as number) : 0;
        if (m.op === 'count') return void reply({ n: table.size });
        if (m.op === 'verb') {
          const v = table.verbOf(h);
          return void reply(v === null ? { err: USE_ERR.unknown_handle } : { ok: v });
        }
        if (m.op === 'invoke') {
          const r = await table.useAsync(h);
          if (!r.ok) return void reply({ err: USE_ERR[r.reason] });
          return void reply(r.result.length > maxResult ? { err: USE_ERR.out_too_small } : { ok: Array.from(r.result) });
        }
        return done({ ok: false, reason: 'host_protocol' });
      });
    });
  });
}
