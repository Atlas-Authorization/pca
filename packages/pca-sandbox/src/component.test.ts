import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { authFixture, claimFixture } from './test-auth';
import { ReceiptLog, createSandbox, defaultHostBinary, referenceComponentWat, runComponent, USE_ERR } from './index';

/**
 * The canonical-ABI host (wasmtime, with fuel). Needs a Rust toolchain to build `wasmtime-host`. In CI (PCA_REQUIRE_WASMTIME=1)
 * a missing toolchain or a failed build FAILS the suite; elsewhere it is skipped explicitly.
 */
const REQUIRED = process.env.PCA_REQUIRE_WASMTIME === '1';
const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };

describe('wasmtime component host is required in CI', () => {
  it('has a toolchain when PCA_REQUIRE_WASMTIME=1', () => {
    if (REQUIRED) expect(() => execFileSync('cargo', ['--version'])).not.toThrow();
  });
});

describe.runIf(process.env.PCA_MUTATION_RUN !== '1' && (REQUIRED || fs.existsSync(defaultHostBinary())))('component model (canonical ABI) under wasmtime with fuel', () => {
  let unavailable: string | null = null;
  beforeAll(() => {
    if (fs.existsSync(defaultHostBinary())) return;
    try {
      execFileSync('cargo', ['build', '--release', '--manifest-path', path.join(__dirname, '../wasmtime-host/Cargo.toml')], { stdio: 'pipe' });
    } catch (e) {
      unavailable = String(e).slice(0, 400);
      if (REQUIRED) throw new Error(`wasmtime host cannot be built in CI: ${unavailable}`);
    }
  }, 900_000);

  async function setup(uses = 1) {
    const f = authFixture(['notes']);
    const sb = createSandbox({ executors: { 'notes.read': async () => Uint8Array.of(42, 1, 2) }, runtimeClaim: claimFixture().runtimeClaim, log: new ReceiptLog({ now: () => 1 }) });
    sb.table.mint(await f.allow(op), op, { uses });
    return sb;
  }
  const skip = (ctx: { skip: () => void }) => { if (unavailable) ctx.skip(); };

  it('a component built for the world calls invoke through the canonical ABI and gets the host bytes', async (ctx) => {
    skip(ctx);
    const sb = await setup();
    const r = await runComponent(sb.table, referenceComponentWat(), { fuel: 1_000_000 });
    expect(r).toMatchObject({ ok: true, value: 42 });
    expect((r as { fuelUsed?: number }).fuelUsed).toBeGreaterThan(0);
    expect(sb.log.entries.map((e) => [e.outcome, e.reason, e.runtime_class])).toEqual([['ok', 'used', 'wasi_no_ambient']]);
  });

  it('the host codes come back through result<_, s32>: spent and unknown handle', async (ctx) => {
    skip(ctx);
    const sb = await setup();
    expect(await runComponent(sb.table, referenceComponentWat(), { fuel: 1_000_000 })).toMatchObject({ ok: true, value: 42 });
    expect(await runComponent(sb.table, referenceComponentWat(), { fuel: 1_000_000 })).toMatchObject({ ok: true, value: USE_ERR.spent });
    expect(await runComponent(sb.table, referenceComponentWat({ handle: 9 }), { fuel: 1_000_000 })).toMatchObject({ ok: true, value: USE_ERR.unknown_handle });
  });

  it('refuses any other import before it runs (no wasi, no ambient authority)', async (ctx) => {
    skip(ctx);
    const sb = await setup();
    expect(await runComponent(sb.table, referenceComponentWat({ extraImport: 'wasi:cli/environment@0.2.0' }), { fuel: 1_000_000 })).toEqual({ ok: false, reason: 'ambient_import:wasi:cli/environment@0.2.0' });
    expect(sb.log.entries).toHaveLength(0);
  });

  it('fuel: a tool that never returns is stopped by the instruction budget, and a budget of one instruction stops even the reference tool', async (ctx) => {
    skip(ctx);
    const sb = await setup();
    expect(await runComponent(sb.table, referenceComponentWat({ spin: true }), { fuel: 100_000, timeoutMs: 20_000 })).toEqual({ ok: false, reason: 'fuel_exhausted' });
    expect(await runComponent(sb.table, referenceComponentWat(), { fuel: 1 })).toEqual({ ok: false, reason: 'fuel_exhausted' });
    expect(sb.log.entries).toHaveLength(0); // it never reached invoke
  });

  it('fuel must be a positive safe integer; malformed components are refused', async (ctx) => {
    skip(ctx);
    const sb = await setup();
    for (const fuel of [0, -1, 1.5, Number.NaN]) expect(await runComponent(sb.table, referenceComponentWat(), { fuel })).toEqual({ ok: false, reason: 'bad_fuel' });
    expect(await runComponent(sb.table, 'not a component', { fuel: 1000 })).toEqual({ ok: false, reason: 'malformed_component' });
  });

  it('a missing host binary is a refusal, not a hang', async () => {
    const sb = await setup();
    expect(await runComponent(sb.table, referenceComponentWat(), { fuel: 1000, host: '/nonexistent/pca-wasmtime-host' })).toEqual({ ok: false, reason: 'host_unavailable' });
  });
});
