/** One client process of the crash harness (`crash.ts`): load the adapter, run the windowed workload, record to a file. */
import { closeClients, driveWindowed, openClients, prng } from './harness';
import { loadAdapter } from './load';
import { FileRecorder } from './recorder';
import type { WorkerConfig } from './crash';

export async function workerMain(cfg: WorkerConfig): Promise<void> {
  const adapter = await loadAdapter(cfg.module, cfg.options);
  const rec = new FileRecorder(cfg.file, cfg.proc);
  const clients = await openClients(adapter, cfg.clients);
  const ctx = { rec, retentionMs: cfg.retentionMs, opTimeoutMs: cfg.opTimeoutMs };
  await Promise.all(clients.map((c, i) => driveWindowed(c, `${cfg.proc}c${i}`, cfg.kind, ctx, { ...cfg, rand: prng(cfg.seed + i) })));
  await closeClients(clients);
  rec.close();
  await adapter.teardown?.();
}

// Stryker disable next-line all: process entry glue (runs only as a forked child, outside the mutated test process)
if (require.main === module) workerMain(JSON.parse(process.argv[2]!) as WorkerConfig).then(() => process.exit(0), (e: unknown) => { process.stderr.write(`pca-store-conformance worker: ${String(e)}\n`); process.exit(1); });
