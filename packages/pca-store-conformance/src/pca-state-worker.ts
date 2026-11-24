/** One child process of the pca-state profile (`pca-state.ts`): run requirePCA guards against the adapter, record outcomes. */
import { pcaStateWorkerMain, type PcaStateWorkerConfig } from './pca-state';

// Stryker disable next-line all: process entry glue (runs only as a forked child, outside the mutated test process)
if (require.main === module) pcaStateWorkerMain(JSON.parse(process.argv[2]!) as PcaStateWorkerConfig).then(() => process.exit(0), (e: unknown) => { process.stderr.write(`pca-store-conformance pca-state worker: ${String(e)}\n`); process.exit(1); });
