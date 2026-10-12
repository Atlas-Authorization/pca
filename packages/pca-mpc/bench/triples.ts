/**
 * Benchmark: steady-state cost of one authenticated Beaver triple from the dealer-free (OT) offline phase
 * (2 sacrifice partners, 2 MAC keys), in process, extension channels warm.
 *
 *   node ../../node_modules/.pnpm/tsx@*\/node_modules/tsx/dist/cli.mjs bench/triples.ts [srcDir] [reps]
 *
 * `srcDir` defaults to ../src; pass another checkout's src to compare builds. Prints one JSON line per party count.
 */
import { resolve } from 'node:path';

const src = resolve(process.argv[2] || resolve(__dirname, '../src'));
const reps = Number(process.argv[3] ?? 5);
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { NoDealerOffline } = require(resolve(src, 'mascot.ts'));

for (const n of [2, 3]) {
  const off = new NoDealerOffline(n, 11n);
  off.genAuthTriple(); // warm up: base OTs and JIT
  const t0 = performance.now();
  for (let i = 0; i < reps; i++) off.genAuthTriple();
  const ms = (performance.now() - t0) / reps;
  console.log(JSON.stringify({ n, statSec: off.statSec, msPerTriple: Math.round(ms), reps, node: process.version }));
}
