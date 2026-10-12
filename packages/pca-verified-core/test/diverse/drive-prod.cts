// drive-prod.cts <casefile> : CLI over prod-runner.ts - print one canonical result line per case (same format as Harness.dfy).
import { readFileSync } from 'node:fs';
import * as RNS from './prod-runner';
// tsx exposes the CJS module under .default for named imports from a .ts file
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { runCase } = ((RNS as any).default ?? RNS) as typeof RNS;

const lines = readFileSync(process.argv[2]!, 'utf8').split('\n');
if (lines[lines.length - 1] === '') lines.pop();
const out: string[] = [];
for (const l of lines) out.push(runCase(l));
process.stdout.write(out.join('\n') + '\n');
