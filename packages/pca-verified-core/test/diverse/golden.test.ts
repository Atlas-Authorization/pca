// golden.test.ts - runs the pinned smoke corpus (formal/dafny/difftargets/golden.json) through the PRODUCTION bridge and requires the
// transcript sha256 to equal the digest that cs, go, java, py AND js (Dafny 4.11.0 compiles of the same proved modules) produced.
// So a local `pnpm test` detects any drift between the shipped generated/pca_core.js and the multi-target consensus, without Dafny.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs generator
import { cases } from './gen-cases.mjs';
import { runCase } from './prod-runner';

const golden = JSON.parse(readFileSync(join(__dirname, '../../../../formal/dafny/difftargets/golden.json'), 'utf8')) as {
  gen: { n: number; seed: number; big: number };
  casesSha256: string;
  transcriptSha256: string;
};

describe('diverse-compilation golden transcript', () => {
  it('the production bridge reproduces the multi-target consensus bit-for-bit', () => {
    const lines: string[] = [...(cases(golden.gen.n, golden.gen.seed, { big: golden.gen.big === 1 }) as Iterable<string>)];
    const sha = (s: string) => createHash('sha256').update(s).digest('hex');
    expect(sha(lines.join('\n') + '\n')).toBe(golden.casesSha256);
    const out = lines.map(runCase).join('\n') + '\n';
    expect(sha(out)).toBe(golden.transcriptSha256);
  });
});
