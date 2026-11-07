import { readFileSync } from 'node:fs';
import { MemoryBlueprintStore } from './blueprint';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { BlueprintRegistry, checkBlueprints } from './blueprint';
import { buildBlueprintVectors } from './test-support/blueprint-vectors';

const file = join(__dirname, '..', '..', 'pca', 'conformance', 'blueprint-vectors.json');
const V = JSON.parse(readFileSync(file, 'utf8'));

describe('agent blueprint shared vectors - T-588', () => {
  it('the committed file is exactly what the generator writes', async () => {
    expect(readFileSync(file, 'utf8')).toBe(`${JSON.stringify(await buildBlueprintVectors(), null, 2)}\n`);
  });
  for (const s of V.scenarios) {
    it(s.name, async () => {
      const reg = new BlueprintRegistry([V.operator], new MemoryBlueprintStore());
      for (const st of s.steps) {
        const got = st.op === 'accept' ? await reg.accept(V.records[st.record]) : await checkBlueprints(st.chain, reg, st.opts);
        expect(got).toEqual(st.expect);
      }
    });
  }
});
