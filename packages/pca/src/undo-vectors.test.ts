import { readFileSync, writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildUndoVectors } from './test-support/undo-vectors';

const path = new URL('../conformance/undo-vectors.json', import.meta.url);
describe('undo-vectors.json', () => {
  it('is current (UNDO_VECTORS_WRITE=1 regenerates it)', () => {
    const v = buildUndoVectors();
    if (process.env.UNDO_VECTORS_WRITE === '1') writeFileSync(path, `${JSON.stringify(v, null, 2)}\n`);
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual(JSON.parse(JSON.stringify(v)));
  });
});
