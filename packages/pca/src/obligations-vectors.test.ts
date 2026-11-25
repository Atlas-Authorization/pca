import { readFileSync, writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildObligationsVectors } from './test-support/obligations-vectors';

const path = new URL('../conformance/obligations-vectors.json', import.meta.url);
describe('obligations-vectors.json', () => {
  it('is current (OBLIGATIONS_VECTORS_WRITE=1 regenerates it)', () => {
    const text = `${JSON.stringify(buildObligationsVectors(), null, 2)}\n`;
    if (process.env.OBLIGATIONS_VECTORS_WRITE === '1') writeFileSync(path, text);
    expect(readFileSync(path, 'utf8')).toBe(text);
  });
});
