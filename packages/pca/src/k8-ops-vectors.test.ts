import { readFileSync, writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildMissingContextVectors, buildPolicyClassVectors } from './test-support/k8-ops-vectors';

describe.each([['missing-context-vectors.json', buildMissingContextVectors], ['policy-classes-vectors.json', buildPolicyClassVectors]] as const)('%s', (file, build) => {
  it('is current and the reference agrees with every hand-written expectation (K8_VECTORS_WRITE=1 regenerates it)', () => {
    const path = new URL(`../conformance/${file}`, import.meta.url);
    const text = `${JSON.stringify(build(), null, 2)}\n`;
    if (process.env.K8_VECTORS_WRITE === '1') writeFileSync(path, text);
    expect(readFileSync(path, 'utf8')).toBe(text);
  });
});
