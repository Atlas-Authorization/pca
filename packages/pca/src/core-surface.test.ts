// `@atlasauth/pca/core` is a strict subset of the root entry: every runtime export is the SAME binding the root exports
// (nothing redefined, so behaviour and wire formats cannot drift), and the surface is pinned so it only grows on purpose.
// One deliberate exception (0.5): `verifyPCActnCore` is the same function WITHOUT the intent-layer extension loaded, because
// Core imports no experimental module; the root entry's has it loaded (see ext-surface.test.ts).
import { describe, expect, it } from 'vitest';
import * as core from './core';
import * as root from './index';

const CORE_RUNTIME_EXPORTS = [
  'InMemoryReplayStore',
  'MAX_CHAIN_DEPTH',
  'PCACTN_MAX_LIFETIME_MS',
  'PCACTN_VERSION',
  'PCA_HEADER',
  'PcaHeaderError',
  'attenuate',
  'b64u',
  'buildPCActn',
  'canonicalizeStrict',
  'capHash',
  'commitPlan',
  'decodeB64uStrict',
  'decodeKey',
  'decodePCActn',
  'decodePcaHeader',
  'delegate',
  'encodeKey',
  'encodePCActn',
  'evaluateAgentCaveats',
  'generateKeyPair',
  'guardPCActnReplay',
  'hashCanonical',
  'merkleRoot',
  'mintRoot',
  'paramsDigest',
  'pcaHeaders',
  'planNodeLeaf',
  'policyCaveats',
  'publicKeyOf',
  'strictParse',
  'verifyChain',
  'verifyInclusion',
  'verifyPCActnCore',
];

describe('@atlasauth/pca/core surface', () => {
  it('exports exactly the pinned Core names', () => {
    expect(Object.keys(core).sort()).toEqual([...CORE_RUNTIME_EXPORTS].sort());
  });
  it('every Core export is the identical root binding (except the extension-free verifyPCActnCore)', () => {
    for (const k of CORE_RUNTIME_EXPORTS.filter((n) => n !== 'verifyPCActnCore')) expect([k, (core as Record<string, unknown>)[k] === (root as Record<string, unknown>)[k]]).toEqual([k, true]);
    expect(core.verifyPCActnCore).not.toBe(root.verifyPCActnCore);
  });
  it('is a small fraction of the root surface', () => {
    expect(Object.keys(root).length).toBeGreaterThan(10 * CORE_RUNTIME_EXPORTS.length);
  });
});
