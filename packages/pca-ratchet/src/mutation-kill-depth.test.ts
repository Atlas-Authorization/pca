/** The depth bound is inclusive: depth == MAX_RATCHET_DEPTH is accepted (leaf derivation is stubbed; 2^20 keys would take minutes). */
import { describe, expect, it, vi } from 'vitest';
import { b64u } from '@atlasauth/pca';

vi.mock('./ggm', async (orig) => {
  const m = await orig<typeof import('./ggm')>();
  return { ...m, allLeafPublicKeys: () => [b64u(new Uint8Array(32).fill(1)), b64u(new Uint8Array(32).fill(2))] };
});

import { MAX_RATCHET_DEPTH } from './ggm';
import { deriveRatchetRoot } from './ratchet';

describe('depth bound', () => {
  it('MAX_RATCHET_DEPTH is accepted, one more is refused', () => {
    expect(deriveRatchetRoot(new Uint8Array(32), MAX_RATCHET_DEPTH).state.depth).toBe(MAX_RATCHET_DEPTH);
    expect(deriveRatchetRoot(new Uint8Array(32), MAX_RATCHET_DEPTH).state.leafCount).toBe(2 ** MAX_RATCHET_DEPTH);
    expect(() => deriveRatchetRoot(new Uint8Array(32), MAX_RATCHET_DEPTH + 1)).toThrow('depth must be an integer in [1, 20]');
  });
});
