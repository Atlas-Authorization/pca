/** randomScalar gives up after EXACTLY 8 all-zero draws (broken entropy source) rather than spinning. */
import { describe, expect, it, vi } from 'vitest';

const calls = vi.hoisted(() => ({ n: 0 }));
vi.mock('@noble/hashes/utils', async (orig) => {
  const m = await orig<typeof import('@noble/hashes/utils')>();
  return { ...m, randomBytes: (len: number) => { calls.n++; return new Uint8Array(len); } };
});

import { randomScalar } from './oprf';

describe('randomScalar', () => {
  it('stops after exactly 8 zero draws with a clear error', () => {
    expect(() => randomScalar()).toThrow('randomScalar: entropy source returned zero repeatedly (RNG failure); refusing to continue');
    expect(calls.n).toBe(8);
  });
});
