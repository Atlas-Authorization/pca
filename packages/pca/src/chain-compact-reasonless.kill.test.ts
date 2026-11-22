/**
 * chain-compact.ts `rememberVerified`: a refusal from the chain verifier that carries no reason is still reported, as
 * 'invalid'. The real verifier always names a reason, so ONLY `verifyChain` is stubbed here to refuse without one.
 */
import { describe, expect, it, vi } from 'vitest';

vi.mock('./capability', async (importOriginal) => {
  const m = await importOriginal<typeof import('./capability')>();
  return { ...m, verifyChain: () => ({ ok: false }) };
});

import { ChainMemo } from './chain-compact';

describe('rememberVerified with a reasonless refusal', () => {
  it('throws with the fallback reason', () => {
    expect(() => new ChainMemo().rememberVerified([] as never, 'issuer', 1_800_000_000_000)).toThrow('rememberVerified: the chain does not verify: invalid');
  });
});
