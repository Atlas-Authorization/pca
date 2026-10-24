/**
 * 0.4.2 mutation kills (Stryker run 39706550807): both verifiers promise "never throw". The proofs they check are valid, so the only way
 * to reach their catch block is an internal failure; here the hash primitive is made to fail mid-verification and the verdict must still
 * be the fail-closed `malformed-input` refusal (not an exception, not `undefined`).
 */
import { describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ fail: false }));
vi.mock('@noble/hashes/sha256', async (importOriginal) => {
  const real = await importOriginal<typeof import('@noble/hashes/sha256')>();
  const wrapped = Object.assign((...a: Parameters<typeof real.sha256>) => {
    if (state.fail) throw new Error('hash primitive failed');
    return real.sha256(...a);
  }, real.sha256);
  return { ...real, sha256: wrapped };
});

import { insecureDevSetup, vdfEval, vdfEvalCanonical, vdfVerifyCanonicalDetailed, vdfVerifyDetailed } from './vdf';

describe('verifiers fail closed on an internal failure', () => {
  const dev = insecureDevSetup({ bits: 64 });
  const x = 12345n;
  const T = 8;
  it('vdfVerifyDetailed', () => {
    const p = vdfEval(x, T, dev.N);
    expect(vdfVerifyDetailed(x, p.y, p.pi, T, dev.N)).toEqual({ ok: true });
    state.fail = true;
    try {
      expect(vdfVerifyDetailed(x, p.y, p.pi, T, dev.N)).toEqual({ ok: false, reason: 'malformed-input' });
    } finally {
      state.fail = false;
    }
  });
  it('vdfVerifyCanonicalDetailed', () => {
    const p = vdfEvalCanonical(x, T, dev.N);
    expect(vdfVerifyCanonicalDetailed(x, p.y, p.pi, T, dev.N)).toEqual({ ok: true });
    state.fail = true;
    try {
      expect(vdfVerifyCanonicalDetailed(x, p.y, p.pi, T, dev.N)).toEqual({ ok: false, reason: 'malformed-input' });
    } finally {
      state.fail = false;
    }
  });
});
