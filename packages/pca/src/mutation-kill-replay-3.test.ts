/** replay.ts residual mutant: the safe-integer horizon refusal carries its exact reason. */
import { describe, expect, it } from 'vitest';
import { guardPCActnReplay, type ReplayStore } from './replay';

const MAXS = Number.MAX_SAFE_INTEGER;

describe('retention horizon refusal reason', () => {
  it('exp + skew above 2^53-1 is refused as malformed with the exact reason', async () => {
    const store: ReplayStore = {
      async consumeOnce() {
        throw new Error('must not be called');
      },
    };
    const exp = MAXS - 1;
    const p = { ver: 2, grant_ref: 'g1', cap_chain: [{ holder: 'h1' }], aud: 'rs', iat: exp - 1000, exp, counter: 1, nonce: 'n1' } as never;
    const v = await guardPCActnReplay(store, p, { aud: 'rs', now: exp - 500 });
    expect(v).toMatchObject({ ok: false, code: 'malformed', reason: 'exp + clock skew exceeds the safe-integer range (retention horizon not representable)' });
  });
});
