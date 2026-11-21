import { describe, expect, it } from 'vitest';
import { delegate, mintRoot, type Capability } from './capability';
import { ChainMemo } from './chain-compact';
import { encodeKey, generateKeyPair } from './keys';

const kp = () => {
  const k = generateKeyPair();
  return { sk: k.secretKey, pub: encodeKey(k.publicKey) };
};
const P = kp(), A = kp(), B = kp();
const NOW = 1_800_000_000_000;
const chain = (): Capability[] => {
  const root = mintRoot({ principalSecret: P.sk, principalPublic: P.pub, holder: A.pub, caveats: [] });
  return [root, delegate(root, B.pub, [], A.sk)];
};

describe('a non-finite clock never keeps a memoized chain (chain memo)', () => {
  // old check `expires_at < now` was false for NaN, so a prune at a NaN clock kept every entry
  it('prune at NaN drops the entry', () => {
    const memo = new ChainMemo({ ttlMs: 10 });
    memo.rememberVerified(chain(), P.pub, NOW);
    expect(memo.size).toBe(1);
    memo.prune(Number.NaN);
    expect(memo.size).toBe(0);
  });
  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('prune at %s drops the entry', (bad) => {
    const memo = new ChainMemo({ ttlMs: 10 });
    memo.rememberVerified(chain(), P.pub, NOW);
    expect(memo.size).toBe(1);
    memo.prune(bad);
    expect(memo.size).toBe(0);
  });
});
