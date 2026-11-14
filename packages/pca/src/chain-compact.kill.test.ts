// Exact-outcome tests for chain-compact.ts: depth boundaries, every shape refusal, the clock and verification errors of
// rememberVerified, the prune boundary, and the resolve refusals that only a corrupted memo entry reaches.
import { describe, expect, it } from 'vitest';
import { delegate, mintRoot, MAX_CHAIN_DEPTH, type Capability } from './capability';
import { ChainMemo, compactChain, compactChainShapeError, type ChainMemoEntry } from './chain-compact';
import { encodeKey, generateKeyPair } from './keys';

const kp = () => {
  const k = generateKeyPair();
  return { sk: k.secretKey, pub: encodeKey(k.publicKey) };
};
const P = kp(), A = kp(), B = kp();
const NOW = 1_800_000_000_000;
const chainOf = (n: number): Capability[] => {
  const out = [mintRoot({ principalSecret: P.sk, principalPublic: P.pub, holder: A.pub, caveats: [] })];
  let signer = A, other = B;
  for (let i = 1; i < n; i++) {
    out.push(delegate(out[i - 1]!, other.pub, [], signer.sk));
    [signer, other] = [other, signer];
  }
  return out;
};
const entriesOf = (m: ChainMemo) => (m as unknown as { entries: Map<string, ChainMemoEntry> }).entries;

describe('compactChain / compactChainShapeError boundaries', () => {
  it('MAX_CHAIN_DEPTH hops fold, one more throws', () => {
    const c = chainOf(1);
    expect(compactChain(Array(MAX_CHAIN_DEPTH).fill(c[0]!)).depth).toBe(MAX_CHAIN_DEPTH);
    expect(() => compactChain(Array(MAX_CHAIN_DEPTH + 1).fill(c[0]!))).toThrow('compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops');
  });
  it('closed members, kind, the depth maximum and a non-string root', () => {
    const c = compactChain(chainOf(2));
    expect(compactChainShapeError({ ...c, [MARKER()]: 1 })).toBe(`unknown member 'compact chain.${MARKER()}'`);
    expect(compactChainShapeError({ ...c, kind: 'x' })).toBe('not a pca-chain-compact v1');
    expect(compactChainShapeError({ ...c, depth: MAX_CHAIN_DEPTH })).toBeNull();
    expect(compactChainShapeError({ ...c, hops_root: Array(43).fill('a') })).toBe('hops_root must be a 43 character digest');
  });
});

function MARKER(): string {
  return ['Stry', 'ker was here'].join('');
}

describe('ChainMemo.rememberVerified', () => {
  it('refuses a non-integer clock', () => {
    expect(() => new ChainMemo().rememberVerified(chainOf(2), P.pub, 0.5)).toThrow('rememberVerified: the clock is not a safe integer');
  });
  it('names the verifier reason', () => {
    expect(() => new ChainMemo().rememberVerified(chainOf(3), B.pub, NOW)).toThrow('rememberVerified: the chain does not verify: hop 0: root issuer is not the expected principal');
  });
  it('prune keeps an entry that expires exactly now', () => {
    const memo = new ChainMemo({ ttlMs: 10 });
    memo.rememberVerified(chainOf(2), P.pub, NOW);
    memo.prune(NOW + 10);
    expect(memo.size).toBe(1);
    memo.prune(NOW + 11);
    expect(memo.size).toBe(0);
  });
});

describe('ChainMemo.resolve refusals', () => {
  it('a malformed presentation names the shape error', () => {
    expect(new ChainMemo().resolve(5, NOW)).toEqual({ ok: false, reason: 'malformed compact chain: not an object' });
  });
  it('a memo entry whose caveat count disagrees with the leaf refuses', () => {
    const memo = new ChainMemo();
    const compact = memo.rememberVerified(chainOf(2), P.pub, NOW);
    const m = entriesOf(memo).get(compact.hops_root)!;
    entriesOf(memo).set(compact.hops_root, { ...m, counts: [...m.counts.slice(0, -1), 99] });
    expect(memo.resolve(compact, NOW)).toEqual({ ok: false, reason: 'the leaf caveats differ from the memoized chain' });
  });
  it('an error while resolving fails closed with its message', () => {
    const memo = new ChainMemo();
    const compact = memo.rememberVerified(chainOf(2), P.pub, NOW);
    const m = entriesOf(memo).get(compact.hops_root)!;
    entriesOf(memo).set(compact.hops_root, {
      ...m,
      get hashes(): readonly string[] {
        throw new Error('boom');
      },
    });
    expect(memo.resolve(compact, NOW)).toEqual({ ok: false, reason: 'compact chain error (fail closed): boom' });
    entriesOf(memo).set(compact.hops_root, {
      ...m,
      get hashes(): readonly string[] {
        throw 'x';
      },
    });
    expect(memo.resolve(compact, NOW)).toEqual({ ok: false, reason: 'compact chain error (fail closed): unknown' });
  });
});
