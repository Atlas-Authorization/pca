import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { delegate, mintRoot, MAX_CHAIN_DEPTH, type Capability } from './capability';
import { CHAIN_MEMO_MAX_TTL_MS, ChainMemo, compactChain, compactChainShapeError, hopsRoot } from './chain-compact';
import { evaluateK1, isK1Caveat } from './caveat-lang';
import { generateKeyPair, encodeKey } from './keys';

const kp = () => {
  const k = generateKeyPair();
  return { sk: k.secretKey, pub: encodeKey(k.publicKey) };
};
const P = kp(), A = kp(), B = kp();
const NOW = 1_800_000_000_000;
const chainOf = (n: number, caveatsAt: Record<number, unknown[]> = {}): Capability[] => {
  const root = mintRoot({ principalSecret: P.sk, principalPublic: P.pub, holder: A.pub, caveats: (caveatsAt[0] ?? []) as never });
  const out = [root];
  let signer = A, other = B;
  for (let i = 1; i < n; i++) {
    out.push(delegate(out[i - 1]!, other.pub, (caveatsAt[i] ?? []) as never, signer.sk));
    [signer, other] = [other, signer];
  }
  return out;
};

describe('chain compaction', () => {
  it('folds to a handle that commits to order and length', () => {
    const c = chainOf(4);
    expect(hopsRoot(c)).toHaveLength(43);
    expect(hopsRoot(c)).not.toBe(hopsRoot(c.slice(0, 3)));
    expect(hopsRoot([c[0]!, c[2]!, c[1]!, c[3]!])).not.toBe(hopsRoot(c));
    const x = compactChain(c);
    expect(x).toMatchObject({ v: 1, kind: 'pca-chain-compact', depth: 4, hops_root: hopsRoot(c), leaf: c[3] });
    expect(() => compactChain([])).toThrow(/1\.\.MAX_CHAIN_DEPTH/);
  });
  it('the memo remembers only chains its own verifier accepted', () => {
    const memo = new ChainMemo();
    const c = chainOf(3);
    expect(() => memo.rememberVerified(c, B.pub, NOW)).toThrow(/does not verify/); // wrong root issuer
    expect(() => memo.rememberVerified([c[0]!, c[2]!], P.pub, NOW)).toThrow(/does not verify/); // a hop missing
    expect(memo.size).toBe(0);
    const compact = memo.rememberVerified(c, P.pub, NOW);
    expect(memo.size).toBe(1);
    expect(memo.resolve(compact, NOW)).toMatchObject({ ok: true });
  });
  it('refuses a compact chain it does not know, with another depth, another leaf, after expiry or a bad clock', () => {
    const memo = new ChainMemo({ ttlMs: 1000 });
    const c = chainOf(3);
    const compact = memo.rememberVerified(c, P.pub, NOW);
    const other = new ChainMemo();
    expect(other.resolve(compact, NOW)).toEqual({ ok: false, reason: 'the chain is not in this verifier memo (present the full chain)' });
    expect(memo.resolve({ ...compact, depth: 2 }, NOW)).toEqual({ ok: false, reason: 'the depth differs from the memoized chain' });
    expect(memo.resolve({ ...compact, leaf: c[1]! }, NOW)).toEqual({ ok: false, reason: 'the leaf is not the memoized last hop' });
    expect(memo.resolve({ ...compact, leaf: { ...compact.leaf, caveats: [{ type: 'sealed' }] } }, NOW)).toEqual({ ok: false, reason: 'the leaf is not the memoized last hop' });
    expect(memo.resolve(compact, NOW + 1000).ok).toBe(true);
    expect(memo.resolve(compact, NOW + 1001)).toEqual({ ok: false, reason: 'the memoized chain has expired (present the full chain)' });
    expect(memo.size).toBe(0);
    expect(memo.resolve(compact, 0.5)).toEqual({ ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' });
  });
  it('shape errors are exact', () => {
    const c = compactChain(chainOf(2));
    expect(compactChainShapeError(c)).toBeNull();
    expect(compactChainShapeError(5)).toBe('not an object');
    expect(compactChainShapeError({ ...c, extra: 1 })).toBe("unknown member 'compact chain.extra'");
    expect(compactChainShapeError({ ...c, v: 2 })).toBe('not a pca-chain-compact v1');
    expect(compactChainShapeError({ ...c, depth: 0 })).toBe(`depth must be 1..${MAX_CHAIN_DEPTH}`);
    expect(compactChainShapeError({ ...c, depth: MAX_CHAIN_DEPTH + 1 })).toBe(`depth must be 1..${MAX_CHAIN_DEPTH}`);
    expect(compactChainShapeError({ ...c, hops_root: 'x' })).toBe('hops_root must be a 43 character digest');
    expect(compactChainShapeError({ ...c, leaf: 5 })).toBe('leaf must be a capability');
  });
  it('a full memo never evicts a live entry; pruning frees expired ones; forget removes', () => {
    const memo = new ChainMemo({ maxEntries: 1, ttlMs: 10 });
    const a = chainOf(2), b = chainOf(3);
    memo.rememberVerified(a, P.pub, NOW);
    expect(() => memo.rememberVerified(b, P.pub, NOW + 5)).toThrow(/full of live entries/);
    expect(() => memo.rememberVerified(a, P.pub, NOW + 5)).not.toThrow(); // re-remembering the same chain is fine
    memo.rememberVerified(b, P.pub, NOW + 100); // the first expired
    expect(memo.size).toBe(1);
    expect(memo.forget(hopsRoot(b))).toBe(true);
    expect(memo.forget(hopsRoot(b))).toBe(false);
    expect(CHAIN_MEMO_MAX_TTL_MS).toBe(3_600_000);
  });
  it('the caveat language decides identically through a compact chain (every shared k1_eval vector)', () => {
    const doc = JSON.parse(readFileSync(new URL('../conformance/caveat-lang-vectors.json', import.meta.url), 'utf8')).primitives.k1_eval as { name: string; input: any }[];
    let ran = 0;
    for (const e of doc) {
      const { grant, chain, k1, context } = e.input;
      const memo = new ChainMemo();
      const compact = memo.rememberVerified(chain, grant.issuer, NOW);
      const r = memo.resolve(compact, NOW);
      expect(r.ok).toBe(true);
      if (!r.ok) continue;
      const full = evaluateK1(grant, chain, k1, { now: context.now, action: context.action });
      const viaView = evaluateK1(grant, r.view, k1, { now: context.now, action: context.action });
      expect({ name: e.name, ok: viaView.ok, failed: viaView.failed, reasons: viaView.reasons, bound: viaView.bound }).toEqual({ name: e.name, ok: full.ok, failed: full.failed, reasons: full.reasons, bound: full.bound });
      expect(isK1Caveat({ type: 'x' })).toBe(false);
      ran += 1;
    }
    expect(ran).toBeGreaterThanOrEqual(100);
  });
});
