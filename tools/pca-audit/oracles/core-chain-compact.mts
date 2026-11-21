// Oracle: packages/pca chain-compact.ts (hop leaves, the hops root, compact chains and their shape check, the verifier memo, the chain view). TS reference.
// Ed25519 chains only; every key is a seed label and no private key is written (a chain holds public keys and signatures). No clock: every time is an argument.
// PORTING (fn(args) -> native entry point; results compared by JSON value, a reference throw = the native throws):
//   hopLeaf(hop) / hopsRoot(chain) / compactChain(chain) / compactChainShapeError(c) / viewOfChain(grant, chain|null) -> {n, leaf, hashes[], counts[]} (hash(i), count(i) for i < n)
//   memoSeq(opts{maxEntries?, ttlMs?}, steps[]) -> one result per step through ONE fresh ChainMemo:
//     ["remember", chain, issuer, now] -> {ok:true, compact} | {ok:false} (the reference threw: a bad chain, a bad clock or a full memo)
//     ["resolve", compact, now]        -> {ok:true, view:{n, leaf, hashes[], counts[]}} | {ok:false, reason}
//     ["prune", now] -> null   ["forget", hopsRoot] -> boolean   ["size"] -> number
import { Oracle, refWrite, seed } from './lib.mjs';
const { b64u }: any = await import('../../../packages/pca/src/hash.ts');
const { publicKeyOf }: any = await import('../../../packages/pca/src/keys.ts');
const cap: any = await import('../../../packages/pca/src/capability.ts');
const cc: any = await import('../../../packages/pca/src/chain-compact.ts');
const cl: any = await import('../../../packages/pca/src/caveat-lang.ts');

const o = new Oracle('core-chain-compact', 'tools/pca-audit/oracles/core-chain-compact.mts', 'TS-reference oracle for chain compaction (hop leaves, hops root, compact chain, memo, chain view).');
const sd = (l: string) => seed('chaincompact/' + l);
const pk = (k: Uint8Array) => b64u(publicKeyOf(k));
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const flip = (b: string) => (b[0] === 'A' ? 'B' : 'A') + b.slice(1);

const priv = sd('principal');
const ks = Array.from({ length: 18 }, (_, i) => sd('h' + i));
const root = cap.mintRoot({ principalSecret: priv, principalPublic: pk(priv), holder: pk(ks[0]), caveats: [{ type: 'scope', actions: ['a'] }] });
const build = (n: number, extra: (i: number) => any[] = () => []) => { const ch: any[] = [root]; for (let i = 1; i < n; i++) ch.push(cap.delegate(ch[i - 1], pk(ks[i]), extra(i), ks[i - 1])); return ch; };
const chains: Record<string, any[]> = { c1: [root], c2: build(2), c3: build(3, (i) => [{ type: 'expires', at: 1000 + i }]), c4: build(4), c16: build(16), c17: build(17) };
const iss = pk(priv);

for (const [n, ch] of Object.entries(chains)) {
  for (const [i, h] of ch.entries()) if (i < 4) await o.run('hopLeaf', `${n}/${i}`, cc.hopLeaf, [h]);
  await o.run('hopsRoot', n, cc.hopsRoot, [ch]);
  await o.run('compactChain', n, cc.compactChain, [ch]);
}
await o.run('hopsRoot', 'empty', cc.hopsRoot, [[]]);
await o.run('hopsRoot', 'reordered', cc.hopsRoot, [[chains.c3[1], chains.c3[0], chains.c3[2]]]);
await o.run('hopsRoot', 'dropped', cc.hopsRoot, [[chains.c3[0], chains.c3[2]]]);
await o.run('hopsRoot', 'doubled', cc.hopsRoot, [[chains.c2[0], chains.c2[0], chains.c2[1]]]);
await o.run('compactChain', 'empty', cc.compactChain, [[]]);
await o.run('compactChain', 'not-array', cc.compactChain, [{}]);
await o.run('compactChain', 'null', cc.compactChain, [null]);

const good = cc.compactChain(chains.c3);
const shapes: [string, any][] = [
  ['ok', good], ['not-object', 5], ['null', null], ['array', []], ['extra', { ...good, x: 1 }], ['missing-leaf', (({ leaf, ...r }: any) => r)(good)], ['v2', { ...good, v: 2 }], ['kind', { ...good, kind: 'x' }],
  ['depth-0', { ...good, depth: 0 }], ['depth-17', { ...good, depth: 17 }], ['depth-16', { ...good, depth: 16 }], ['depth-frac', { ...good, depth: 1.5 }], ['depth-str', { ...good, depth: '3' }], ['depth-neg', { ...good, depth: -1 }],
  ['root-short', { ...good, hops_root: good.hops_root.slice(1) }], ['root-num', { ...good, hops_root: 5 }], ['root-long', { ...good, hops_root: good.hops_root + 'A' }], ['leaf-null', { ...good, leaf: null }], ['leaf-array', { ...good, leaf: [] }], ['leaf-str', { ...good, leaf: 'x' }],
];
for (const [n, c] of shapes) await o.run('compactChainShapeError', n, (x: any) => cc.compactChainShapeError(x), [c]);

const NOW = 1_700_000_000_000;
const viewOut = (v: any) => ({ n: v.n, leaf: v.leaf, hashes: Array.from({ length: v.n }, (_, i) => v.hash(i)), counts: Array.from({ length: v.n }, (_, i) => v.count(i)) });
for (const [n, ch] of Object.entries(chains)) await o.run('viewOfChain', n, (g: any, c: any) => viewOut(cc.viewOfChain(g, c ?? undefined)), [ch[ch.length - 1], ch]);
await o.run('viewOfChain', 'grant-only', (g: any, c: any) => viewOut(cc.viewOfChain(g, c ?? undefined)), [chains.c2[1], null]);
await o.run('viewOfChain', 'empty-chain', (g: any, c: any) => viewOut(cc.viewOfChain(g, c ?? undefined)), [chains.c2[1], []]);

const memoSeq = (opts: any, steps: any[]) => {
  const m = new cc.ChainMemo(opts ?? {});
  return steps.map((s: any) => {
    switch (s[0]) {
      case 'remember': try { return { ok: true, compact: m.rememberVerified(s[1], s[2], s[3]) }; } catch { return { ok: false }; }
      case 'resolve': { const r = m.resolve(s[1], s[2]); return r.ok ? { ok: true, view: viewOut(r.view) } : { ok: false, reason: r.reason }; }
      case 'prune': m.prune(s[1]); return null;
      case 'forget': return m.forget(s[1]);
      default: return m.size;
    }
  });
};
const c3 = cc.compactChain(chains.c3), c2 = cc.compactChain(chains.c2), c4 = cc.compactChain(chains.c4);
const seqs: [string, any, any[]][] = [
  ['remember-resolve', null, [['remember', chains.c3, iss, NOW], ['size'], ['resolve', c3, NOW + 1], ['resolve', c3, NOW + 3_600_000], ['resolve', c3, NOW + 3_600_001], ['size']]],
  ['not-remembered', null, [['resolve', c3, NOW], ['remember', chains.c2, iss, NOW], ['resolve', c3, NOW], ['resolve', c2, NOW]]],
  ['wrong-issuer', null, [['remember', chains.c3, pk(ks[5]), NOW], ['size'], ['resolve', c3, NOW]]],
  ['bad-clock', null, [['remember', chains.c3, iss, 1.5], ['remember', chains.c3, iss, NOW], ['resolve', c3, 2.5], ['resolve', c3, NOW]]],
  ['tampered-leaf', null, [['remember', chains.c3, iss, NOW], ['resolve', { ...c3, leaf: chains.c2[1] }, NOW], ['resolve', { ...c3, leaf: { ...clone(c3.leaf), sig: flip(c3.leaf.sig) } }, NOW], ['resolve', { ...c3, leaf: { ...clone(c3.leaf), caveats: [] } }, NOW]]],
  ['tampered-depth', null, [['remember', chains.c3, iss, NOW], ['resolve', { ...c3, depth: 2 }, NOW], ['resolve', { ...c3, depth: 4 }, NOW], ['resolve', { ...c3, hops_root: flip(c3.hops_root) }, NOW]]],
  ['malformed', null, [['remember', chains.c3, iss, NOW], ['resolve', 5, NOW], ['resolve', null, NOW], ['resolve', { ...c3, v: 2 }, NOW], ['resolve', { ...c3, extra: 1 }, NOW]]],
  ['ttl', { ttlMs: 100 }, [['remember', chains.c3, iss, NOW], ['resolve', c3, NOW + 100], ['resolve', c3, NOW + 101], ['size']]],
  ['ttl-capped', { ttlMs: 9_999_999_999 }, [['remember', chains.c3, iss, NOW], ['resolve', c3, NOW + 3_600_000], ['resolve', c3, NOW + 3_600_001]]],
  ['full-fail-closed', { maxEntries: 2 }, [['remember', chains.c2, iss, NOW], ['remember', chains.c3, iss, NOW], ['remember', chains.c4, iss, NOW], ['size'], ['remember', chains.c3, iss, NOW + 1], ['size']]],
  ['full-then-expired', { maxEntries: 1, ttlMs: 10 }, [['remember', chains.c2, iss, NOW], ['remember', chains.c3, iss, NOW + 5], ['remember', chains.c3, iss, NOW + 11], ['size'], ['resolve', c2, NOW + 11], ['resolve', c3, NOW + 11]]],
  ['forget', null, [['remember', chains.c3, iss, NOW], ['forget', c3.hops_root], ['forget', c3.hops_root], ['resolve', c3, NOW], ['size']]],
  ['prune', { ttlMs: 50 }, [['remember', chains.c2, iss, NOW], ['remember', chains.c4, iss, NOW + 40], ['prune', NOW + 60], ['size'], ['resolve', c2, NOW + 60], ['resolve', c4, NOW + 60]]],
  ['re-remember', null, [['remember', chains.c3, iss, NOW], ['remember', chains.c3, iss, NOW + 1000], ['size'], ['resolve', c3, NOW + 3_600_500]]],
  ['empty-chain', null, [['remember', [], iss, NOW], ['remember', chains.c17, iss, NOW], ['size']]],
  ['two-chains', null, [['remember', chains.c2, iss, NOW], ['remember', chains.c4, iss, NOW], ['resolve', c2, NOW], ['resolve', c4, NOW], ['resolve', c3, NOW]]],
];
for (const [n, opts, steps] of seqs) await o.run('memoSeq', n, memoSeq, [opts, steps]);

refWrite(o, 'core-chain-compact');
