// Oracle: @atlasauth/pca-invariants: the deterministic exports (key pairs from seeds, the legal-chain builder, the risk "worsen" helper and
// the registry constants). The fast-check arbitraries, the property functions and the property runner are not portable (no property-testing
// library in the native SDK) and are not generated.
// PORTING (fn(args) -> native entry point; JSON equality, bytes as {"$bytes": b64u}; a throw requires the native to refuse):
//   keyPairFromSeed(seed)    Invariants.keyPairFromSeed(byte[] seed) -> {secretKey, publicKey, pub}
//   buildChain(model)        Invariants.buildChain(model): model {principalSeed, holder0Seed ({"$bytes"}), rootSpecs, hops:[{holderSeed, addedSpecs}], predicates}
//                            -> {caps, predicates, rootIssuer, holders}; caps are signed (Ed25519 signatures are deterministic): compared byte for byte
//   worsen(base, deltas)     Invariants.worsen(base, deltas): the six clamped risk inputs
//   consts                   DEFAULT_SEED, DEFAULT_NUM_RUNS, INVARIANT_NAMES (the registry names, in order)
import * as I from '@atlasauth/pca-invariants';
import { Oracle, refWrite, rng, seed, reparse } from './lib.mjs';

const X: any = (I as any).default ?? I;
const o = new Oracle('invariants', 'tools/pca-audit/oracles/invariants.mts', 'TS-reference oracle for the deterministic pca-invariants exports.');
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const b64u = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const unb = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const rev = (v: any): any => (Array.isArray(v) ? v.map(rev) : v !== null && typeof v === 'object' ? (Object.keys(v).length === 1 && '$bytes' in v ? unb(v.$bytes) : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, rev(x)]))) : v);
const run = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, nm(name), (...a: any[]) => ref(...a.map(rev)), args);
const sd = (l: string) => ({ $bytes: b64u(seed('invariants/' + l)) });

for (const l of ['a', 'b', 'c', 'zero', 'x'.repeat(5)]) await run('keyPairFromSeed', l, X.keyPairFromSeed, [sd(l)]);
await run('keyPairFromSeed', 'zeros', X.keyPairFromSeed, [{ $bytes: b64u(new Uint8Array(32)) }]);
await run('keyPairFromSeed', 'ff', X.keyPairFromSeed, [{ $bytes: b64u(new Uint8Array(32).fill(255)) }]);
await run('keyPairFromSeed', 'short', X.keyPairFromSeed, [{ $bytes: b64u(new Uint8Array(31)) }]);

const r = rng(2026);
const spec = (): any => r.pick([
  () => ({ k: 'expires', at: r.int(0, 10_000_000) }), () => ({ k: 'not_before', at: r.int(0, 10_000_000) }), () => ({ k: 'rate', max: r.int(1, 10), per_secs: r.int(1, 3600) }),
  () => ({ k: 'max_blast_radius', max: r.int(0, 1000) / 1000 }), () => ({ k: 'reversibility_max', cls: r.pick(['reversible', 'rate_limited', 'irreversible']) }), () => ({ k: 'delegation_depth', max: r.int(0, 20) }),
  () => ({ k: 'budget_frac', frac: r.pick([0, 1, 0.5, 1 / 3, 0.999999, 1e-7, r.next(), r.next(), r.next()]) }),
])();
const preds = (): any[] => Array.from({ length: r.int(1, 3) }, () => ({ verb: r.pick(['read', 'write', 'admin']), resource: r.pick(['/acct/a', '/x/y', '*']), ...(r.next() < 0.5 ? { where: [{ field: 'action.params.amount', op: 'lte', value: r.int(1, 500) }] } : {}) }));
for (let i = 0; i < 90; i++) {
  const model = {
    principalSeed: sd('p' + i), holder0Seed: sd('h0-' + i),
    rootSpecs: Array.from({ length: r.int(1, 4) }, spec),
    hops: Array.from({ length: r.int(0, 5) }, (_, j) => ({ holderSeed: sd(`h${i}.${j}`), addedSpecs: Array.from({ length: r.int(0, 3) }, spec) })),
    predicates: preds(),
  };
  await run('buildChain', `m${i}`, X.buildChain, [model]);
}
for (const [i, specs] of ([[], [{ k: 'budget_frac', frac: 0 }, { k: 'budget_frac', frac: 1 }], [{ k: 'budget_frac', frac: 0.5 }, { k: 'budget_frac', frac: 0.5 }, { k: 'budget_frac', frac: 0.5 }], [{ k: 'max_blast_radius', max: 0 }, { k: 'max_blast_radius', max: 1 }, { k: 'delegation_depth', max: 0 }]] as any[]).entries()) {
  await run('buildChain', `fixed${i}`, X.buildChain, [{ principalSeed: sd('p'), holder0Seed: sd('h'), rootSpecs: specs, hops: [{ holderSeed: sd('h1'), addedSpecs: specs }], predicates: [] }]);
}

const u = () => r.pick([0, 1, 0.5, 0.25, 0.1, 0.2, 0.7, 0.123456789, r.next(), r.next(), r.next()]);
for (let i = 0; i < 200; i++) {
  const base = { semanticDistance: u(), blastRadius: u(), taint: u(), age: u(), reversibility: u(), confidence: u() };
  const d = { dSem: u(), dBlast: u(), dTaint: u(), dAge: u(), dRev: u(), dConf: u() };
  await run('worsen', `w${i}`, X.worsen, [base, d]);
}
for (const [i, d] of ([{ dSem: 1, dBlast: 1, dTaint: 1, dAge: 1, dRev: 1, dConf: 1 }, { dSem: 0, dBlast: 0, dTaint: 0, dAge: 0, dRev: 0, dConf: 0 }, { dSem: -1, dBlast: -1, dTaint: -1, dAge: -1, dRev: -1, dConf: -1 }] as any[]).entries()) {
  for (const base of [{ semanticDistance: 0, blastRadius: 0, taint: 0, age: 0, reversibility: 1, confidence: 1 }, { semanticDistance: 1, blastRadius: 1, taint: 1, age: 1, reversibility: 0, confidence: 0 }, { semanticDistance: 0.5, blastRadius: 0.5, taint: 0.5, age: 0.5, reversibility: 0.5, confidence: 0.5 }]) await run('worsen', `edge${i}`, X.worsen, [base, d]);
}
o.add('consts', 'all', [], { DEFAULT_SEED: X.DEFAULT_SEED, DEFAULT_NUM_RUNS: X.DEFAULT_NUM_RUNS, INVARIANT_NAMES: X.INVARIANTS.map((i: any) => i.name) });
refWrite(o, 'invariants');
