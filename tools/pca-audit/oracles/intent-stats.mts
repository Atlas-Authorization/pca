// Oracle: @atlasauth/pca-intent numerics (clopper.ts + metrics.ts pure parts). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule):
//   binomialCdf(k,n,p)             IntentStats.binomialCdf; double, JSON-number equal (log/exp via fdlibm-compatible math)
//   doubleToDyadic(x)              IntentStats.doubleToDyadic; {num: {$bigint}, exp}
//   cdfRecNumerator(n,k,a)         numerator as {$bigint}; a arrives as {$bigint} (decimal string)
//   cdfExceeds(n,k,a,alpha)        boolean; a and alpha.num are {$bigint}
//   clopperPearsonUpper(k,n,a)     double; clopperPearsonCertified -> {upper, upperUnits, lowerUnits} with {$bigint}
//   hoeffdingHalfWidth(r,m,d?)     double;  wilsonInterval(k,n,z?) -> {p,lo,hi} (NaN printed {$num:"NaN"})
// A thrown reference error requires the native to throw.
import * as C0 from '../../../packages/pca-intent/src/clopper';
import * as M0 from '../../../packages/pca-intent/src/metrics';
const C: any = (C0 as any).default ?? C0;
const Mt: any = (M0 as any).default ?? M0;
const { binomialCdf, doubleToDyadic, cdfRecNumerator, cdfExceeds, clopperPearsonCertified, clopperPearsonUpper } = C;
const { hoeffdingHalfWidth, wilsonInterval } = Mt;
import { Oracle, refWrite, rng, seed } from './lib.mjs';

const o = new Oracle('intent-stats', 'tools/pca-audit/oracles/intent-stats.mts', 'TS-reference oracle for the intent package numerics.');
const bi = (a: any) => (a !== null && typeof a === 'object' && '$bigint' in a ? BigInt(a.$bigint) : a);
const B = (x: bigint) => ({ $bigint: x.toString() });
let n = 0;
const nm = () => String(n++);
const r = rng(Buffer.from(seed('intent-stats')).readUInt32LE(0));

const alphas = [0.05, 0.01, 0.1, 0.5, 0.001, 1e-9, 0.9, 0.025, 0.3333333333333333];
const kn: [number, number][] = [[0, 0], [0, 1], [1, 1], [0, 10], [3, 10], [10, 10], [0, 50], [1, 50], [25, 50], [49, 50], [50, 50], [5, 100], [0, 300], [17, 200], [150, 300]];
for (const [k, nn] of kn) for (const a of alphas) {
  await o.run('clopperPearsonUpper', nm(), clopperPearsonUpper, [k, nn, a]);
  await o.run('clopperPearsonCertified', nm(), (...x: any[]) => { const c = (clopperPearsonCertified as any)(...x); return { upper: c.upper, upperUnits: B(c.upperUnits), lowerUnits: B(c.lowerUnits) }; }, [k, nn, a]);
}
for (let i = 0; i < 60; i++) {
  const nn = r.int(0, 120); const k = r.int(0, nn); const a = r.pick(alphas) * (0.5 + r.next() * 0.5);
  await o.run('clopperPearsonUpper', nm(), clopperPearsonUpper, [k, nn, a]);
}
for (const bad of [[-1, 5, 0.05], [6, 5, 0.05], [1.5, 5, 0.05], [1, 5, 0], [1, 5, 1], [1, -5, 0.05], [1, 5, -0.1]]) await o.run('clopperPearsonUpper', nm(), clopperPearsonUpper, bad);

for (const [k, nn] of kn) for (const p of [0, 1e-9, 0.01, 0.3, 0.5, 0.97, 1 - 1e-12, 1, -0.1, 1.1]) await o.run('binomialCdf', nm(), binomialCdf, [k, nn, p]);
for (let i = 0; i < 40; i++) { const nn = r.int(1, 400); await o.run('binomialCdf', nm(), binomialCdf, [r.int(-1, nn + 1), nn, r.next()]); }

for (const x of [0.5, 0.25, 0.05, 0.1, 0.3333333333333333, 1e-9, 1e-300, 5e-324, 0.999999999999, 0, 1, -0.5, 2]) await o.run('doubleToDyadic', nm(), (v: number) => { const d = doubleToDyadic(v); return { num: B(d.num), exp: d.exp }; }, [x]);

const A = 1n << 52n;
for (const [k, nn] of [[0, 0], [0, 3], [2, 5], [5, 5], [7, 5], [3, 30], [29, 30], [0, 60]]) for (const a of [0n, 1n, A / 3n, A / 2n, A - 1n, A, A + 1n, -1n]) {
  await o.run('cdfRecNumerator', nm(), (nn: number, kk: number, aa: any) => B(cdfRecNumerator(nn, kk, bi(aa))), [nn, k, B(a)]);
  for (const al of [0.05, 0.5, 1e-9]) await o.run('cdfExceeds', nm(), (nn: number, kk: number, aa: any, d: any) => cdfExceeds(nn, kk, bi(aa), { num: bi(d.num), exp: d.exp }), [nn, k, B(a), (() => { const d = doubleToDyadic(al); return { num: B(d.num), exp: d.exp }; })()]);
}

for (const rg of [0, 1, 0.5, 3.7, 1e-9, 100]) for (const m of [1, 2, 10, 20000, 0, -1]) for (const d of [undefined, 0.05, 0.01, 0.5]) await o.run('hoeffdingHalfWidth', nm(), hoeffdingHalfWidth, d === undefined ? [rg, m] : [rg, m, d]);
for (const [k, nn] of [[0, 1], [1, 1], [0, 10], [5, 10], [10, 10], [3, 7], [50, 100], [1, 1000], [999, 1000], [0, 0], [3, -2]]) for (const z of [undefined, 1.96, 2.576, 0, 1]) await o.run('wilsonInterval', nm(), wilsonInterval, z === undefined ? [k, nn] : [k, nn, z]);
refWrite(o, 'intent-stats');
