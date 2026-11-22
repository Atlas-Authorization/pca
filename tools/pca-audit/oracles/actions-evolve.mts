// Oracle: @atlasauth/pca-actions evolve.ts. Writes out/ref-actions-evolve.json.gz.
// PORTING table (regs are the core registry; the signing key is an Ed25519 seed passed as {$bytes})
//   evolutionRecords(ns, prev[], next[], confirmed)             -> ActionEvolve.evolutionRecords(ns, prev, next, CORE, d -> confirmed); a throw (duplicate_def) must throw
//   signEvolution(records[], kid, {$bytes: seed})               -> ActionEvolve.signEvolution (Ed25519, deterministic)
//   evolutionError(ns, prev[], next[], records[], keys[], confirmed) -> ActionEvolve.evolutionError (null = consistent)
import * as B0 from '../../../packages/pca-actions/src/builtin.ts';
import * as DM0 from '../../../packages/pca-actions/src/domain.ts';
import * as EV0 from '../../../packages/pca-actions/src/evolve.ts';
import * as V0 from '../../../packages/pca-actions/src/validate.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, clone, seed, variants } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const BI = un(B0), DM = un(DM0), EV = un(EV0), V = un(V0), CT = un(CT0);
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const CORE = CT.CORE_REGISTRY;
const o = new Oracle('actions-evolve', 'tools/pca-audit/oracles/actions-evolve.mts', 'TS-reference oracle for pca-actions evolution records.');
const ALL: any[] = [...BI.BUILTIN_DEFS, ...DM.DOMAIN_DEFS].map((d: any) => clone(d));
const opt = (c: boolean) => ({ attestationVerified: () => c });
const SK = seed('ref-actions-evolve/registry'), SK2 = seed('ref-actions-evolve/other');
const bytes = (u: Uint8Array) => ({ $bytes: P.b64u(u) });
const KEYS = [{ kid: 'reg1', alg: 'ed25519', pk: P.b64u(P.publicKeyOf(SK)) }];
const OTHER = [{ kid: 'reg1', alg: 'ed25519', pk: P.b64u(P.publicKeyOf(SK2)) }];
const ER = (n: string, ns: string, a: any, b: any, recs: any, keys: any = KEYS, c = false) => o.run('evolutionError', n, (x: string, p: any, q: any, r: any, k: any, cc: any) => EV.evolutionError(x, p, q, r, k, CORE, opt(cc)), [ns, a, b, recs, keys, c]);
const REC = (a: any, b: any, c = false) => EV.evolutionRecords('acme', a, b, CORE, opt(c));
const SIGN = (recs: any) => EV.signEvolution(recs, 'reg1', SK);

const mut = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };
const PREV = ALL.slice(0, 6);
const NEXTS: [string, any[]][] = [
  ['same', clone(PREV)], ['title', PREV.map((d, i) => (i === 0 ? mut(d, (x) => (x.title = 'Renamed title')) : d))], ['added', [...PREV, ALL[6]]], ['removed', PREV.slice(1)], ['swap', [...PREV.slice(1), ALL[7]]],
  ['blast', PREV.map((d, i) => (i === 1 ? mut(d, (x) => (x.blast = { radius: 'global', ppm: 1_000_000 })) : d))], ['empty', []],
  ['effects widen', PREV.map((d, i) => (i === 2 ? mut(d, (x) => (x.effects = [...new Set([...x.effects, 'delete'])])) : d))],
];
for (const [n, next] of NEXTS) {
  for (const c of [false, true]) await o.run('evolutionRecords', `${n} ${c}`, (x: string, p: any, q: any, cc: any) => EV.evolutionRecords(x, p, q, CORE, opt(cc)), ['acme', PREV, next, c]);
  const recs = REC(PREV, next);
  await o.run('signEvolution', n, (r: any, k: any, s: any) => EV.signEvolution(r, k, Uint8Array.from(Buffer.from(s.$bytes, 'base64url'))), [recs, 'reg1', bytes(SK)]);
  const signed = SIGN(recs);
  await ER(`${n} ok`, 'acme', PREV, next, signed);
  await ER(`${n} wrong ns`, 'other', PREV, next, signed);
  await ER(`${n} wrong key`, 'acme', PREV, next, signed, OTHER);
  await ER(`${n} no keys`, 'acme', PREV, next, signed, []);
  if (signed.length > 0) {
    await ER(`${n} missing record`, 'acme', PREV, next, signed.slice(1));
    await ER(`${n} extra record`, 'acme', PREV, next, [...signed, signed[0]]);
    await ER(`${n} misclassified`, 'acme', PREV, next, SIGN(recs.map((r: any, i: number) => (i === 0 && r.class !== 'added' && r.class !== 'removed' ? { ...r, class: r.class === 'narrow' ? 'widen' : 'narrow' } : r))));
    await ER(`${n} tampered`, 'acme', PREV, next, signed.map((r: any, i: number) => (i === 0 ? { ...r, reasons: [...r.reasons, 'extra'] } : r)));
    await ER(`${n} unsigned`, 'acme', PREV, next, recs);
    await ER(`${n} bad sig`, 'acme', PREV, next, signed.map((r: any, i: number) => (i === 0 ? { ...r, sig: { ...r.sig, value: 'A'.repeat(86) } } : r)));
  }
}
await o.run('evolutionRecords', 'duplicate prev', (x: string, p: any, q: any, cc: any) => EV.evolutionRecords(x, p, q, CORE, opt(cc)), ['acme', [ALL[0], ALL[0]], PREV, false]);
await o.run('evolutionRecords', 'duplicate next', (x: string, p: any, q: any, cc: any) => EV.evolutionRecords(x, p, q, CORE, opt(cc)), ['acme', PREV, [ALL[0], ALL[0]], false]);
await o.run('evolutionRecords', 'bad ns', (x: string, p: any, q: any, cc: any) => EV.evolutionRecords(x, p, q, CORE, opt(cc)), ['Not A Ns', PREV, [...PREV, ALL[6]], false]);
await o.run('signEvolution', 'bad ns record', (r: any, k: any, s: any) => EV.signEvolution(r, k, Uint8Array.from(Buffer.from(s.$bytes, 'base64url'))), [EV.evolutionRecords('Bad Ns', PREV, [...PREV, ALL[6]], CORE, {}), 'reg1', bytes(SK)]);
// valid structural variants of one def as the "next" version
let n = 0;
for (const [lbl, v] of variants(ALL[0], { maxPaths: 150, hostile: [null, 0, 1, '', 'x', [], {}, true] })) {
  let ok = false; try { ok = V.validateDef(v) === null && v.verb === ALL[0].verb; } catch { ok = false; }
  if (!ok || n++ > 60) continue;
  await o.run('evolutionRecords', `v ${lbl}`, (x: string, p: any, q: any, cc: any) => EV.evolutionRecords(x, p, q, CORE, opt(cc)), ['acme', [ALL[0]], [v], false]);
}
refWrite(o, 'actions-evolve');
