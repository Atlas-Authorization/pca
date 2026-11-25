// Oracle: @atlasauth/pca-ratchet (puncturable capability ratchet, Pedersen risk accumulator on ristretto255, adapters, verifier bindings).
// The provers draw fresh randomness, so a proof is NOT comparable byte for byte: the corpus records proofs the reference produced (valid,
// out of range, over budget) and tampered copies, and a native must reach the same verdict. Deterministic functions are compared exactly.
// Bytes travel as {"$bytes": b64url}, bigints as {"$bigint": decimal}. Run-time cost of a verification is dominated by group arithmetic, so the
// valid-proof cases are kept to a few dozen.
// PORTING (fn(args) -> native entry point, comparison rule; everything compared by JSON value):
//   leafNullifier(root, leafIndex)                 -> Ratchet.leafNullifier
//   counterToLeafIndex(counter, depth) / leafIndexToCounter(i) / leafIndexForAction({counter}, depth) -> Adapters (a throw carries a code)
//   riskToUnits(r) / budgetCeilingUnits(policy)    -> Adapters (bigint result as {$bigint})
//   quantizer(rs)                                  -> a fresh RiskQuantizer: [for each r: next(r) as {$bigint}, or {$err: true}], then totalUnits as {$bigint}
//   ratchet(spec)                                  -> scenario over a ratchet: spec = {store?: 'mem'|'throws', ops: [step...]}; a step is {op, ...}:
//        derive{seed,depth} (state := deriveRatchetRoot; the signature list is NOT reset; result {root, leafPubKeys[], available[]}), sign{leaf,msg} (result {signature}),
//        avail, isAvail{leaf}, verify{root?:'good'|'other', leaf, msg, sigRef (index of the step that signed), set?:[[path,value]...]},
//        once{same as verify}: verifyLeafSignatureOnce over the scenario's spent-leaf store. A throw is {"$err": code|true}.
//   commitRisk(risk, blinding)                     -> Accumulator.commitRisk; result {commitment, blinding as {$bigint}}
//   addCommitments(list) / openCommitment(c, risk, blinding) / verifyRiskRange(c, proof) / verifyBudget(sum, bMax, proof)
//   verifyBoundedBudget(cs, rangeProofs, bMax, budgetProof) -> Accumulator (verdict: boolean)
//   proveBudget / proveRiskRange / issueRiskCommitment     -> only their refusals are recorded ({$throws, code}); a native must throw the same code
//   verifyRiskAttestation(commitment, attestation, authorityPublicKey) / verifyAttestedBudget(items, digests, authorityPublicKey, bMax, proof) -> Binding
import * as R0 from '@atlasauth/pca-ratchet';
import * as C0 from '@atlasauth/pca';
import { Oracle, refWrite, seed, rng } from './lib.mjs';

const R: any = (R0 as any).default ?? R0;
const C: any = (C0 as any).default ?? C0;
const { encodeKey, publicKeyOf } = C;
const o = new Oracle('ratchet', 'tools/pca-audit/oracles/ratchet.mts', 'TS-reference oracle for @atlasauth/pca-ratchet.');
const b64 = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
const revive = (x: any): any => {
  if (Array.isArray(x)) return x.map(revive);
  if (x !== null && typeof x === 'object') {
    const k = Object.keys(x);
    if (k.length === 1 && k[0] === '$bytes') return new Uint8Array(Buffer.from(x.$bytes, 'base64url'));
    if (k.length === 1 && k[0] === '$bigint') return BigInt(x.$bigint);
    return Object.fromEntries(k.map((key) => [key, revive(x[key])]));
  }
  return x;
};
const J = (x: any) => JSON.parse(JSON.stringify(x, (_k, v) => (typeof v === 'bigint' ? { $bigint: v.toString() } : v instanceof Uint8Array ? { $bytes: Buffer.from(v).toString('base64url') } : v)));
const big = (n: bigint | number) => ({ $bigint: String(n) });
let n = 0;
const run = (fn: string, name: string, ref: (...a: any[]) => any, args: any[]) => o.run(fn, `${name}#${n++}`, (...a: any[]) => ref(...revive(a)), args);
const throwsOnly = async (fn: string, name: string, ref: (...a: any[]) => any, args: any[]) => {
  try { await ref(...revive(JSON.parse(JSON.stringify(args)))); } catch { await run(fn, name, ref, args); }
};
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

// ---- deterministic functions ---------------------------------------------------------------------------------------------
const roots = ['', 'x', 'root-commitment-0123456789', 'café', 'a'.repeat(300)];
const idxs: any[] = [0, 1, 7, 255, 65535, 2 ** 20, 2 ** 31, 2 ** 32, 2 ** 53 - 1, 2 ** 53, -1, -0, 1.5, 1e21, '1', null, true];
for (const r of roots) for (const i of idxs) await run('leafNullifier', `${JSON.stringify(r).slice(0, 12)}/${Object.is(i, -0) ? 'neg0' : JSON.stringify(i)}`, R.leafNullifier, [r, i]);

const counters: any[] = [0, 1, 5, 7, 8, 2 ** 10 - 1, 2 ** 10, 2 ** 20 - 1, 2 ** 20, 2 ** 53 - 1, 2 ** 53, -1, -0, 1.5, 1e21, '5', null, true, [], {}];
for (const d of [1, 3, 10, 20, 0, 21, -1, 1.5, '3', null, 2 ** 53]) for (const c of counters) await run('counterToLeafIndex', `${JSON.stringify(c)}${Object.is(c, -0) ? 'neg0' : ''}/${JSON.stringify(d)}`, R.counterToLeafIndex, [c, d]);
for (const c of counters) await run('leafIndexToCounter', `${JSON.stringify(c)}${Object.is(c, -0) ? 'neg0' : ''}`, R.leafIndexToCounter, [c]);
for (const a of [{ counter: 3 }, { counter: 3, extra: 1 }, { counter: -1 }, { counter: 1.5 }, { counter: 'x' }, {}, null, { counter: 2 ** 20 }, { counter: 2 ** 20 - 1 }]) for (const d of [3, 20, 4]) await run('leafIndexForAction', `${JSON.stringify(a)}/${d}`, R.leafIndexForAction, [a, d]);

const rs: any[] = [0, 0.001, 0.0003, 0.0005, 0.0007, 0.3, 0.29999999999999999, 0.1 + 0.2, 0.5, 0.9999, 1, 1.0000001, 12.345, 1e-12, 1e-9, 1e6, 1e15, 1e300, 1e306, 2 ** 53 / 1000, -0, -1, -1e-9, 0.123456789, 0.7, 0.35, 4.35, 8.2, '1', null, true, [], 1e21];
for (const r of rs) await run('riskToUnits', `${JSON.stringify(r)}${Object.is(r, -0) ? 'neg0' : ''}`, R.riskToUnits, [r]);
{
  const g = rng(7);
  for (let i = 0; i < 150; i++) await run('riskToUnits', `gen${i}`, R.riskToUnits, [i % 3 === 0 ? g.int(0, 2000) / 1000 : i % 3 === 1 ? g.next() * 2 : g.int(0, 1000) / 1000 + g.next() * 1e-9]);
}
const pols: any[] = [{ kappa: 100, bMax: 1000 }, { kappa: 3, bMax: 10 }, { kappa: 0.3, bMax: 0.9 }, { kappa: 1, bMax: 0 }, { kappa: 0, bMax: 100 }, { kappa: -1, bMax: 100 }, { kappa: 1, bMax: -5 }, { kappa: 1e-300, bMax: 1 }, { kappa: 7, bMax: 123456.789 },
  { kappa: 1, bMax: 1e12 }, { kappa: 1, bMax: null }, { kappa: null, bMax: 5 }, {}, { kappa: 1 }, { bMax: 1 }, { kappa: 'x', bMax: 1 }, { kappa: 5, bMax: 'y' }, null, { kappa: 2, bMax: 2 ** 40 }, { kappa: 1e-7, bMax: 1e-7 }, { kappa: 0.1, bMax: 0.3 }, { kappa: 3, bMax: 1 }];
for (const [i, p] of pols.entries()) await run('budgetCeilingUnits', `${i}`, R.budgetCeilingUnits, [p]);
const quant = (list: any[]) => {
  const q = new R.RiskQuantizer();
  const out: any[] = [];
  for (const r of list) { try { out.push(q.next(r)); } catch { out.push({ $err: true }); } }
  out.push(q.totalUnits);
  return out;
};
const qlists: any[][] = [[], [0], [0.0004, 0.0004, 0.0004], [0.1, 0.2, 0.3], [0.0001, 0.0001, 0.0001, 0.0001, 0.0001, 0.0001, 0.0001, 0.0001, 0.0001, 0.0001], [1, 1, 1], [0.0005, 0.0005], [-1, 0.5, 'x', 0.5, null, 0.25], [0.3333333333333333, 0.3333333333333333, 0.3333333333333334], [1e-12, 1e-12, 1e-12], [0.7, 0.7, 0.7, 0.7], [2 ** 53 / 1000, 1]];
{
  const g = rng(11);
  for (let i = 0; i < 12; i++) qlists.push(Array.from({ length: 30 }, () => (g.int(0, 3) === 0 ? 0 : g.next() / 50)));
}
for (const [i, l] of qlists.entries()) await run('quantizer', `${i}`, quant, [l]);

// ---- ratchet scenarios -----------------------------------------------------------------------------------------------------------
const SEED = seed('ratchet-a');
const SEED2 = seed('ratchet-b');
const enc = (s: string) => new Uint8Array(Buffer.from(s, 'utf8'));
const clonePath = (v: any, path: any[], value: any) => {
  const c = JSON.parse(JSON.stringify(v));
  let t = c;
  for (const k of path.slice(0, -1)) t = t?.[k];
  if (t !== undefined && t !== null) { if (value === '__DEL__') delete t[path[path.length - 1]]; else t[path[path.length - 1]] = value; }
  return c;
};
async function scenarioAsync(spec: any) {
  let state: any;
  let root: string | undefined;
  const sigs: any[] = [];
  const seen = new Map<string, string>();
  const store: any = spec.store === 'throws' ? { claim() { throw new Error('boom'); } } : { claim(nul: string, rec: string) { const p = seen.get(nul); if (p !== undefined) return { first: false, record: p }; seen.set(nul, rec); return { first: true }; } };
  const out: any[] = [];
  for (const s of spec.ops) {
    try {
      switch (s.op) {
        case 'derive': { const d = R.deriveRatchetRoot(s.seed, s.depth); state = d.state; root = d.rootCommitment; out.push({ root: d.rootCommitment, leafPubKeys: d.state.leafPubKeys, available: R.availableLeaves(d.state) }); break; }
        case 'sign': { const r = R.signAtLeaf(state, s.leaf, s.msg); state = r.newState; sigs.push(r.signature); out.push({ signature: r.signature }); break; }
        case 'avail': out.push(R.availableLeaves(state)); break;
        case 'isAvail': out.push(R.isLeafAvailable(state, s.leaf)); break;
        case 'verify':
        case 'once': {
          let sig = sigs[s.sigRef];
          for (const [p, v] of s.set ?? []) sig = clonePath(sig, p, v);
          const rc = s.root === 'other' ? 'other-root' : root;
          out.push(s.op === 'verify' ? R.verifyLeafSignature(rc, s.leaf, s.msg, sig) : await R.verifyLeafSignatureOnce(rc, s.leaf, s.msg, sig, store));
          break;
        }
        default: throw new Error('bad op');
      }
    } catch (e: any) {
      out.push({ $err: typeof e?.code === 'string' ? e.code : true });
    }
  }
  return out;
}
const sc = (name: string, spec: any) => run('ratchet', name, scenarioAsync, [spec]);
const M1 = b64(enc('m1')), M2 = b64(enc('m2'));
const D3 = { op: 'derive', seed: b64(SEED), depth: 3 };
await sc('derive/3', { ops: [D3] });
await sc('derive/1', { ops: [{ op: 'derive', seed: b64(SEED), depth: 1 }] });
await sc('derive/6', { ops: [{ op: 'derive', seed: b64(SEED2), depth: 6 }, { op: 'sign', leaf: 37, msg: M1 }, { op: 'avail' }, { op: 'isAvail', leaf: 37 }, { op: 'isAvail', leaf: 36 }, { op: 'sign', leaf: 36, msg: M2 }, { op: 'sign', leaf: 0, msg: M1 }, { op: 'sign', leaf: 63, msg: M1 }, { op: 'avail' }, { op: 'verify', sigRef: 0, leaf: 37, msg: M1 }, { op: 'verify', sigRef: 3, leaf: 63, msg: M1 }] });
await sc('derive/10', { ops: [{ op: 'derive', seed: b64(SEED), depth: 10 }, { op: 'sign', leaf: 1000, msg: M1 }, { op: 'sign', leaf: 3, msg: M1 }, { op: 'avail' }, { op: 'verify', sigRef: 1, leaf: 3, msg: M1 }] });
for (const [i, d] of [0, 21, -1, 1.5, '3', null, 2 ** 53, 1e9].entries()) await sc(`derive/baddepth/${i}`, { ops: [{ op: 'derive', seed: b64(SEED), depth: d }] });
for (const [i, s] of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(32), new Uint8Array(33), new Uint8Array(64), 'str', null, [1, 2]].entries()) await sc(`derive/badseed/${i}`, { ops: [{ op: 'derive', seed: s instanceof Uint8Array ? b64(s) : s, depth: 2 }] });
await sc('derive/seed-prefix', { ops: [{ op: 'derive', seed: b64(new Uint8Array(40).fill(7)), depth: 2 }, { op: 'derive', seed: b64(new Uint8Array(32).fill(7)), depth: 2 }] });
// every leaf of a depth-3 tree, in several orders: puncture bookkeeping
for (const [name, order] of Object.entries({ asc: [0, 1, 2, 3, 4, 5, 6, 7], desc: [7, 6, 5, 4, 3, 2, 1, 0], mid: [3, 4, 2, 5, 1, 6, 0, 7], sparse: [5, 2, 7] })) {
  const ops: any[] = [D3];
  for (const l of order) { ops.push({ op: 'sign', leaf: l, msg: M1 }, { op: 'avail' }, { op: 'isAvail', leaf: l }); }
  ops.push({ op: 'sign', leaf: order[0], msg: M2 });
  await sc(`order/${name}`, { ops });
}
const badLeaves: any[] = [-1, 8, 100, 1.5, -0, 2 ** 53, '1', null, true];
for (const [i, l] of badLeaves.entries()) await sc(`sign/badleaf/${i}`, { ops: [D3, { op: 'sign', leaf: l, msg: M1 }, ...(typeof l === 'number' ? [{ op: 'isAvail', leaf: l }] : []), { op: 'avail' }] });
for (const l of [0.5, 1.5, 7.9, 8, 8.5, -0.5, 1e-9, 7.999999]) await sc(`isAvail/frac/${l}`, { ops: [D3, { op: 'isAvail', leaf: l }, { op: 'sign', leaf: 0, msg: M1 }, { op: 'isAvail', leaf: l }, { op: 'sign', leaf: 7, msg: M1 }, { op: 'isAvail', leaf: l }] });
await sc('sign/before-derive', { ops: [{ op: 'sign', leaf: 0, msg: M1 }] });
for (const [i, m] of [new Uint8Array(0), enc('m1'), enc('café'), new Uint8Array(1000).fill(9)].entries()) await sc(`sign/msg/${i}`, { ops: [D3, { op: 'sign', leaf: 2, msg: b64(m) }, { op: 'verify', sigRef: 0, leaf: 2, msg: b64(m) }, { op: 'verify', sigRef: 0, leaf: 2, msg: M2 }] });
// verification variants
const V = (extra: any) => ({ op: 'verify', sigRef: 0, leaf: 2, msg: M1, ...extra });
const mutations: any[] = [
  {}, { root: 'other' }, { leaf: 3 }, { leaf: 1 }, { leaf: -1 }, { leaf: 1.5 }, { leaf: 2 ** 53 }, { msg: M2 },
  { set: [[['edSig'], 'AAAA']] }, { set: [[['edSig'], 5]] }, { set: [[['edSig'], '__DEL__']] }, { set: [[['leafPubKey'], 'AAAA']] }, { set: [[['leafPubKey'], '__DEL__']] },
  { set: [[['nullifier'], 'x']] }, { set: [[['nullifier'], '__DEL__']] }, { set: [[['nullifier'], 5]] },
  { set: [[['merklePath'], null]] }, { set: [[['merklePath'], 'x']] }, { set: [[['merklePath'], []]] }, { set: [[['merklePath'], '__DEL__']] },
  { set: [[['merklePath', 'index'], 3]] }, { set: [[['merklePath', 'index'], '2']] }, { set: [[['merklePath', 'index'], 2.0000001]] }, { set: [[['merklePath', 'size'], 7]] }, { set: [[['merklePath', 'size'], 16]] },
  { set: [[['merklePath', 'path'], []]] }, { set: [[['merklePath', 'path'], 'x']] }, { set: [[['merklePath', 'path', 0, 'side'], 'L']] }, { set: [[['merklePath', 'path', 0, 'hash'], 'AAAA']] }, { set: [[['merklePath', 'hash_suite'], 'sha384']] },
  { set: [[['merklePath', 'hash_suite'], 'sha256']] }, { set: [[['extra'], 1]] },
  { set: [[[], null]] }, { set: [[[], 'x']] }, { set: [[[], []]] }, { set: [[[], 5]] },
];
for (const [i, m] of mutations.entries()) await sc(`verify/${i}`, { ops: [D3, { op: 'sign', leaf: 2, msg: M1 }, V(m)] });
// signature from another tree / another leaf
await sc('verify/other-tree', { ops: [D3, { op: 'sign', leaf: 2, msg: M1 }, { op: 'derive', seed: b64(SEED2), depth: 3 }, V({})] });
// spent-leaf store: first / replay / equivocation / invalid / store error
const ONCE = (extra: any) => ({ op: 'once', sigRef: 0, leaf: 2, msg: M1, ...extra });
await sc('once/first-replay', { ops: [D3, { op: 'sign', leaf: 2, msg: M1 }, ONCE({}), ONCE({}), ONCE({})] });
await sc('once/equivocation', { ops: [D3, { op: 'sign', leaf: 2, msg: M1 }, { op: 'derive', seed: b64(SEED), depth: 3 }, { op: 'sign', leaf: 2, msg: M2 }, ONCE({}), ONCE({ sigRef: 1, msg: M2 }), ONCE({ sigRef: 1, msg: M2 })] });
await sc('once/invalid', { ops: [D3, { op: 'sign', leaf: 2, msg: M1 }, ONCE({ msg: M2 }), ONCE({ leaf: 3 }), ONCE({ set: [[['nullifier'], 'x']] }), ONCE({})] });
await sc('once/two-leaves', { ops: [D3, { op: 'sign', leaf: 2, msg: M1 }, { op: 'sign', leaf: 5, msg: M1 }, ONCE({}), ONCE({ sigRef: 1, leaf: 5 }), ONCE({}), ONCE({ sigRef: 1, leaf: 5 })] });
await sc('once/store-throws', { store: 'throws', ops: [D3, { op: 'sign', leaf: 2, msg: M1 }, ONCE({}), ONCE({ msg: M2 })] });
await sc('once/empty-msg', { ops: [D3, { op: 'sign', leaf: 1, msg: b64(new Uint8Array(0)) }, ONCE({ leaf: 1, msg: b64(new Uint8Array(0)) }), ONCE({ leaf: 1, msg: b64(new Uint8Array(0)) })] });

// ---- accumulator -----------------------------------------------------------------------------------------------------------------------
const risksIn: any[] = [0, 1, 5, 999, 2 ** 32 - 1, 2 ** 32, 2 ** 53 - 1, 2 ** 53, 1e21, big(7), big(0), big(2n ** 64n), big(-1), -1, 1.5, '1', null, true, [], -0, 0.5];
const blindsIn: any[] = [big(0), big(1), big(12345), big(L - 1n), big(L), big(L + 1n), big(2n ** 300n), big(-1), big(-L), 5, null, '5'];
for (const [i, r] of risksIn.entries()) for (const [j, b] of blindsIn.entries()) if ((i + j) % 2 === 0 || j < 4) await run('commitRisk', `${i}/${j}`, R.commitRisk, [r, b]);
const mk = (risk: any, blinding: bigint) => R.commitRisk(risk, blinding).commitment;
const ccs = [mk(1, 11n), mk(2, 22n), mk(3, 33n), mk(0, 0n), mk(5, 7n)];
const refPoints = [ccs[0], ...['', 'x', 'AAAA', 'A'.repeat(43), 'A'.repeat(44), '_'.repeat(43), ccs[0] + '=', ccs[0].slice(0, 42), ccs[0] + 'A', 5, null, []] as any[]];
await run('addCommitments', 'empty', R.addCommitments, [[]]);
for (const [i, l] of [[ccs[0]], [ccs[0], ccs[1]], [ccs[1], ccs[0]], ccs, [ccs[0], ccs[0]], [ccs[3]], [ccs[0], 'x'], [ccs[0], null], 'x', null, [ccs[0], refPoints[2]], [refPoints[8]], ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA']].entries()) await run('addCommitments', `${i}`, R.addCommitments, [l]);
for (const p of refPoints) await run('addCommitments', `pt/${JSON.stringify(p)}`, R.addCommitments, [[p]]);
// ristretto decoding corner cases: negative (odd) encodings, the identity, non-canonical s >= p
const rawPoints = [new Uint8Array(32), (() => { const u = new Uint8Array(32); u[0] = 1; return u; })(), (() => { const u = new Uint8Array(32); u.fill(0xff); return u; })(), (() => { const u = new Uint8Array(32); u[0] = 2; return u; })(), (() => { const u = new Uint8Array(32); u[0] = 0xed; u.fill(0xff, 1); u[31] = 0x7f; return u; })(), (() => { const u = new Uint8Array(32); u[0] = 0xec; u.fill(0xff, 1); u[31] = 0x7f; return u; })()];
for (const [i, u] of rawPoints.entries()) await run('addCommitments', `raw/${i}`, R.addCommitments, [[Buffer.from(u).toString('base64url')]]);
{
  const g = rng(3);
  for (let i = 0; i < 40; i++) { const u = new Uint8Array(32); for (let k = 0; k < 32; k++) u[k] = g.int(0, 255); u[31] &= 0x7f; u[0] &= 0xfe; await run('addCommitments', `rnd/${i}`, R.addCommitments, [[Buffer.from(u).toString('base64url')]]); }
}
for (const [i, [c, r, b]] of ([[ccs[0], 1, big(11)], [ccs[0], 1, big(12)], [ccs[0], 2, big(11)], [ccs[1], 2, big(22)], [ccs[3], 0, big(0)], [ccs[3], 0, big(L)], [ccs[0], 1, big(11n + L)], [ccs[0], 1, big(11n - L)], [ccs[0], -1, big(11)], [ccs[0], 1.5, big(11)], [ccs[0], '1', big(11)], [ccs[0], 1, 11], [ccs[0], 1, null],
  ['x', 1, big(11)], [null, 1, big(11)], [ccs[0], big(1), big(11)], [ccs[0], 2 ** 53, big(11)], [mk(2 ** 32, 5n), 2 ** 32, big(5)], [mk(2n ** 70n as any, 5n), big(2n ** 70n), big(5)], [ccs[4], 5, big(7)]] as any[]).entries()) await run('openCommitment', `${i}`, R.openCommitment, [c, r, b]);

// proofs the reference produces (random): kept as recorded vectors
const rr = (risk: bigint | number, b: bigint) => R.proveRiskRange(risk, b);
const rangeProofs: Record<string, any> = { r0: [mk(0, 5n), rr(0, 5n)], r1: [mk(1, 11n), rr(1, 11n)], r7: [mk(7, 9n), rr(7, 9n)], rmax: [mk(2 ** 32 - 1, 3n), rr(2 ** 32 - 1, 3n)], rbig: [mk(2 ** 32, 4n), rr(2 ** 32, 4n)], rwrapped: [mk(2n ** 40n as any, 4n), rr(2n ** 40n, 4n)] };
for (const [k, [c, p]] of Object.entries(rangeProofs)) await run('verifyRiskRange', `proof/${k}`, R.verifyRiskRange, [c, J(p)]);
const rp1 = J(rangeProofs.r1[1]);
const flip = (s: string) => s.slice(0, 5) + (s[5] === 'A' ? 'B' : 'A') + s.slice(6);
const L_B64 = (v: bigint) => { const u = new Uint8Array(32); let x = v; for (let i = 0; i < 32; i++) { u[i] = Number(x & 0xffn); x >>= 8n; } return Buffer.from(u).toString('base64url'); };
const tamper: [string, (p: any) => any][] = [
  ['bit0 e0', (p) => { p.or[0].e0 = flip(p.or[0].e0); return p; }], ['bit31 z1', (p) => { p.or[31].z1 = flip(p.or[31].z1); return p; }], ['bit5 e1', (p) => { p.or[5].e1 = flip(p.or[5].e1); return p; }],
  ['bitCommitment3', (p) => { p.bitCommitments[3] = rp1.bitCommitments[4]; return p; }], ['agg.a', (p) => { p.agg.a = flip(p.agg.a); return p; }], ['agg.z', (p) => { p.agg.z = flip(p.agg.z); return p; }],
  ['n=31', (p) => { p.n = 31; return p; }], ['n=33', (p) => { p.n = 33; return p; }], ['n string', (p) => { p.n = '32'; return p; }], ['drop commitment', (p) => { p.bitCommitments.pop(); return p; }], ['drop or', (p) => { p.or.pop(); return p; }],
  ['extra or', (p) => { p.or.push(p.or[0]); return p; }], ['swap or', (p) => { [p.or[0], p.or[1]] = [p.or[1], p.or[0]]; return p; }], ['swap bits', (p) => { [p.bitCommitments[0], p.bitCommitments[1]] = [p.bitCommitments[1], p.bitCommitments[0]]; return p; }],
  ['null agg', (p) => { p.agg = null; return p; }], ['no agg', (p) => { delete p.agg; return p; }], ['agg array', (p) => { p.agg = []; return p; }], ['or null', (p) => { p.or = null; return p; }], ['or[0] null', (p) => { p.or[0] = null; return p; }],
  ['or[0] string', (p) => { p.or[0] = 'x'; return p; }], ['or[0] empty', (p) => { p.or[0] = {}; return p; }], ['z0 non-canonical', (p) => { p.or[0].z0 = L_B64(L + 1n); return p; }], ['z0 = L', (p) => { p.or[0].z0 = L_B64(L); return p; }],
  ['agg.z non-canonical', (p) => { p.agg.z = L_B64(L + 1n); return p; }], ['agg.z padded', (p) => { p.agg.z += '='; return p; }], ['bit commitment identity', (p) => { p.bitCommitments[0] = Buffer.alloc(32).toString('base64url'); return p; }], ['bit commitment junk', (p) => { p.bitCommitments[0] = 'x'; return p; }],
  ['proof null', () => null], ['proof string', () => 'x'], ['proof array', () => []], ['proof empty', () => ({})], ['proof number', () => 5], ['unknown member', (p) => { p.zz = 1; return p; }],
];
for (const [name, f] of tamper) await run('verifyRiskRange', `tamper/${name}`, R.verifyRiskRange, [rangeProofs.r1[0], f(JSON.parse(JSON.stringify(rp1)))]);
for (const [name, c] of [['other commitment', ccs[1]], ['sum', ccs[2]], ['junk', 'x'], ['null', null], ['identity', Buffer.alloc(32).toString('base64url')]] as any[]) await run('verifyRiskRange', `commitment/${name}`, R.verifyRiskRange, [c, rp1]);
// range proof against a commitment that does not match its blinding / value
await run('verifyRiskRange', 'mismatch/value', R.verifyRiskRange, [mk(2, 11n), rp1]);
await run('verifyRiskRange', 'mismatch/blinding', R.verifyRiskRange, [mk(1, 12n), rp1]);
await run('verifyRiskRange', 'budget-as-range', R.verifyRiskRange, [R.addCommitments([mk(1, 2n)]), J(R.proveBudget([1], [2n], 5))]);

// budget proofs
const bp = (risks: number[], blinds: bigint[], bMax: any) => J(R.proveBudget(risks, blinds, bMax));
const sumOf = (risks: number[], blinds: bigint[]) => R.addCommitments(risks.map((r, i) => mk(r, blinds[i]!)));
const budgets: Record<string, { risks: number[]; blinds: bigint[]; prove: any; verify: any }> = {
  ok: { risks: [3, 4], blinds: [5n, 6n], prove: 10, verify: 10 }, exact: { risks: [3, 4], blinds: [5n, 6n], prove: 7, verify: 7 }, over1: { risks: [3, 4], blinds: [5n, 6n], prove: 6, verify: 6 }, empty: { risks: [], blinds: [], prove: 0, verify: 0 },
  zero: { risks: [0], blinds: [9n], prove: 0, verify: 0 }, huge: { risks: [100], blinds: [7n], prove: 2 ** 40, verify: 2 ** 40 }, hugeClamp: { risks: [100], blinds: [7n], prove: 2 ** 32 + 5, verify: 2 ** 32 + 5 },
  hugeClamp2: { risks: [100], blinds: [7n], prove: 2 ** 32 - 1, verify: 2 ** 40 }, maxCeil: { risks: [2 ** 32 - 1], blinds: [3n], prove: 2 ** 32 - 1, verify: 2 ** 32 - 1 }, wrongBMax: { risks: [3, 4], blinds: [5n, 6n], prove: 10, verify: 11 },
  wrongBMax2: { risks: [3, 4], blinds: [5n, 6n], prove: 10, verify: 9 }, bigBlind: { risks: [1], blinds: [L - 1n], prove: 3, verify: 3 }, three: { risks: [1, 2, 3], blinds: [1n, 2n, 3n], prove: 100, verify: 100 },
};
const budgetProofs: Record<string, any> = {};
for (const [k, b] of Object.entries(budgets)) {
  budgetProofs[k] = bp(b.risks, b.blinds, b.prove);
  await run('verifyBudget', `proof/${k}`, R.verifyBudget, [sumOf(b.risks, b.blinds), b.verify, budgetProofs[k]]);
}
const okSum = sumOf([3, 4], [5n, 6n]);
const bpOk = budgetProofs.ok;
const btamper: [string, (p: any) => any][] = [tamper[0]!, tamper[4]!, tamper[5]!, tamper[6]!, tamper[9]!, tamper[14]!, tamper[19]!, tamper[22]!, tamper[26]!, tamper[28]!, tamper[29]!, tamper[30]!, tamper[31]!, tamper[32]!];
for (const [name, f] of btamper) await run('verifyBudget', `tamper/${name}`, R.verifyBudget, [okSum, 10, f(JSON.parse(JSON.stringify(bpOk)))]);
for (const [i, a] of ([[sumOf([3, 5], [5n, 6n]), 10], [sumOf([3, 4], [5n, 7n]), 10], [ccs[0], 10], ['x', 10], [null, 10], [okSum, -1], [okSum, 1.5], [okSum, '10'], [okSum, null], [okSum, big(10)], [okSum, 2 ** 53], [okSum, 1e21], [okSum, 0], [okSum, 7], [okSum, 11]] as any[]).entries())
  await run('verifyBudget', `args/${i}`, R.verifyBudget, [a[0], a[1], bpOk]);
await run('verifyBudget', 'range-as-budget', R.verifyBudget, [rangeProofs.r1[0], 5, rp1]);

// bounded budgets (range proofs for every addend + budget proof for the sum)
const rps = (risks: number[], blinds: bigint[]) => risks.map((r, i) => J(rr(r, blinds[i]!)));
const bb = (name: string, risks: number[], blinds: bigint[], bMaxProve: any, bMaxVerify: any, mut?: (rp: any[], bp: any, cs: string[]) => [any[], any, any[]]) => {
  const cs = risks.map((r, i) => mk(r, blinds[i]!));
  let r = rps(risks, blinds);
  let b = J(R.proveBudget(risks, blinds, bMaxProve));
  let c: any[] = cs;
  if (mut) [r, b, c] = mut(r, b, cs) as any;
  return run('verifyBoundedBudget', name, R.verifyBoundedBudget, [c, r, bMaxVerify, b]);
};
await bb('ok', [3, 4], [5n, 6n], 10, 10);
await bb('exact', [3, 4], [5n, 6n], 7, 7);
await bb('over', [3, 4], [5n, 6n], 6, 6);
await bb('single', [9], [2n], 9, 9);
await bb('swapped-proofs', [3, 4], [5n, 6n], 10, 10, (r, b, c) => [[r[1], r[0]], b, c]);
await bb('missing-proof', [3, 4], [5n, 6n], 10, 10, (r, b, c) => [[r[0]], b, c]);
await bb('extra-commitment', [3, 4], [5n, 6n], 10, 10, (r, b, c) => [r, b, [...c, c[0]]]);
await bb('reordered-commitments', [3, 4], [5n, 6n], 10, 10, (r, b, c) => [[r[1], r[0]], b, [c[1], c[0]]]);
await run('verifyBoundedBudget', 'empty', R.verifyBoundedBudget, [[], [], 0, bp([], [], 0)]);
await run('verifyBoundedBudget', 'empty-nonzero-ceiling', R.verifyBoundedBudget, [[], [], 5, bp([], [], 5)]);
for (const [i, a] of ([[null, [], 0], ['x', [], 0], [[], null, 0], [[], {}, 0], [[ccs[0]], [], 0], [[], [rp1], 0]] as any[]).entries()) await run('verifyBoundedBudget', `shape/${i}`, R.verifyBoundedBudget, [a[0], a[1], a[2], bpOk]);

// refusals only (the proofs are random)
const throwCases: [string, any[]][] = [
  ['proveBudget/len', [[1, 2], [big(1)], 10]], ['proveBudget/len2', [[], [big(1)], 10]], ['proveBudget/negrisk', [[-1], [big(1)], 10]], ['proveBudget/fracrisk', [[1.5], [big(1)], 10]], ['proveBudget/strrisk', [['1'], [big(1)], 10]],
  ['proveBudget/negmax', [[1], [big(1)], -1]], ['proveBudget/fracmax', [[1], [big(1)], 0.5]], ['proveBudget/nullmax', [[1], [big(1)], null]], ['proveBudget/strmax', [[1], [big(1)], '10']], ['proveBudget/bigintneg', [[big(-1)], [big(1)], 10]],
  ['proveBudget/blindnum', [[1], [5], 10]],
];
for (const [name, args] of throwCases) await throwsOnly('proveBudget', name, R.proveBudget, args);
for (const [i, a] of ([[-1, big(1)], [1.5, big(1)], ['1', big(1)], [null, big(1)], [true, big(1)], [big(-5), big(1)], [1, 5], [1, null], [1, '5']] as any[]).entries()) await throwsOnly('proveRiskRange', `${i}`, R.proveRiskRange, a);
const AUTH = seed('ratchet-authority');
for (const [i, a] of ([[-1, 'digest-1'], [1.5, 'digest-1'], ['1', 'digest-1'], [null, 'digest-1'], [3, 'digest-1', 'short'], [3, 5]] as any[]).entries()) await throwsOnly('issueRiskCommitment', `${i}`, (r: any, d: any, k: any) => R.issueRiskCommitment(r, d, k === 'short' ? new Uint8Array(3) : AUTH), a);

// ---- attestations ----------------------------------------------------------------------------------------------------------------------------
const authPk = encodeKey(publicKeyOf(AUTH));
const otherPk = encodeKey(publicKeyOf(seed('ratchet-authority-2')));
const issued = (risk: number, digest: string) => R.issueRiskCommitment(risk, digest, AUTH);
const i1 = issued(3, 'digest-1');
const i2 = issued(4, 'digest-2');
const att1 = J(i1.attestation);
await run('verifyRiskAttestation', 'ok', R.verifyRiskAttestation, [i1.commitment, att1, authPk]);
const attCases: [string, any, any, any][] = [
  ['other commitment', i2.commitment, att1, authPk], ['other authority', i1.commitment, att1, otherPk], ['digest swapped', i1.commitment, { ...att1, actionDigest: 'digest-2' }, authPk], ['sig flip', i1.commitment, { ...att1, sig: flip(att1.sig) }, authPk],
  ['sig short', i1.commitment, { ...att1, sig: att1.sig.slice(0, 20) }, authPk], ['sig number', i1.commitment, { ...att1, sig: 5 }, authPk], ['no sig', i1.commitment, { actionDigest: 'digest-1' }, authPk], ['no digest', i1.commitment, { sig: att1.sig }, authPk],
  ['digest number', i1.commitment, { ...att1, actionDigest: 5 }, authPk], ['null', i1.commitment, null, authPk], ['string', i1.commitment, 'x', authPk], ['array', i1.commitment, [], authPk], ['empty', i1.commitment, {}, authPk],
  ['pk bad', i1.commitment, att1, 'x'], ['pk number', i1.commitment, att1, 5], ['pk null', i1.commitment, att1, null], ['commitment number', 5, att1, authPk], ['commitment null', null, att1, authPk],
  ['empty digest', i1.commitment, { ...att1, actionDigest: '' }, authPk], ['unknown member', i1.commitment, { ...att1, zz: 1 }, authPk], ['unicode digest', i1.commitment, { ...att1, actionDigest: 'déé' }, authPk],
];
for (const [name, c, a, k] of attCases) await run('verifyRiskAttestation', name, R.verifyRiskAttestation, [c, a, k]);
const empty = issued(0, '');
await run('verifyRiskAttestation', 'empty-digest-issued', R.verifyRiskAttestation, [empty.commitment, J(empty.attestation), authPk]);
const uni = issued(1, 'déé€');
await run('verifyRiskAttestation', 'unicode-issued', R.verifyRiskAttestation, [uni.commitment, J(uni.attestation), authPk]);

// attested budgets
const items = (xs: any[]) => xs.map((i) => ({ commitment: i.commitment, rangeProof: J(i.rangeProof), attestation: J(i.attestation) }));
const att = (name: string, xs: any[], digests: any, pk: any, bMaxVerify: any, proofOf: any, mut?: (it: any[]) => any[]) => {
  let it = items(xs);
  if (mut) it = mut(it);
  return run('verifyAttestedBudget', name, R.verifyAttestedBudget, [it, digests, pk, bMaxVerify, J(proofOf)]);
};
const setProof = R.proveBudget([3, 4], [i1.blinding, i2.blinding], 10);
await att('ok', [i1, i2], ['digest-1', 'digest-2'], authPk, 10, setProof);
await att('over-ceiling', [i1, i2], ['digest-1', 'digest-2'], authPk, 6, R.proveBudget([3, 4], [i1.blinding, i2.blinding], 6));
await att('digest-order', [i1, i2], ['digest-2', 'digest-1'], authPk, 10, setProof);
await att('digest-short', [i1, i2], ['digest-1'], authPk, 10, setProof);
await att('digest-wrong', [i1, i2], ['digest-1', 'digest-3'], authPk, 10, setProof);
await att('other-authority', [i1, i2], ['digest-1', 'digest-2'], otherPk, 10, setProof);
await att('no-attestation', [i1, i2], ['digest-1', 'digest-2'], authPk, 10, setProof, (it) => { delete it[1].attestation; return it; });
await att('attestation-moved', [i1, i2], ['digest-1', 'digest-2'], authPk, 10, setProof, (it) => { [it[0].attestation, it[1].attestation] = [it[1].attestation, it[0].attestation]; return it; });
await att('commitment-swapped', [i1, i2], ['digest-1', 'digest-2'], authPk, 10, setProof, (it) => { [it[0].commitment, it[1].commitment] = [it[1].commitment, it[0].commitment]; return it; });
await att('item-null', [i1, i2], ['digest-1', 'digest-2'], authPk, 10, setProof, (it) => { it[1] = null; return it; });
await att('items-not-array', [i1, i2], ['digest-1', 'digest-2'], authPk, 10, setProof, () => 'x' as any);
await att('digests-not-array', [i1, i2], 'x', authPk, 10, setProof);
await att('empty', [], [], authPk, 0, R.proveBudget([], [], 0));
await att('single', [i1], ['digest-1'], authPk, 3, R.proveBudget([3], [i1.blinding], 3));
await att('rangeproof-swapped', [i1, i2], ['digest-1', 'digest-2'], authPk, 10, setProof, (it) => { [it[0].rangeProof, it[1].rangeProof] = [it[1].rangeProof, it[0].rangeProof]; return it; });
await att('budget-for-other-set', [i1, i2], ['digest-1', 'digest-2'], authPk, 10, R.proveBudget([3, 5], [i1.blinding, i2.blinding], 10));

const randomized = 'only the refusals are recorded: a proof is randomized, its success path is replayed through the verify* cases';
(o as any).constantByDesign = { proveBudget: randomized, proveRiskRange: randomized };
refWrite(o, 'ratchet');
