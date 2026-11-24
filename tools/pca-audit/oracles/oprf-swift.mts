// Oracle: @atlasauth/pca-oprf (RFC 9497 OPRF / VOPRF / POPRF on ristretto255-SHA512 + the PCA private-revocation / private-rate-limit layer).
// Deterministic: keys derive from fixed seeds; every randomised step is pinned (blind, proof nonce) except the PCA-layer flows, which use random
// blinds but return values that do not depend on them (a boolean, or the unblinded token). Bytes cross as {"$bytes": b64u}; bigints as decimal strings.
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw requires the native to throw):
//   deriveKeyPair(seed, info, mode) -> {secretKey, publicKey}            blind(input, mode, fixedBlind?) -> {blind, blindedElement}
//   blindEvaluate(sk, blinded, mode, pk?, proofRand?) -> {evaluatedElement, proof?}   finalize(input, blind, evaluated, mode, {proof?, publicKey?, blindedElement?}?) -> bytes
//   evaluate(sk, input, mode) -> bytes            hashToGroup(input, mode) -> bytes (serialised element)     publicKeyFor(sk) -> bytes
//   blindPoprf(input, info, pk, fixedBlind?) -> {blind, blindedElement, tweakedKey}   blindEvaluatePoprf(sk, blinded, info, proofRand?) -> {evaluatedElement, proof}
//   finalizePoprf(input, blind, evaluated, info, {proof, blindedElement, tweakedKey}) -> bytes     evaluatePoprf(sk, input, info) -> bytes
//   serializeScalar(decimal) -> bytes   deserializeScalar(bytes) -> decimal   deserializeElement(bytes) -> bytes (re-serialised)
//   toHex(bytes) -> string   bytesEqual(a, b) -> boolean
//   buildRevocationSet(sk, ids, mode) -> {outputs (sorted), mode, publicKey?}
//   isRevokedPrivate(capId, {sk, mode, revoked, lie?}) -> boolean   (builds the set + evaluator from sk; lie "wrong-key" answers with another key, "no-proof" drops the proof)
//   rateToken(sk, id, window) -> bytes   rateTokenHex(sk, id, window) -> string   privateRateToken(id, window, {sk, pk?}) -> bytes (evaluator = makeRateEvaluator(sk); pk defaults to publicKeyFor(sk))
//   rateCounter(limit, steps) -> results: steps are ["hit", b64u] -> {count, allowed}, ["count", b64u] -> n, ["reset"] -> null
// Not covered: mode strings other than oprf/voprf/poprf (the Java port refuses blindEvaluate/finalize/evaluate with poprf where the reference silently
// takes the voprf path), non-bytes arguments other than null/strings, randomScalar/randomKeyPair (random).
import * as O0 from '@atlasauth/pca-oprf';
import { Oracle, refWrite, splitWrite, tokensIn, rng, seed as seed0, capture, reparse } from './lib.mjs';
import { createHash } from 'node:crypto';

const O_RAW: any = (O0 as any).default ?? O0;
const o = new Oracle('oprf-swift', 'tools/pca-audit/oracles/oprf-swift.mts', 'TS-reference oracle for RFC 9497 ristretto255-SHA512 OPRF/VOPRF/POPRF and the PCA private-membership layer.');
// Swift lane: written WITHOUT key material. Every seed()-derived value is a {"$seed": label} (32 bytes sha256("atlas-pca-conformance/" + label)); a
// secret key derived by deriveKeyPair is {"$sk": {seed, info, mode}} (the test re-derives it); in an expected OUTPUT every such value is
// {"$sha256": b64u(sha256(bytes))}. The one PRNG-drawn derivation seed of the Java-lane generator is a labelled seed here (so the PRNG stream after it differs).
const REG = new Map<string, any>();
const hx = (u: Uint8Array) => Buffer.from(u).toString('hex');
const reg = (u: Uint8Array, d: any) => { const k = hx(u); if (!REG.has(k)) REG.set(k, d); };
const seed = (l: string) => { const u = seed0(l); reg(u, { $seed: l }); return u; };
const dOf = (u: any) => REG.get(hx(u)) ?? { $bytes: Buffer.from(u).toString('base64url') };
const O: any = {
  ...O_RAW,
  deriveKeyPair(sd: any, info: any, mode: any) {
    const r = O_RAW.deriveKeyPair(sd, info, mode);
    reg(r.secretKey, { $sk: { seed: dOf(sd), info: dOf(info), mode } });
    return r;
  },
};
const r = rng(0x09497);
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const B = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
const bytes = (n: number) => Uint8Array.from({ length: n }, () => r.int(0, 255));
const le = (n: bigint) => { const u = new Uint8Array(32); for (let i = 0; i < 32; i++) { u[i] = Number(n & 0xffn); n >>= 8n; } return u; };
/** {$bytes} -> Uint8Array, recursively (the reference sees real byte arrays; anything else passes through) */
const un = (v: any): any => {
  if (Array.isArray(v)) return v.map(un);
  if (v !== null && typeof v === 'object') {
    if (typeof v.$bytes === 'string' && Object.keys(v).length === 1) return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, un(x)]));
  }
  return v;
};
const call = (name: string) => (...a: any[]) => O[name](...a.map(un));
const run = (fn: string, name: string, f: (...a: any[]) => any, args: any[]) => o.run(fn, name, f, args);
const MODES = ['oprf', 'voprf', 'poprf'];
const seedA = new Uint8Array(32).fill(0xa3);
const SEEDS = [seedA, new Uint8Array(32), new Uint8Array(32).fill(0xff), seed('ref-oprf/s1'), seed('ref-oprf/s2'), seed('ref-oprf/s5')];
const INFOS = [new Uint8Array(), new TextEncoder().encode('test key'), bytes(100), bytes(300)];
const INPUTS = [new Uint8Array(), new Uint8Array([0]), new Uint8Array([0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a]), new TextEncoder().encode('capability:abc'), bytes(64), bytes(200)];

// ---- keys
for (const m of MODES) for (const [si, s] of SEEDS.entries()) for (const [ii, i] of INFOS.entries()) {
  if ((si + ii) % 2 && s.length === 32 && si > 2) continue;
  await run('deriveKeyPair', `${m}-s${si}-i${ii}`, call('deriveKeyPair'), [B(s), B(i), m]);
}
for (const [nm, a] of [['seed31', [B(bytes(31)), B(new Uint8Array()), 'oprf']], ['seed33', [B(bytes(33)), B(new Uint8Array()), 'oprf']], ['seed0', [B(new Uint8Array()), B(new Uint8Array()), 'oprf']], ['seed-str', ['a'.repeat(32), B(new Uint8Array()), 'oprf']], ['seed-null', [null, B(new Uint8Array()), 'oprf']], ['mode-x', [B(seedA), B(new Uint8Array()), 'x']], ['info-null', [B(seedA), null, 'oprf']], ['info-65536', [B(seedA), B(new Uint8Array(65536)), 'oprf']]] as [string, any[]][])
  await run('deriveKeyPair', nm, call('deriveKeyPair'), a);
const KP: Record<string, any> = {};
for (const m of MODES) KP[m] = O.deriveKeyPair(seed(`ref-oprf/key-${m}`), new TextEncoder().encode('k'), m);
const kpA = (m: string) => ({ sk: B(KP[m].secretKey), pk: B(KP[m].publicKey) });
await run('publicKeyFor', 'ok', call('publicKeyFor'), [B(KP.oprf.secretKey)]);
await run('publicKeyFor', 'ok2', call('publicKeyFor'), [B(KP.voprf.secretKey)]);
for (const [nm, v] of [['zero', 0n], ['one', 1n], ['L-1', L - 1n], ['L', L], ['L+1', L + 1n], ['max', 2n ** 256n - 1n]] as [string, bigint][]) {
  await run('publicKeyFor', nm, call('publicKeyFor'), [B(le(v))]);
  await run('deserializeScalar', nm, (b: any) => O.deserializeScalar(un(b)).toString(), [B(le(v))]);
}
for (const n of [0, 1, 31, 33, 64]) await run('deserializeScalar', `len${n}`, (b: any) => O.deserializeScalar(un(b)).toString(), [B(bytes(n))]);
await run('deserializeScalar', 'null', (b: any) => O.deserializeScalar(un(b)).toString(), [null]);
for (const [nm, v] of [['0', 0n], ['1', 1n], ['L-1', L - 1n], ['L', L], ['L+5', L + 5n], ['2^256+3', 2n ** 256n + 3n], ['neg1', -1n], ['neg-L', -L], ['big', 2n ** 600n + 17n]] as [string, bigint][])
  await run('serializeScalar', nm, (s: string) => O.serializeScalar(BigInt(s)), [v.toString()]);

// ---- group
const els: Uint8Array[] = [];
for (const m of MODES) for (const [ii, i] of INPUTS.entries()) {
  await run('hashToGroup', `${m}-i${ii}`, (a: any, mm: string) => O.hashToGroup(un(a), mm).toRawBytes(), [B(i), m]);
  els.push(O.hashToGroup(i, m).toRawBytes());
}
await run('hashToGroup', 'mode-x', (a: any, mm: string) => O.hashToGroup(un(a), mm).toRawBytes(), [B(INPUTS[1]), 'x']);
const de = (b: any) => O.serializeElement(O.deserializeElement(un(b)));
for (const [i, e] of els.entries()) {
  await run('deserializeElement', `valid${i}`, de, [B(e)]);
  if (i % 3 === 0) for (const bit of [0, 7, 100, 255]) { const m = Uint8Array.from(e); m[bit >> 3] ^= 1 << (bit & 7); await run('deserializeElement', `flip${i}-${bit}`, de, [B(m)]); }
}
await run('deserializeElement', 'base', de, [B(O.publicKeyFor(le(1n)))]);
for (const [nm, b] of [['identity', new Uint8Array(32)], ['nc-p', Uint8Array.from(Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'))], ['odd', Uint8Array.from([1, ...new Uint8Array(31)])], ['len31', bytes(31)], ['len33', bytes(33)], ['len0', new Uint8Array()], ['ff', new Uint8Array(32).fill(0xff)], ['top-bit', Uint8Array.from([...new Uint8Array(31), 0x80])]] as [string, Uint8Array][])
  await run('deserializeElement', nm, de, [B(b)]);
for (let i = 0; i < 12; i++) await run('deserializeElement', `rand${i}`, de, [B(bytes(32))]);
await run('deserializeElement', 'null', de, [null]);
await run('deserializeElement', 'str', de, ['00']);

// ---- OPRF / VOPRF
const BLINDS = [le(1n), le(2n), le(L - 1n), le(0n), le(L), le(123456789n), seed('ref-oprf/b1')];
for (const m of MODES) for (const [ii, i] of INPUTS.entries()) for (const [bi, b] of BLINDS.entries()) {
  if ((ii + bi) % 3) continue;
  const bl = bi === 6 ? Uint8Array.from(O.serializeScalar(BigInt('0x' + Buffer.from(b).reverse().toString('hex')) % L)) : b;
  await run('blind', `${m}-i${ii}-b${bi}`, call('blind'), [B(i), m, B(bl)]);
}
await run('blind', 'big-input', call('blind'), [B(new Uint8Array(65536)), 'oprf', B(le(5n))]);
await run('blind', 'max-input', call('blind'), [B(new Uint8Array(65535)), 'oprf', B(le(5n))]);
await run('blind', 'null-input', call('blind'), [null, 'oprf', B(le(5n))]);
await run('blind', 'str-input', call('blind'), ['abc', 'oprf', B(le(5n))]);
await run('blind', 'badmode', call('blind'), [B(INPUTS[1]), 'x', B(le(5n))]);
await run('blind', 'fixed-short', call('blind'), [B(INPUTS[1]), 'oprf', B(bytes(31))]);

type Flow = { m: string; i: Uint8Array; bl: any; ev: any; sk: Uint8Array; pk: Uint8Array; pr: Uint8Array };
const flows: Flow[] = [];
for (const m of ['oprf', 'voprf']) for (const [ii, i] of INPUTS.entries()) {
  const k = KP[m];
  const bl = O.blind(i, m, le(BigInt(ii + 3) * 7919n));
  const pr = le(BigInt(ii + 11) * 104729n);
  const ev = O.blindEvaluate(k.secretKey, bl.blindedElement, m, m === 'voprf' ? k.publicKey : undefined, m === 'voprf' ? pr : undefined);
  flows.push({ m, i, bl, ev, sk: k.secretKey, pk: k.publicKey, pr });
  const common = [B(k.secretKey), B(bl.blindedElement), m];
  await run('blindEvaluate', `${m}-i${ii}`, call('blindEvaluate'), m === 'voprf' ? [...common, B(k.publicKey), B(pr)] : common);
  if (m === 'voprf') {
    await run('blindEvaluate', `${m}-i${ii}-nopk`, call('blindEvaluate'), [...common, null, B(pr)]);
    await run('blindEvaluate', `${m}-i${ii}-nopk-pk`, call('blindEvaluate'), [...common, B(KP.poprf.publicKey), B(pr)]);
  }
  await run('evaluate', `${m}-i${ii}`, call('evaluate'), [B(k.secretKey), B(i), m]);
}
// blindEvaluate errors
const k0 = KP.oprf;
for (const [nm, a] of [
  ['sk-zero', [B(le(0n)), B(flows[0].bl.blindedElement), 'oprf']], ['sk-L', [B(le(L)), B(flows[0].bl.blindedElement), 'oprf']], ['sk-short', [B(bytes(31)), B(flows[0].bl.blindedElement), 'oprf']],
  ['blinded-identity', [B(k0.secretKey), B(new Uint8Array(32)), 'oprf']], ['blinded-junk', [B(k0.secretKey), B(new Uint8Array(32).fill(0xff)), 'oprf']], ['blinded-short', [B(k0.secretKey), B(bytes(31)), 'oprf']],
  ['voprf-fixed-zero', [B(KP.voprf.secretKey), B(flows[2].bl.blindedElement), 'voprf', null, B(le(0n))]], ['voprf-fixed-L', [B(KP.voprf.secretKey), B(flows[2].bl.blindedElement), 'voprf', null, B(le(L))]],
  ['voprf-pk-identity', [B(KP.voprf.secretKey), B(flows[2].bl.blindedElement), 'voprf', B(new Uint8Array(32)), B(le(9n))]],
] as [string, any[]][]) await run('blindEvaluate', nm, call('blindEvaluate'), a);
for (const [nm, a] of [['sk-zero', [B(le(0n)), B(INPUTS[1]), 'oprf']], ['sk-L', [B(le(L)), B(INPUTS[1]), 'oprf']], ['big-input', [B(k0.secretKey), B(new Uint8Array(65536)), 'oprf']], ['null-input', [B(k0.secretKey), null, 'oprf']]] as [string, any[]][])
  await run('evaluate', nm, call('evaluate'), a);

// finalize: honest, tampered
let fi = 0;
for (const f of flows) {
  const base = f.m === 'voprf' ? { proof: B(f.ev.proof), publicKey: B(f.pk), blindedElement: B(f.bl.blindedElement) } : undefined;
  const a = (ev = f.ev.evaluatedElement, opts: any = base, bl = f.bl.blind, inp = f.i) => (opts === undefined ? [B(inp), B(bl), B(ev), f.m] : [B(inp), B(bl), B(ev), f.m, opts]);
  const t = `${f.m}-${fi++}`;
  await run('finalize', `${t}-ok`, call('finalize'), a());
  await run('finalize', `${t}-other-input`, call('finalize'), a(undefined, undefined, undefined, bytes(5)));
  await run('finalize', `${t}-other-blind`, call('finalize'), a(undefined, undefined, le(99n)));
  await run('finalize', `${t}-blind-zero`, call('finalize'), a(undefined, undefined, le(0n)));
  await run('finalize', `${t}-blind-L`, call('finalize'), a(undefined, undefined, le(L)));
  await run('finalize', `${t}-ev-identity`, call('finalize'), a(new Uint8Array(32)));
  await run('finalize', `${t}-ev-other`, call('finalize'), a(flows[(fi) % flows.length].ev.evaluatedElement));
  if (f.m === 'voprf') {
    for (const idx of [0, 31, 32, 63]) { const p = Uint8Array.from(f.ev.proof); p[idx] ^= 1; await run('finalize', `${t}-proof-flip${idx}`, call('finalize'), a(undefined, { ...base, proof: B(p) })); }
    await run('finalize', `${t}-proof-trunc`, call('finalize'), a(undefined, { ...base, proof: B(f.ev.proof.subarray(0, 63)) }));
    await run('finalize', `${t}-proof-long`, call('finalize'), a(undefined, { ...base, proof: B(new Uint8Array([...f.ev.proof, 0])) }));
    const sL = le(BigInt('0x' + Buffer.from(f.ev.proof.subarray(32)).reverse().toString('hex')) + L);
    await run('finalize', `${t}-proof-s+L`, call('finalize'), a(undefined, { ...base, proof: B(new Uint8Array([...f.ev.proof.subarray(0, 32), ...sL])) }));
    await run('finalize', `${t}-wrong-pk`, call('finalize'), a(undefined, { ...base, publicKey: B(KP.poprf.publicKey) }));
    await run('finalize', `${t}-pk-identity`, call('finalize'), a(undefined, { ...base, publicKey: B(new Uint8Array(32)) }));
    await run('finalize', `${t}-wrong-blinded`, call('finalize'), a(undefined, { ...base, blindedElement: B(flows[(fi) % flows.length].bl.blindedElement) }));
    await run('finalize', `${t}-no-proof`, call('finalize'), a(undefined, { publicKey: base!.publicKey, blindedElement: base!.blindedElement }));
    await run('finalize', `${t}-no-pk`, call('finalize'), a(undefined, { proof: base!.proof, blindedElement: base!.blindedElement }));
    await run('finalize', `${t}-no-blinded`, call('finalize'), a(undefined, { proof: base!.proof, publicKey: base!.publicKey }));
    await run('finalize', `${t}-no-opts`, call('finalize'), a(undefined, undefined));
  }
}

// ---- POPRF
const INFOS2 = [new Uint8Array(), new TextEncoder().encode('test info'), bytes(50), new Uint8Array(65535)];
const pflows: any[] = [];
for (const [ii, i] of INPUTS.entries()) for (const [ni, info] of INFOS2.entries()) {
  if (ni === 3 && ii > 1) continue;
  const k = KP.poprf;
  const bl0 = le(BigInt(ii * 5 + ni + 3) * 31337n);
  const t = `i${ii}-n${ni}`;
  await run('blindPoprf', t, call('blindPoprf'), [B(i), B(info), B(k.publicKey), B(bl0)]);
  const bl = O.blindPoprf(i, info, k.publicKey, bl0);
  const pr = le(BigInt(ii * 5 + ni + 17) * 65537n);
  await run('blindEvaluatePoprf', t, call('blindEvaluatePoprf'), [B(k.secretKey), B(bl.blindedElement), B(info), B(pr)]);
  const ev = O.blindEvaluatePoprf(k.secretKey, bl.blindedElement, info, pr);
  await run('evaluatePoprf', t, call('evaluatePoprf'), [B(k.secretKey), B(i), B(info)]);
  pflows.push({ i, info, bl, ev, t });
}
for (const [nm, a] of [
  ['bp-pk-identity', [B(INPUTS[1]), B(INFOS2[1]), B(new Uint8Array(32)), B(le(5n))]], ['bp-info-big', [B(INPUTS[1]), B(new Uint8Array(65536)), B(KP.poprf.publicKey), B(le(5n))]], ['bp-fixed-zero', [B(INPUTS[1]), B(INFOS2[1]), B(KP.poprf.publicKey), B(le(0n))]],
  ['bp-input-null', [null, B(INFOS2[1]), B(KP.poprf.publicKey), B(le(5n))]], ['bp-info-null', [B(INPUTS[1]), null, B(KP.poprf.publicKey), B(le(5n))]],
] as [string, any[]][]) await run('blindPoprf', nm, call('blindPoprf'), a);
for (const [nm, a] of [['bep-sk0', [B(le(0n)), B(pflows[0].bl.blindedElement), B(pflows[0].info), B(le(31n))]], ['bep-blinded-identity', [B(KP.poprf.secretKey), B(new Uint8Array(32)), B(pflows[0].info)]], ['bep-fixed-zero', [B(KP.poprf.secretKey), B(pflows[0].bl.blindedElement), B(pflows[0].info), B(le(0n))]]] as [string, any[]][])
  await run('blindEvaluatePoprf', nm, call('blindEvaluatePoprf'), a);
for (const [nm, a] of [['ep-sk0', [B(le(0n)), B(INPUTS[1]), B(INFOS2[1])]], ['ep-info-big', [B(KP.poprf.secretKey), B(INPUTS[1]), B(new Uint8Array(65536))]], ['ep-sk-L', [B(le(L)), B(INPUTS[1]), B(INFOS2[1])]]] as [string, any[]][])
  await run('evaluatePoprf', nm, call('evaluatePoprf'), a);
let pj = 0;
for (const f of pflows) {
  if (pj++ % 2) continue;
  const k = KP.poprf;
  const opts = (p = f.ev.proof, b = f.bl.blindedElement, tk = f.bl.tweakedKey) => ({ proof: B(p), blindedElement: B(b), tweakedKey: B(tk) });
  const a = (o2: any = opts(), ev = f.ev.evaluatedElement, bl = f.bl.blind, inp = f.i, info = f.info) => [B(inp), B(bl), B(ev), B(info), o2];
  const t = f.t;
  await run('finalizePoprf', `${t}-ok`, call('finalizePoprf'), a());
  await run('finalizePoprf', `${t}-other-input`, call('finalizePoprf'), a(undefined, undefined, undefined, bytes(4)));
  await run('finalizePoprf', `${t}-other-info`, call('finalizePoprf'), a(undefined, undefined, undefined, undefined, bytes(3)));
  await run('finalizePoprf', `${t}-blind0`, call('finalizePoprf'), a(undefined, undefined, le(0n)));
  await run('finalizePoprf', `${t}-blind-other`, call('finalizePoprf'), a(undefined, undefined, le(77n)));
  for (const idx of [0, 40]) { const p = Uint8Array.from(f.ev.proof); p[idx] ^= 0x80; await run('finalizePoprf', `${t}-proof-flip${idx}`, call('finalizePoprf'), a(opts(p))); }
  await run('finalizePoprf', `${t}-proof-trunc`, call('finalizePoprf'), a(opts(f.ev.proof.subarray(0, 10))));
  await run('finalizePoprf', `${t}-tweaked-pk`, call('finalizePoprf'), a(opts(undefined, undefined, k.publicKey)));
  await run('finalizePoprf', `${t}-tweaked-identity`, call('finalizePoprf'), a(opts(undefined, undefined, new Uint8Array(32))));
  await run('finalizePoprf', `${t}-wrong-blinded`, call('finalizePoprf'), a(opts(undefined, pflows[(pj) % pflows.length].bl.blindedElement)));
  await run('finalizePoprf', `${t}-no-proof`, call('finalizePoprf'), a({ blindedElement: B(f.bl.blindedElement), tweakedKey: B(f.bl.tweakedKey) }));
  await run('finalizePoprf', `${t}-ev-identity`, call('finalizePoprf'), a(undefined, new Uint8Array(32)));
}

// ---- utilities
for (const b of [new Uint8Array(), new Uint8Array([0]), new Uint8Array([255, 1, 16]), bytes(40)]) await run('toHex', `b${b.length}-${b[0] ?? 'x'}`, (x: any) => O.toHex(un(x)), [B(b)]);
for (const [nm, a, b] of [['eq', bytes(5), null], ['empty', new Uint8Array(), new Uint8Array()], ['len', bytes(4), bytes(5)], ['neq', Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2, 4])]] as [string, Uint8Array, Uint8Array | null][])
  await run('bytesEqual', nm, (x: any, y: any) => O.bytesEqual(un(x), un(y)), [B(a), B(b ?? a)]);

// ---- PCA layer
const SKC = KP.oprf.secretKey, SKV = KP.voprf.secretKey;
const IDS = ['cap-1', 'cap-2', 'é日本', 'x'.repeat(200), '', 'a\u0000b'];
const evalMode = (mode: string, sk: Uint8Array, lie?: string) => {
  const real = O.makeRevocationEvaluator(lie === 'wrong-key' ? KP.poprf.secretKey : sk, mode);
  return (b: Uint8Array) => { const res = real(b); return lie === 'no-proof' ? { evaluatedElement: res.evaluatedElement } : res; };
};
const irp = (capId: any, op: any) => {
  const sk = un(op.sk);
  const set = O.buildRevocationSet(sk, op.revoked, op.mode);
  return O.isRevokedPrivate(capId, { blindEval: evalMode(op.mode, sk, op.lie), revokedSet: set });
};
for (const mode of ['oprf', 'voprf']) {
  const sk = mode === 'oprf' ? SKC : SKV;
  await run('buildRevocationSet', `${mode}-ids`, (s: any, ids: string[], m: string) => { const x = O.buildRevocationSet(un(s), ids, m); return { outputs: [...x.outputs].sort(), mode: x.mode, ...(x.publicKey ? { publicKey: x.publicKey } : {}) }; }, [B(sk), IDS.slice(0, 3), mode]);
  await run('buildRevocationSet', `${mode}-empty`, (s: any, ids: string[], m: string) => { const x = O.buildRevocationSet(un(s), ids, m); return { outputs: [...x.outputs].sort(), mode: x.mode, ...(x.publicKey ? { publicKey: x.publicKey } : {}) }; }, [B(sk), [], mode]);
  await run('buildRevocationSet', `${mode}-dups`, (s: any, ids: string[], m: string) => { const x = O.buildRevocationSet(un(s), ids, m); return { outputs: [...x.outputs].sort(), mode: x.mode }; }, [B(sk), ['a', 'a', 'b'], mode]);
  await run('buildRevocationSet', `${mode}-surrogate`, (s: any, ids: string[], m: string) => O.buildRevocationSet(un(s), ids, m).mode, [B(sk), ['\ud800'], mode]);
  for (const [i, id] of IDS.entries()) {
    await run('isRevokedPrivate', `${mode}-in${i}`, irp, [id, { sk: B(sk), mode, revoked: IDS }]);
    await run('isRevokedPrivate', `${mode}-out${i}`, irp, [id + '!', { sk: B(sk), mode, revoked: IDS }]);
  }
  await run('isRevokedPrivate', `${mode}-empty-set`, irp, ['cap-1', { sk: B(sk), mode, revoked: [] }]);
  await run('isRevokedPrivate', `${mode}-surrogate`, irp, ['\ud800', { sk: B(sk), mode, revoked: IDS }]);
  await run('isRevokedPrivate', `${mode}-low-surrogate`, irp, ['a\udc00', { sk: B(sk), mode, revoked: IDS }]);
  await run('isRevokedPrivate', `${mode}-astral`, irp, ['😀', { sk: B(sk), mode, revoked: ['😀'] }]);
  await run('isRevokedPrivate', `${mode}-null`, irp, [null, { sk: B(sk), mode, revoked: IDS }]);
  for (const lie of ['wrong-key', 'no-proof']) for (const id of [IDS[0], 'nope']) await run('isRevokedPrivate', `${mode}-lie-${lie}-${id}`, irp, [id, { sk: B(sk), mode, revoked: IDS, lie }]);
}
// rate tokens
const WINDOWS = ['2026-11-15T10', 'w2', '', 'é'];
const SKP = KP.poprf.secretKey;
for (const [idn, id] of ['agent-1', 'agent-2', '', 'é日本', 'z'.repeat(100)].entries()) for (const [wn, w] of WINDOWS.entries()) {
  await run('rateToken', `id${idn}-w${wn}`, (s: any, i: string, ww: string) => O.rateToken(un(s), i, ww), [B(SKP), id, w]);
  if (wn === 0) await run('rateTokenHex', `id${idn}`, (s: any, i: string, ww: string) => O.rateTokenHex(un(s), i, ww), [B(SKP), id, w]);
}
for (const [nm, a] of [['id-surr', [B(SKP), '\ud800', 'w']], ['win-surr', [B(SKP), 'a', '\udc00']], ['id-null', [B(SKP), null, 'w']], ['sk0', [B(le(0n)), 'a', 'w']]] as [string, any[]][]) await run('rateToken', nm, (s: any, i: string, ww: string) => O.rateToken(un(s), i, ww), a);
const prt = (id: any, w: any, op: any) => { const sk = un(op.sk); return O.privateRateToken(id, w, { blindEval: O.makeRateEvaluator(sk), publicKey: op.pk ? un(op.pk) : O.publicKeyFor(sk) }); };
for (const [idn, id] of ['agent-1', 'é日本', ''].entries()) for (const [wn, w] of WINDOWS.slice(0, 3).entries()) await run('privateRateToken', `id${idn}-w${wn}`, prt, [id, w, { sk: B(SKP) }]);
await run('privateRateToken', 'wrong-pk', prt, ['agent-1', 'w', { sk: B(SKP), pk: B(KP.voprf.publicKey) }]);
await run('privateRateToken', 'pk-identity', prt, ['agent-1', 'w', { sk: B(SKP), pk: B(new Uint8Array(32)) }]);
await run('privateRateToken', 'id-surr', prt, ['\ud800', 'w', { sk: B(SKP) }]);
await run('privateRateToken', 'win-surr', prt, ['a', '\ud800', { sk: B(SKP) }]);
const tok = (id: string, w: string) => B(O.rateToken(SKP, id, w));
const counter = (limit: any, steps: any[]) => { const c = new O.RateWindowCounter(limit); return steps.map((s) => (s[0] === 'hit' ? c.hit(un(s[1])) : s[0] === 'count' ? c.count(un(s[1])) : (c.reset(), null))); };
const T1 = tok('a', 'w'), T2 = tok('b', 'w');
await run('rateCounter', 'basic', counter, [2, [['hit', T1], ['hit', T1], ['hit', T1], ['hit', T2], ['count', T1], ['count', T2], ['count', tok('c', 'w')], ['reset'], ['count', T1], ['hit', T1]]]);
await run('rateCounter', 'limit1', counter, [1, [['hit', T1], ['hit', T1], ['hit', T2]]]);
for (const l of [0, -1, 1.5, null, '3']) await run('rateCounter', `limit-${l}`, counter, [l, []]);
const scrub = (v: any, isOut: boolean): any => {
  if (Array.isArray(v)) return v.map((x) => scrub(x, isOut));
  if (v !== null && typeof v === 'object') {
    if (typeof v.$bytes === 'string' && Object.keys(v).length === 1) {
      const u = new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
      const d = REG.get(hx(u));
      if (!d) return v;
      return isOut ? { $sha256: createHash('sha256').update(u).digest('base64url') } : JSON.parse(JSON.stringify(d));
    }
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrub(x, isOut)]));
  }
  return v;
};
if (!process.env.Ref_NOSCRUB) o.cases = o.cases.map((c: any) => ({ ...c, args: scrub(c.args, false), out: scrub(c.out, true) }));
splitWrite(o, 'oprf-swift', (j: string) => tokensIn(j, /"(?:sk|secretKey)":(?:\{"\$bytes":)?"([A-Za-z0-9_-]{40,})"/g));
