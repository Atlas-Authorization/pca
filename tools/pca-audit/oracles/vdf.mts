// Oracle: @atlasauth/pca-vdf (Wesolowski VDF over an RSA group + the PCA timelock). Deterministic: every input derives from fixed seeds.
// Big integers cross the oracle as DECIMAL STRINGS (args and results); the wrapper converts with BigInt(). Step counts are JSON numbers.
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw requires the native to throw):
//   isProbablePrime(n) / isMillerRabinProbablePrime(n) / isStrongLucasProbablePrime(n) -> boolean
//   hashToPrime(x, y, T, N, bits?)             -> decimal string of the challenge prime (byte-identical: domain, length-prefixed transcript, counter/block sha256 expansion)
//   modpow(b, e, m) / gcd(a, b) / canonicalVdfOutput(y, N) -> decimal string
//   bigIntToBytes(n) -> bytes ({"$bytes"}); bytesRoundTrip(b64u) = bigIntToBytes(bytesToBigInt(bytes))
//   sequentialSquare(x, T, N) -> decimal string
//   vdfEval / vdfEvalCanonical(x, T, N) -> {y, pi} decimal strings
//   vdfVerifyDetailed / vdfVerifyCanonicalDetailed(x, y, pi, T, N) -> {ok, reason?}  (never throws; T is any JSON number)
//   checkProductionModulus(N) -> {ok, reason?}   (the in-process insecureDevSetup registry is not exercised)
//   deriveTimelockInput(action, N, beacon) -> decimal string. action is a string digest or any JSON object (digest = canonical hash); beacon is a string
//   requireTimelock(action, {steps, N, beacon, allowInsecureDevModulus?}) -> {kind, x, steps, N, actionDigest}
//   proveTimelockElapsed(action, steps, N, {beacon, allowInsecureDevModulus?}) -> {kind, y, pi, steps}
//   verifyTimelock(action, proof, {steps, N, beacon, allowInsecureDevModulus?}) -> boolean (proof is the object proveTimelockElapsed returned, possibly tampered; y/pi are decimal strings)
import * as V0 from "@atlasauth/pca-vdf";
const V: any = (V0 as any).default ?? V0;
import { Oracle, refWrite, rng, capture, reparse } from './lib.mjs';

const o = new Oracle('vdf', 'tools/pca-audit/oracles/vdf.mts', 'TS-reference oracle for the Wesolowski VDF and PCA timelock.');
const B = (s: any) => { if (typeof s !== 'string') throw new TypeError('bigint arg'); return BigInt(s); };
const S = (b: bigint) => b.toString();
const r = rng(0x5ed5);
const M = (e: number) => (1n << BigInt(e)) - 1n;
const RSA = S(V.RSA_2048_CHALLENGE_MODULUS);
// odd composite moduli of unknown-to-the-test-but-fixed factorisation (products of known primes)
const NS: Record<string, string> = {
  tiny: S(1000003n * 1000033n),
  n64: S(M(31) * M(61)),
  n196: S(M(89) * M(107)),
  n1128: S(M(521) * M(607)),
  n3482: S(M(1279) * M(2203)),
  rsa: RSA,
};
const NK = Object.keys(NS);
const randBig = (bits: number) => { let v = 0n; for (let i = 0; i < bits; i += 16) v = (v << 16n) | BigInt(r.int(0, 65535)); return v & ((1n << BigInt(bits)) - 1n); };

// ---- primality
const prim: [string, string][] = [];
for (let n = 0; n <= 1200; n++) prim.push([`n${n}`, String(n)]);
for (const e of [2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281]) { prim.push([`m${e}`, S(M(e))]); prim.push([`m${e}p2`, S(M(e) + 2n)]); }
for (const n of [561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265, 321197185, 2047, 3277, 4033, 4681, 8321, 15841, 29341, 42799, 49141, 52633, 65281, 74665, 80581, 85489, 88357, 90751, 5459, 5777, 10877, 16109, 18971, 22499, 24569, 25199, 40309, 58519, 75077, 97439, 3215031751, 3825123056546413051, 318665857834031151167461, 3317044064679887385961981, 9, 25, 49, 121, 169, 289, 961, 4294967297, 18446744073709551617, 1000003 * 1000033])
  prim.push([`k${n}`, String(n)]);
for (let i = 0; i < 40; i++) { const b = randBig(256) | (1n << 255n) | 1n; prim.push([`r256-${i}`, S(b)]); }
for (let i = 0; i < 20; i++) { const b = randBig(96) | (1n << 95n) | 1n; prim.push([`r96-${i}`, S(b)]); }
for (const [n, v] of prim) {
  await o.run('isProbablePrime', n, (a: string) => V.isProbablePrime(B(a)), [v]);
  await o.run('isMillerRabinProbablePrime', n, (a: string) => V.isMillerRabinProbablePrime(B(a)), [v]);
  await o.run('isStrongLucasProbablePrime', n, (a: string) => V.isStrongLucasProbablePrime(B(a)), [v]);
}
for (const v of ['-7', '-1', '0', '1', '2', '3']) {
  await o.run('isProbablePrime', `neg${v}`, (a: string) => V.isProbablePrime(B(a)), [v]);
  await o.run('isStrongLucasProbablePrime', `neg${v}`, (a: string) => V.isStrongLucasProbablePrime(B(a)), [v]);
}

// ---- helpers
for (const [b, e, m] of [['2', '10', '1000'], ['0', '0', '7'], ['5', '0', '1'], ['-3', '5', '7'], ['123456789', '987654321', S(M(61))], ['2', '255', S(M(127))], ['7', '3', '0'], ['7', '-1', '13'], [RSA, '65537', S(M(89))], ['-2', '3', '5']])
  await o.run('modpow', `${b}^${e}%${m}`.slice(0, 60), (x: string, y: string, z: string) => S(V.modpow(B(x), B(y), B(z))), [b, e, m]);
for (const [a, b] of [['12', '18'], ['0', '5'], ['5', '0'], ['-12', '18'], ['17', '31'], [S(M(89) * 6n), S(M(107) * 6n)]])
  await o.run('gcd', `${a}-${b}`.slice(0, 40), (x: string, y: string) => S(V.gcd(B(x), B(y))), [a, b]);
for (const [y, n] of [['5', '11'], ['6', '11'], ['1', '3'], ['10', '11'], ['0', '7']])
  await o.run('canonicalVdfOutput', `${y}-${n}`, (a: string, b: string) => S(V.canonicalVdfOutput(B(a), B(b))), [y, n]);
for (const v of ['0', '1', '255', '256', '65535', '65536', S(M(64)), S(M(2203)), '-1'])
  await o.run('bigIntToBytes', v.slice(0, 30), (a: string) => V.bigIntToBytes(B(a)), [v]);
for (const b of ['', 'AA', 'AAA', '_w', 'AQID', 'AAAAAQ', 'AAEC'])
  await o.run('bytesRoundTrip', b || 'empty', (a: string) => V.bigIntToBytes(V.bytesToBigInt(new Uint8Array(Buffer.from(a, 'base64url')))), [b]);

// ---- hashToPrime
let hi = 0;
for (const nk of NK) {
  const N = B(NS[nk]);
  for (const T of [0, 1, 7, 1000, 2 ** 40]) for (const bits of [undefined, 8, 16, 64, 512]) {
    if (hi++ % 2 && bits !== undefined) continue;
    const x = randBig(60) + 2n, y = randBig(80) + 2n;
    const args: any[] = [S(x), S(y), T, NS[nk]]; if (bits !== undefined) args.push(bits);
    await o.run('hashToPrime', `${nk}-T${T}-b${bits}`, (a: string, b: string, t: number, n: string, bt?: number) => S(V.hashToPrime(B(a), B(b), t, B(n), bt)), args);
  }
}
for (const [nm, args] of [
  ['neg-x', ['-5', '7', 3, NS.tiny]], ['x>N', [S(B(NS.tiny) * 3n + 4n), '7', 3, NS.tiny]], ['bits7', ['5', '7', 3, NS.tiny, 7]], ['bits8193', ['5', '7', 3, NS.tiny, 8193]],
  ['bits1.5', ['5', '7', 3, NS.tiny, 1.5]], ['T-1', ['5', '7', -1, NS.tiny]], ['T1.5', ['5', '7', 1.5, NS.tiny]], ['T2^53', ['5', '7', 2 ** 53, NS.tiny]], ['T2^53-1', ['5', '7', 2 ** 53 - 1, NS.tiny]], ['bits8192', ['5', '7', 3, NS.tiny, 8192]],
] as [string, any[]][])
  await o.run('hashToPrime', nm, (a: string, b: string, t: number, n: string, bt?: number) => S(V.hashToPrime(B(a), B(b), t, B(n), bt)), args);

// ---- sequentialSquare / eval
for (const nk of NK) for (const T of [0, 1, 2, 9, 40]) {
  const x = S(randBig(100) + 2n);
  await o.run('sequentialSquare', `${nk}-T${T}`, (a: string, t: number, n: string) => S(V.sequentialSquare(B(a), t, B(n))), [x, T, NS[nk]]);
}
await o.run('sequentialSquare', 'N1', (a: string, t: number, n: string) => S(V.sequentialSquare(B(a), t, B(n))), ['5', 2, '1']);
await o.run('sequentialSquare', 'Tneg', (a: string, t: number, n: string) => S(V.sequentialSquare(B(a), t, B(n))), ['5', -2, NS.tiny]);
const pf = (p: any) => ({ y: S(p.y), pi: S(p.pi) });
const proofs: any[] = [];
for (const nk of NK) for (const T of [0, 1, 2, 5, 13, 40]) for (let i = 0; i < 2; i++) {
  if (nk === 'rsa' && i === 1 && T > 13) continue;
  const x = S(randBig(120) + 2n);
  const a = [x, T, NS[nk]];
  await o.run('vdfEval', `${nk}-T${T}-${i}`, (x: string, t: number, n: string) => pf(V.vdfEval(B(x), t, B(n))), a);
  await o.run('vdfEvalCanonical', `${nk}-T${T}-${i}`, (x: string, t: number, n: string) => pf(V.vdfEvalCanonical(B(x), t, B(n))), a);
  try { proofs.push({ nk, x, T, plain: pf(V.vdfEval(B(x), T, B(NS[nk]))), canon: pf(V.vdfEvalCanonical(B(x), T, B(NS[nk]))) }); } catch { /* degenerate */ }
}
const N11 = NS.tiny, Nn = B(N11);
for (const [nm, x, T, N] of [
  ['x0', '0', 3, N11], ['x1', '1', 3, N11], ['xN-1', S(Nn - 1n), 3, N11], ['xneg1', '-1', 3, N11], ['xshare', '1000003', 3, N11], ['xN', N11, 3, N11], ['x>N', S(Nn + 5n), 3, N11], ['xneg', '-5', 3, N11],
  ['Neven', '5', 3, '1000034'], ['N3', '2', 3, '3'], ['N1', '2', 3, '1'], ['Tneg', '5', -1, N11], ['T1.5', '5', 1.5, N11], ['T2^53', '5', 2 ** 53, N11],
] as [string, string, number, string][]) {
  await o.run('vdfEval', nm, (x: string, t: number, n: string) => pf(V.vdfEval(B(x), t, B(n))), [x, T, N]);
  await o.run('vdfEvalCanonical', nm, (x: string, t: number, n: string) => pf(V.vdfEvalCanonical(B(x), t, B(n))), [x, T, N]);
}

// ---- verify (valid, tampered, hostile)
const vd = (canonical: boolean) => (x: string, y: string, pi: string, t: number, n: string) => {
  const v = (canonical ? V.vdfVerifyCanonicalDetailed : V.vdfVerifyDetailed)(B(x), B(y), B(pi), t, B(n));
  return v.ok ? { ok: true } : { ok: false, reason: v.reason };
};
let pi_ = 0;
for (const p of proofs) {
  const N = B(NS[p.nk]);
  for (const [kind, fn] of [['plain', 'vdfVerifyDetailed'], ['canon', 'vdfVerifyCanonicalDetailed']] as const) {
    const pr = p[kind], can = fn === 'vdfVerifyCanonicalDetailed';
    const y = B(pr.y), pi = B(pr.pi);
    const tag = `${p.nk}-T${p.T}-${kind}-${pi_}`;
    const cases: [string, string[], number][] = [
      ['ok', [p.x, pr.y, pr.pi], p.T],
      ['y+1', [p.x, S(y + 1n), pr.pi], p.T], ['pi+1', [p.x, pr.y, S(pi + 1n)], p.T], ['T+1', [p.x, pr.y, pr.pi], p.T + 1], ['T-1', [p.x, pr.y, pr.pi], p.T - 1],
      ['x+1', [S(B(p.x) + 1n), pr.y, pr.pi], p.T], ['ny', [p.x, S(N - y), pr.pi], p.T], ['npi', [p.x, pr.y, S(N - pi)], p.T], ['nynpi', [p.x, S(N - y), S(N - pi)], p.T],
      ['swap', [p.x, pr.pi, pr.y], p.T], ['y0', [p.x, '0', pr.pi], p.T], ['pi0', [p.x, pr.y, '0'], p.T], ['yN', [p.x, S(N), pr.pi], p.T], ['pineg', [p.x, pr.y, '-' + pr.pi], p.T],
      ['x0', ['0', pr.y, pr.pi], p.T], ['x1', ['1', pr.y, pr.pi], p.T], ['xN-1', [S(N - 1n), pr.y, pr.pi], p.T], ['xplusN', [S(B(p.x) + N), pr.y, pr.pi], p.T],
      ['T1.5', [p.x, pr.y, pr.pi], 1.5], ['Tneg', [p.x, pr.y, pr.pi], -1], ['T2^53', [p.x, pr.y, pr.pi], 2 ** 53], ['T1e21', [p.x, pr.y, pr.pi], 1e21], ['Tneg0', [p.x, pr.y, pr.pi], -0],
    ];
    if (pi_ % 3 === 0) { for (const [nm, a, t] of cases) await o.run(fn, `${tag}-${nm}`, vd(can), [a[0], a[1], a[2], t, NS[p.nk]]); }
    else for (const [nm, a, t] of cases.slice(0, 8)) await o.run(fn, `${tag}-${nm}`, vd(can), [a[0], a[1], a[2], t, NS[p.nk]]);
    // cross-kind: plain proof under the canonical verifier and vice versa
    const other = p[kind === 'plain' ? 'canon' : 'plain'];
    await o.run(fn, `${tag}-cross`, vd(can), [p.x, other.y, other.pi, p.T, NS[p.nk]]);
  }
  pi_++;
}
for (const [nm, N] of [['N-even', '1000034'], ['N3', '3'], ['N-neg', '-15'], ['N1', '1'], ['N0', '0']])
  for (const fn of ['vdfVerifyDetailed', 'vdfVerifyCanonicalDetailed'] as const)
    await o.run(fn, nm, vd(fn === 'vdfVerifyCanonicalDetailed'), ['5', '7', '9', 3, N]);
// zero-work forgeries at production size
for (const fn of ['vdfVerifyDetailed', 'vdfVerifyCanonicalDetailed'] as const) {
  await o.run(fn, 'forge-0-0', vd(fn === 'vdfVerifyCanonicalDetailed'), ['123456789', '0', '0', 1_000_000_000, RSA]);
  await o.run(fn, 'forge-N-N', vd(fn === 'vdfVerifyCanonicalDetailed'), ['123456789', RSA, RSA, 1_000_000_000, RSA]);
  await o.run(fn, 'forge-5-0', vd(fn === 'vdfVerifyCanonicalDetailed'), ['123456789', '5', '0', 1_000_000_000, RSA]);
  await o.run(fn, 'forge-neg', vd(fn === 'vdfVerifyCanonicalDetailed'), ['123456789', '-5', '7', 1_000_000_000, RSA]);
  await o.run(fn, 'forge-rand', vd(fn === 'vdfVerifyCanonicalDetailed'), ['123456789', S(randBig(2000) + 3n), S(randBig(2000) + 3n), 1_000_000_000, RSA]);
}

// ---- production modulus screen
const prodMods: [string, string][] = [
  ['rsa', RSA], ['m2203', S(M(2203))], ['rsa^2', S(B(RSA) ** 2n)], ['rsa*3', S(B(RSA) * 3n)], ['rsa+1', S(B(RSA) + 1n)], ['m521*m607', NS.n1128], ['n3482', NS.n3482], ['small', '15'], ['three', '3'], ['zero', '0'], ['neg', '-15'],
  ['2^2047', S(1n << 2047n)], ['m2281*m1279', S(M(2281) * M(1279))], ['sq3482', S(B(NS.n3482) ** 2n)], ['p65537*m2203', S(65537n * M(2203))], ['p65539*m2203', S(65539n * M(2203))], ['2048bit-exact', S((1n << 2047n) | 1n)],
  ['2047bit', S((1n << 2046n) | 1n)],
];
for (const [nm, v] of prodMods) await o.run('checkProductionModulus', nm, (a: string) => { const c = V.checkProductionModulus(B(a)); return c.ok ? { ok: true } : { ok: false, reason: c.reason }; }, [v]);

// ---- timelock
const ACT: [string, any][] = [['digest', 'dGVzdC1hY3Rpb24'], ['empty-str', ''], ['pcactn', { v: 1, action: { verb: 'transfer', resource: 'acct/1' }, params_digest: 'abc', n: 2 }], ['obj2', { b: 1, a: [1, 2, { z: null }] }], ['unicode', 'é日本']];
const BEAC = ['beacon-0123456789abcdef', 'b', 'é', ''];
const topt = (n: string, steps: number, beacon: any, allow?: boolean) => ({ steps, N: n, beacon, ...(allow === undefined ? {} : { allowInsecureDevModulus: allow }) });
const tl = (f: 'derive' | 'require' | 'prove' | 'verify') => (action: any, a: any, b?: any) => {
  const opts = (x: any) => ({ steps: x.steps, N: x.N === undefined ? undefined : B(x.N), beacon: x.beacon, allowInsecureDevModulus: x.allowInsecureDevModulus });
  if (f === 'derive') return S(V.deriveTimelockInput(action, B(a), b));
  if (f === 'require') { const q = V.requireTimelock(action, opts(a)); return { kind: q.kind, x: S(q.x), steps: q.steps, N: S(q.N), actionDigest: q.actionDigest }; }
  if (f === 'prove') { const p = V.proveTimelockElapsed(action, a, B(b.N), { beacon: b.beacon, allowInsecureDevModulus: b.allowInsecureDevModulus }); return { kind: p.kind, y: S(p.y), pi: S(p.pi), steps: p.steps }; }
  const pr = a === null || typeof a !== 'object' ? a : { ...a, y: typeof a.y === 'string' ? BigInt(a.y) : a.y, pi: typeof a.pi === 'string' ? BigInt(a.pi) : a.pi };
  return V.verifyTimelock(action, pr, opts(b));
};
for (const [an, act] of ACT) for (const nk of NK) for (const bc of BEAC) {
  if (nk !== 'rsa' && nk !== 'n3482' && bc !== BEAC[0]) continue;
  await o.run('deriveTimelockInput', `${an}-${nk}-${bc || 'empty'}`, tl('derive'), [act, NS[nk], bc]);
}
for (const [nm, n] of [['N3', '3'], ['N4', '4'], ['N2', '2']]) await o.run('deriveTimelockInput', nm, tl('derive'), ['a', n, 'b']);
const tproofs: any[] = [];
for (const [an, act] of ACT.slice(0, 3)) for (const nk of ['n1128', 'n3482', 'rsa']) for (const steps of [1, 6, 25]) {
  const allow = nk === 'n1128' ? true : undefined; // n1128 is below 2048 bits: needs the dev flag
  const a = [act, steps, NS[nk], { beacon: BEAC[0], ...(allow === undefined ? {} : { allowInsecureDevModulus: allow }) }];
  await o.run('requireTimelock', `${an}-${nk}-${steps}`, (ac: any, op: any) => tl('require')(ac, op), [act, topt(NS[nk], steps, BEAC[0], allow)]);
  await o.run('proveTimelockElapsed', `${an}-${nk}-${steps}`, (ac: any, s: number, n: string, op: any) => tl('prove')(ac, s, { ...op, N: n }), [act, steps, NS[nk], a[3]]);
  const pr = reparse([tl('prove')(act, steps, { ...(a[3] as any), N: NS[nk] })])[0];
  tproofs.push({ an, act, nk, steps, allow, pr });
}
const tag2 = (t: any) => `${t.an}-${t.nk}-${t.steps}`;
let ti = 0;
for (const t of tproofs) {
  const op = (steps = t.steps, beacon: any = BEAC[0], allow = t.allow, N = NS[t.nk]) => topt(N, steps, beacon, allow);
  const v: [string, any, any, any][] = [
    ['ok', t.act, t.pr, op()], ['other-action', 'zzz', t.pr, op()], ['other-beacon', t.act, t.pr, op(t.steps, 'other-beacon')], ['steps+1', t.act, t.pr, op(t.steps + 1)], ['steps0', t.act, t.pr, op(0)],
    ['steps1.5', t.act, t.pr, op(1.5)], ['y+1', t.act, { ...t.pr, y: S(B(t.pr.y) + 1n) }, op()], ['pi+1', t.act, { ...t.pr, pi: S(B(t.pr.pi) + 1n) }, op()],
    ['kind', t.act, { ...t.pr, kind: 'x' }, op()], ['proof-steps', t.act, { ...t.pr, steps: t.steps + 1 }, op()], ['proof-steps-str', t.act, { ...t.pr, steps: String(t.steps) }, op()],
    ['proof-null', t.act, null, op()], ['proof-num', t.act, 5, op()], ['y-num', t.act, { ...t.pr, y: 5 }, op()], ['ny', t.act, { ...t.pr, y: S(B(NS[t.nk]) - B(t.pr.y)) }, op()],
    ['empty-beacon', t.act, t.pr, op(t.steps, '')], ['y0pi0', t.act, { ...t.pr, y: '0', pi: '0' }, op()],
  ];
  if (t.allow === undefined) v.push(['no-allow-dev', t.act, t.pr, op(t.steps, BEAC[0], undefined, undefined)]);
  else v.push(['allow-false', t.act, t.pr, op(t.steps, BEAC[0], false)]);
  for (const [nm, act, pr, opts] of (ti++ % 2 === 0 ? v : v.slice(0, 6))) await o.run('verifyTimelock', `${tag2(t)}-${nm}`, (ac: any, p: any, op: any) => tl('verify')(ac, p, op), [act, pr, opts]);
}
for (const [nm, args] of [
  ['steps0', ['a', topt(NS.rsa, 0, 'b')]], ['stepsNeg', ['a', topt(NS.rsa, -3, 'b')]], ['steps1.5', ['a', topt(NS.rsa, 1.5, 'b')]], ['stepsBig', ['a', topt(NS.rsa, 2 ** 53, 'b')]],
  ['small-N', ['a', topt('15', 3, 'b')]], ['small-N-allow', ['a', topt('15', 3, 'b', true)]], ['even-N', ['a', topt(S(B(RSA) + 1n), 3, 'b')]], ['empty-beacon', ['a', topt(NS.rsa, 3, '')]],
  ['m2203', ['a', topt(S(M(2203)), 3, 'b')]], ['N3-allow', ['a', topt('3', 3, 'b', true)]],
] as [string, any[]][]) {
  await o.run('requireTimelock', nm, (ac: any, op: any) => tl('require')(ac, op), args);
  await o.run('proveTimelockElapsed', nm, (ac: any, s: number, n: string, op: any) => tl('prove')(ac, s, { ...op, N: n }), [args[0], args[1].steps, args[1].N, { beacon: args[1].beacon, allowInsecureDevModulus: args[1].allowInsecureDevModulus }]);
}
refWrite(o, 'vdf');
