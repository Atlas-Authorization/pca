/**
 * dudect-style statistical timing tests (Reparaz, Balasch, Verbauwhede 2016) for secret-dependent operations in the PCA
 * TypeScript core. Two input classes (class 0 = one FIXED secret, class 1 = fresh RANDOM secrets) are measured in
 * random interleaved order; the timing distributions are cropped at several percentiles (dudect's outlier handling) and
 * compared with Welch's t-test. |t| > 10 on a pooled, repeated run is reported as a detected leak, 4.5 < |t| <= 10 as
 * inconclusive, otherwise "no leak detected at this sample size".
 *
 * HONEST LIMITS: this is a black-box wall-clock test in a JIT-compiled, garbage-collected runtime. "No leak detected"
 * is absence of evidence at N samples on this machine, not a constant-time proof; the harness validates itself with a
 * deliberately leaky comparison (positive control) that MUST be flagged, and a constant-time comparison (negative
 * control) that must not.
 *
 * Usage: tsx dudect.ts [--n 20000] [--only substr] [--json out.json]
 */
import { writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { ed25519, x25519 } from '../../../packages/pca/node_modules/@noble/curves/ed25519.js';
import { generateKeyPair, sign } from '../../../packages/pca/src/keys';
import { mlDsa65Keygen, mlDsa65Sign } from '../../../packages/pca/src/pq';
import { hybridDecapsulate, hybridEncapsulate, hybridKemKeygen } from '../../../packages/pca/src/kem';
import { ctAdd, ctMul, ctReduce } from '../../../packages/pca/src/ct-scalar';
import { frostCommit, frostSign, frostTrustedDealerKeygen } from '../../../packages/pca/src/frost';

const arg = (n: string, d: string) => {
  const i = process.argv.indexOf(`--${n}`);
  return i >= 0 ? process.argv[i + 1]! : d;
};
const N = Number(arg('n', '20000'));

// ---- statistics --------------------------------------------------------------------------------------------------
class Welch {
  n = [0, 0];
  mean = [0, 0];
  m2 = [0, 0];
  push(c: 0 | 1, x: number) {
    this.n[c]!++;
    const d = x - this.mean[c]!;
    this.mean[c]! += d / this.n[c]!;
    this.m2[c]! += d * (x - this.mean[c]!);
  }
  t(): number {
    const v0 = this.m2[0]! / (this.n[0]! - 1);
    const v1 = this.m2[1]! / (this.n[1]! - 1);
    const se = Math.sqrt(v0 / this.n[0]! + v1 / this.n[1]!);
    return se === 0 ? 0 : (this.mean[0]! - this.mean[1]!) / se;
  }
}

export interface Result {
  name: string;
  samples: number;
  maxAbsT: number;
  atCrop: string;
  verdict: 'no-leak-detected' | 'inconclusive' | 'LEAK-DETECTED';
  medianNs: [number, number];
}

function analyse(name: string, t0: number[], t1: number[]): Result {
  const all = [...t0, ...t1].sort((a, b) => a - b);
  const pct = (p: number) => all[Math.min(all.length - 1, Math.floor(p * all.length))]!;
  // dudect crop thresholds: 1 - 0.5^(10 * k / 100) style tail cuts plus the raw (uncropped) set
  const cuts: Array<[string, number]> = [['raw', Infinity]];
  for (let k = 1; k <= 10; k++) cuts.push([`p${(100 * (1 - Math.pow(0.5, (10 * k) / 100))).toFixed(1)}`, pct(1 - Math.pow(0.5, (10 * k) / 100))]);
  cuts.push(['p50', pct(0.5)], ['p90', pct(0.9)]);
  let best = 0;
  let at = 'raw';
  for (const [label, cut] of cuts) {
    const w = new Welch();
    for (const x of t0) if (x <= cut) w.push(0, x);
    for (const x of t1) if (x <= cut) w.push(1, x);
    if (w.n[0]! < 100 || w.n[1]! < 100) continue;
    const t = Math.abs(w.t());
    if (t > best) {
      best = t;
      at = label;
    }
  }
  const med = (a: number[]) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)]!;
  return { name, samples: t0.length + t1.length, maxAbsT: best, atCrop: at, verdict: best > 10 ? 'LEAK-DETECTED' : best > 4.5 ? 'inconclusive' : 'no-leak-detected', medianNs: [med(t0), med(t1)] };
}

/** Run `op` on N prepared inputs per class (class chosen at random per slot), timing each call. */
function measure<I>(name: string, n: number, mk: (cls: 0 | 1, i: number) => I, op: (x: I) => unknown, reps = 1): Result {
  const slots: Array<{ c: 0 | 1; x: I }> = [];
  for (let i = 0; i < 2 * n; i++) {
    const c = (randomBytes(1)[0]! & 1) as 0 | 1;
    slots.push({ c, x: mk(c, i) });
  }
  for (let i = 0; i < 300; i++) op(mk((i & 1) as 0 | 1, 2 * n + i)); // warm-up (JIT) on throw-away inputs: single-use inputs (FROST nonces) must not be consumed
  const t: [number[], number[]] = [[], []];
  let sink = 0;
  for (const s of slots) {
    const a = process.hrtime.bigint();
    for (let r = 0; r < reps; r++) sink ^= (op(s.x) as { length?: number } | undefined)?.length ?? 0;
    const b = process.hrtime.bigint();
    t[s.c].push(Number(b - a) / reps);
  }
  if (sink === 0.5) console.log('');
  return analyse(name, t[0], t[1]);
}

// ---- targets -----------------------------------------------------------------------------------------------------
const msg = new TextEncoder().encode('pca-timing-message-0123456789abcdef');

/** Early-exit comparison: the POSITIVE control. */
const leakyEq = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};
/** Branch-free comparison: the NEGATIVE control. */
const ctEq = (a: Uint8Array, b: Uint8Array): boolean => {
  let d = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ (b[i] ?? 0);
  return d === 0;
};

type Suite = Array<{ name: string; run: () => Result; expectLeak?: boolean }>;
const suite = (): Suite => {
  const fixedSk = generateKeyPair().secretKey;
  const fixedMl = mlDsa65Keygen(new Uint8Array(32).fill(9));
  const kem = hybridKemKeygen();
  const enc = hybridEncapsulate(kem.publicKey);
  const secretCmp = randomBytes(64);
  const dealer = frostTrustedDealerKeygen(2, 3);
  const mkFrost = (share: (typeof dealer.participantShares)[number]) => {
    const other = dealer.participantShares[1]!;
    const a = frostCommit(share);
    const b = frostCommit(other);
    return { share, a, commits: [a.commitment, b.commitment] };
  };
  const fixedShare = dealer.participantShares[0]!;
  const sharePool = Array.from({ length: 64 }, () => frostTrustedDealerKeygen(2, 3).participantShares[0]!);
  return [
    { name: 'CONTROL positive: early-exit byte compare (must be flagged)', expectLeak: true, run: () => measure('leaky compare', N, (c) => (c === 0 ? Uint8Array.from(secretCmp) : randomBytes(64)), (x: Uint8Array) => leakyEq(secretCmp, x), 20) },
    { name: 'CONTROL negative: branch-free byte compare (must not be flagged)', run: () => measure('ct compare', N, (c) => (c === 0 ? Uint8Array.from(secretCmp) : randomBytes(64)), (x: Uint8Array) => ctEq(secretCmp, x), 20) },
    { name: 'ed25519 sign (keys.sign -> @noble/curves): fixed secret vs random secrets', run: () => measure('ed25519 sign', N, (c) => (c === 0 ? Uint8Array.from(fixedSk) : generateKeyPair().secretKey), (sk: Uint8Array) => sign(sk, msg)) },
    { name: 'CONTROL null: ed25519 sign, random secrets vs random secrets (must not be flagged)', run: () => measure('ed25519 sign null', N, () => generateKeyPair().secretKey, (sk: Uint8Array) => sign(sk, msg)) },
    { name: 'ed25519 sign: fixed secret A vs fixed secret B (separates key-dependent timing from repetition/cache effects)', run: () => { const kb = generateKeyPair().secretKey; return measure('ed25519 sign A/B', N, (c) => Uint8Array.from(c === 0 ? fixedSk : kb), (sk: Uint8Array) => sign(sk, msg)); } },
    { name: 'ed25519 public-key derivation: fixed secret vs random secrets', run: () => measure('ed25519 getPublicKey', N, (c) => (c === 0 ? Uint8Array.from(fixedSk) : generateKeyPair().secretKey), (sk: Uint8Array) => ed25519.getPublicKey(sk)) },
    { name: 'x25519 scalar mult (ECDH): fixed secret vs random secrets', run: () => measure('x25519', N, (c) => (c === 0 ? kem.secretKey.slice(0, 32) : randomBytes(32)), (sk: Uint8Array) => x25519.getSharedSecret(sk, x25519.getPublicKey(randomBytes(32)))) },
    { name: 'ML-DSA-65 sign: fixed secret vs random secrets (rejection sampling is value-dependent by design; reported, not gated)', run: () => measure('ml-dsa-65 sign', Math.min(N, 1500), (c) => (c === 0 ? Uint8Array.from(fixedMl.secretKey) : mlDsa65Keygen(randomBytes(32)).secretKey), (sk: Uint8Array) => mlDsa65Sign(sk, msg)) },
    { name: 'hybrid KEM decapsulation: valid ciphertext vs random (invalid) ciphertexts', run: () => measure('hybrid decap', Math.min(N, 3000), (c) => (c === 0 ? Uint8Array.from(enc.ciphertext) : randomBytes(enc.ciphertext.length)), (ct: Uint8Array) => { try { return hybridDecapsulate(ct, kem.secretKey); } catch { return undefined; } }) },
    { name: 'ct-scalar mul mod L (FROST/DKG secret path): fixed secret vs random secrets', run: () => { const pub = randomBytes(32); pub[31]! &= 0x0f; const fixed = new Uint8Array(32).fill(0x11); fixed[31] = 0x01; return measure('ct mul', N, (c) => (c === 0 ? Uint8Array.from(fixed) : (() => { const r = randomBytes(32); r[31]! &= 0x0f; return new Uint8Array(r); })()), (x: Uint8Array) => ctAdd(ctMul(x, pub), x), 5); } },
    { name: 'CONTROL positive: the REPLACED BigInt mul/mod path, short secret vs full-size random secrets (must be flagged)', expectLeak: true, run: () => { const Ln = ed25519.CURVE.n; const pubN = 0x1234567890abcdefn; return measure('bigint mulmod', N, (c) => (c === 0 ? 3n : BigInt('0x' + randomBytes(31).toString('hex'))), (x: bigint) => { let a = x; for (let i = 0; i < 40; i++) a = (a * pubN + 7n) % Ln; return new Uint8Array([Number(a & 0xffn)]); }); } },
    { name: 'ct-scalar 64-byte wide reduction (nonce hash-to-scalar): all-zero-ish input vs random input', run: () => measure('ct reduce', N, (c) => (c === 0 ? new Uint8Array(64).fill(1) : new Uint8Array(randomBytes(64))), (x: Uint8Array) => ctReduce(x), 5) },
    {
      name: 'FROST round-2 sign (secret scalar arithmetic on the fixed-width ct-scalar path; noble point mult unchanged): fixed share vs random shares',
      expectLeak: false,
      // FROST nonces are one-shot (reuse throws), so every sample gets FRESH nonces; only the secret share differs by class.
      run: () => measure('frost sign', Math.min(N, 2000), (c, i) => mkFrost(c === 0 ? fixedShare : sharePool[i % sharePool.length]!), (x: ReturnType<typeof mkFrost>) => frostSign(x.share.identifier, x.share.share, dealer.groupPublicKey, { hiding: x.a.hidingNonce, binding: x.a.bindingNonce }, msg, x.commits)),
    },
  ];
};

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop()!)) {
  const only = arg('only', '');
  const out: Array<Result & { runs: Result[] }> = [];
  let exit = 0;
  for (const s of suite().filter((x) => x.name.toLowerCase().includes(only.toLowerCase()))) {
    // two independent runs; a LEAK verdict must reproduce in both to count (single-run flags are noise from the host)
    const r1 = s.run();
    const r2 = s.run();
    const leak = r1.verdict === 'LEAK-DETECTED' && r2.verdict === 'LEAK-DETECTED';
    const worst = r1.maxAbsT >= r2.maxAbsT ? r1 : r2;
    const final: Result['verdict'] = leak ? 'LEAK-DETECTED' : r1.verdict !== 'no-leak-detected' || r2.verdict !== 'no-leak-detected' ? 'inconclusive' : 'no-leak-detected';
    console.log(`${final.padEnd(17)} |t|=${r1.maxAbsT.toFixed(1)}/${r2.maxAbsT.toFixed(1)} (n=${r1.samples}) ${s.name}`);
    out.push({ ...worst, name: s.name, verdict: final, runs: [r1, r2] });
    if (s.expectLeak === true && final !== 'LEAK-DETECTED') {
      console.log('  !! harness sensitivity failure: the positive control was NOT flagged');
      exit = 1;
    }
    if (s.expectLeak === undefined && /CONTROL negative/.test(s.name) && final === 'LEAK-DETECTED') exit = 1;
  }
  const j = arg('json', '');
  if (j) writeFileSync(j, JSON.stringify({ n: N, node: process.version, platform: `${process.platform}-${process.arch}`, results: out }, null, 2));
  process.exitCode = exit;
}
