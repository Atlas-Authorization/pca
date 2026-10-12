/**
 * A small dudect-style leakage detector (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?",
 * DATE 2017): time an operation on inputs drawn from two classes (typically "fixed secret" vs "random
 * secret"), interleaved in random order, and apply Welch's t-test to the two timing distributions, both on
 * the raw data and after cropping the slowest measurements at a series of percentiles (to cut scheduler and GC
 * noise). A large |t| is evidence that the running time depends on the class, i.e. on the secret.
 *
 * Limits (stated in the audit document): JavaScript on a shared machine has timer jitter, JIT tiering and
 * garbage collection, BigInt arithmetic is variable-time by construction, and a passing result is the
 * absence of detected leakage at this sample size, never a proof of constant time.
 */

export interface DudectResult {
  name: string;
  samples: number;
  /** max |t| over the raw distribution and every percentile crop. */
  maxAbsT: number;
  /** |t| with no cropping. */
  rawAbsT: number;
  meanNs: [number, number];
}

class Welch {
  n = 0;
  m = 0;
  m2 = 0;
  push(x: number): void {
    this.n++;
    const d = x - this.m;
    this.m += d / this.n;
    this.m2 += d * (x - this.m);
  }
  get variance(): number {
    return this.n > 1 ? this.m2 / (this.n - 1) : 0;
  }
}

function welchT(a: Welch, b: Welch): number {
  const se = Math.sqrt(a.variance / a.n + b.variance / b.n);
  return se === 0 ? 0 : (a.m - b.m) / se;
}

export function dudect<I>(
  name: string,
  makeInput: (cls: 0 | 1) => I,
  run: (input: I) => unknown,
  opts: { samples?: number; warmup?: number; inner?: number } = {},
): DudectResult {
  const samples = opts.samples ?? 2000;
  const inner = opts.inner ?? 1;
  const warm = opts.warmup ?? 100;
  const classes: (0 | 1)[] = [];
  const inputs: I[] = [];
  for (let i = 0; i < samples; i++) {
    const c = (Math.random() < 0.5 ? 0 : 1) as 0 | 1;
    classes.push(c);
    inputs.push(makeInput(c));
  }
  for (let i = 0; i < warm; i++) run(inputs[i % samples] as I);
  const times: number[] = new Array<number>(samples);
  let sink: unknown;
  for (let i = 0; i < samples; i++) {
    const inp = inputs[i] as I;
    const t0 = process.hrtime.bigint();
    for (let k = 0; k < inner; k++) sink = run(inp);
    const t1 = process.hrtime.bigint();
    times[i] = Number(t1 - t0) / inner;
  }
  void sink;
  const sorted = times.slice().sort((x, y) => x - y);
  const cuts: number[] = [Number.POSITIVE_INFINITY];
  for (let i = 0; i < 40; i++) {
    const p = 1 - Math.pow(0.5, (10 * (i + 1)) / 40);
    cuts.push(sorted[Math.min(samples - 1, Math.floor(p * samples))] as number);
  }
  let maxAbs = 0;
  let raw = 0;
  cuts.forEach((cut, idx) => {
    const a = new Welch();
    const b = new Welch();
    for (let i = 0; i < samples; i++) {
      const t = times[i] as number;
      if (t > cut) continue;
      (classes[i] === 0 ? a : b).push(t);
    }
    const t = Math.abs(welchT(a, b));
    if (idx === 0) raw = t;
    if (t > maxAbs) maxAbs = t;
  });
  const sum = [new Welch(), new Welch()] as const;
  for (let i = 0; i < samples; i++) sum[classes[i] as 0 | 1].push(times[i] as number);
  return { name, samples, maxAbsT: maxAbs, rawAbsT: raw, meanNs: [sum[0].m, sum[1].m] };
}

/** A deliberately leaky comparison used as a positive control: the harness MUST flag it. */
export function leakyEquals(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
    // make each matching byte observably costly so the control is unambiguous
    let x = 0;
    for (let j = 0; j < 2000; j++) x = (x + j) | 0;
    if (x === -1) return false;
  }
  return true;
}
