// Shared helpers for the primitives N-version harness (plain ESM, no deps).
export const hex = (u8) => Buffer.from(u8).toString('hex');
export const unhex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
export const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };

/** xoshiro128** seeded by splitmix32: fast, deterministic, replayable by (seed). */
export class Prng {
  constructor(seed = 1) {
    let z = seed >>> 0; const sm = () => { z = (z + 0x9e3779b9) >>> 0; let t = z ^ (z >>> 16); t = Math.imul(t, 0x21f0aaad); t ^= t >>> 15; t = Math.imul(t, 0x735a2d97); return (t ^ (t >>> 15)) >>> 0; };
    this.s = new Uint32Array([sm(), sm(), sm(), sm()]);
  }
  u32() {
    const s = this.s; const m = Math.imul(s[1], 5); const r = Math.imul(((m << 7) | (m >>> 25)) >>> 0, 9) >>> 0;
    const t = s[1] << 9; s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t; s[3] = (s[3] << 11) | (s[3] >>> 21);
    return r;
  }
  int(n) { return this.u32() % n; }
  pick(a) { return a[this.int(a.length)]; }
  bytes(n) { const o = new Uint8Array(n); let i = 0; while (i + 4 <= n) { const v = this.u32(); o[i++] = v; o[i++] = v >>> 8; o[i++] = v >>> 16; o[i++] = v >>> 24; } if (i < n) { let v = this.u32(); while (i < n) { o[i++] = v; v >>>= 8; } } return o; }
}

/** Block-boundary and structural message lengths for SHA-2 (64/128), SHA-3/SHAKE rates (72..168), HMAC (block +-1). */
export const BOUNDARY_LENGTHS = (() => {
  const s = new Set([0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 47, 48, 49]);
  for (const b of [64, 72, 104, 128, 136, 144, 168, 200, 256, 512, 1024, 4096])
    for (const k of [1, 2, 3]) for (const d of [-9, -8, -2, -1, 0, 1, 2, 8]) if (b * k + d >= 0) s.add(b * k + d);
  for (const n of [55, 56, 63, 64, 111, 112, 119, 120, 127, 128, 135, 136, 167, 168]) s.add(n);
  s.add(65535); s.add(65536); s.add(1 << 20); s.add((1 << 20) + 1);
  return [...s].sort((a, b) => a - b);
})();

export function patterned(n, kind, rng) {
  if (kind === 0) return new Uint8Array(n);
  if (kind === 1) return new Uint8Array(n).fill(0xff);
  if (kind === 2) { const o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = i & 255; return o; }
  return rng.bytes(n);
}

/** Accumulates divergences with a bounded sample, keyed by a signature string so the report stays small. */
export class Report {
  constructor() { this.suites = {}; this.divergences = []; this.counts = {}; }
  count(suite, k, n = 1) { const s = (this.suites[suite] ??= {}); s[k] = (s[k] ?? 0) + n; }
  diverge(suite, kind, detail) {
    const key = suite + '|' + kind; this.counts[key] = (this.counts[key] ?? 0) + 1;
    if (this.counts[key] <= 25) this.divergences.push({ suite, kind, ...detail });
  }
}
