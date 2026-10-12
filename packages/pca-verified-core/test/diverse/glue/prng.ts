// Tiny seeded PRNG for the glue drivers (xoshiro128**), so a failing case replays from GLUE_SEED.
export class Prng {
  private s = new Uint32Array(4);
  constructor(seed: number) {
    let z = seed >>> 0;
    const sm = () => { z = (z + 0x9e3779b9) >>> 0; let t = z ^ (z >>> 16); t = Math.imul(t, 0x21f0aaad); t ^= t >>> 15; t = Math.imul(t, 0x735a2d97); return (t ^ (t >>> 15)) >>> 0; };
    this.s.set([sm(), sm(), sm(), sm()]);
  }
  u32(): number {
    const s = this.s; const m = Math.imul(s[1]!, 5); const r = Math.imul(((m << 7) | (m >>> 25)) >>> 0, 9) >>> 0;
    const t = s[1]! << 9; s[2]! ^= s[0]!; s[3]! ^= s[1]!; s[1]! ^= s[2]!; s[0]! ^= s[3]!; s[2]! ^= t; s[3] = (s[3]! << 11) | (s[3]! >>> 21);
    return r;
  }
  int(n: number): number { return this.u32() % n; }
  pick<T>(a: readonly T[]): T { return a[this.int(a.length)]!; }
}
export function bytes(r: Prng, n: number): Uint8Array { const o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = r.u32() & 255; return o; }
