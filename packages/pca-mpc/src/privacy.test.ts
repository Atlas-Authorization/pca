import { describe, expect, it } from 'vitest';
import { FieldRng, PRIME, fmul, mod } from './field';
import { reconstruct, share, type SharedValue } from './sharing';
import { beaverMul, type OpenedMsg, type Triple } from './beaver';
import { composeSecure } from './runner';
import type { DecisionVector } from './party';

describe('PRIVACY: additive shares hide the secret (info-theoretic, N-1 colluders)', () => {
  it('any N-1 shares are consistent with EVERY possible secret', () => {
    // The strong statement: given all-but-one share, for any candidate secret there is exactly one
    // value of the missing share that reconstructs to it. So N-1 shares reveal nothing.
    const n = 4;
    const rng = new FieldRng(123n);
    const shares = share(42n, n, rng);
    for (const drop of [0, 1, 2, 3]) {
      const retained = shares.filter((_, i) => i !== drop);
      const sumRetained = retained.reduce((a, b) => mod(a + b), 0n);
      for (const candidate of [0n, 1n, 2n, 999n, PRIME - 1n]) {
        const neededMissing = mod(candidate - sumRetained);
        const full = shares.slice();
        full[drop] = neededMissing;
        expect(reconstruct(full)).toBe(candidate); // retained N-1 shares fit this secret too
      }
    }
  });

  it('the independent (non-last) shares do not depend on the secret', () => {
    // share() draws the first N-1 shares from the RNG independent of the secret; only the last is the
    // complement. So with the same RNG stream, two different secrets yield identical non-last shares.
    const n = 3;
    const a = share(0n, n, new FieldRng(7n));
    const b = share(1n, n, new FieldRng(7n));
    const c = share(1234567n, n, new FieldRng(7n));
    expect(a.slice(0, n - 1)).toEqual(b.slice(0, n - 1));
    expect(a.slice(0, n - 1)).toEqual(c.slice(0, n - 1));
    // only the dependent (last) share differs, and each still reconstructs correctly
    expect(reconstruct(a)).toBe(0n);
    expect(reconstruct(b)).toBe(1n);
    expect(reconstruct(c)).toBe(1234567n);
  });

  it('a single share is spread across the field (not constant, not the secret)', () => {
    // Statistical sanity check (the PRNG stands in for a CSPRNG): over many sharings of the SAME
    // secret, party 0's share takes many distinct, well-spread field values.
    const n = 3;
    const secret = 1n;
    const seen = new Set<string>();
    let min = PRIME;
    let max = 0n;
    for (let i = 0; i < 500; i++) {
      const s = share(secret, n, new FieldRng(BigInt(i + 1)))[0]!;
      seen.add(s.toString());
      if (s < min) min = s;
      if (s > max) max = s;
      expect(s).not.toBe(secret); // the share is not the plaintext
    }
    expect(seen.size).toBe(500); // all distinct (overwhelmingly likely for a 61-bit field)
    // spread covers a large fraction of the field
    expect(min < PRIME / 8n).toBe(true);
    expect(max > (PRIME / 8n) * 7n).toBe(true);
  });
});

describe('PRIVACY: Beaver openings are simulatable (reveal nothing about inputs)', () => {
  const n = 3;
  const tripleFor = (a: bigint, b: bigint, rng: FieldRng): Triple => ({
    a: share(a, n, rng),
    b: share(b, n, rng),
    c: share(fmul(a, b), n, rng),
  });

  it('for ANY inputs, a chosen triple reproduces ANY desired opened transcript (a simulator exists)', () => {
    // d = x-a, e = y-b. Pick a = x - dWant, b = y - eWant and the opening is exactly (dWant, eWant),
    // whatever x and y are. So the opened messages carry no information about the inputs.
    const dWant = 111n;
    const eWant = 222n;

    const runWith = (xVal: bigint, yVal: bigint): { opened: OpenedMsg[]; product: bigint } => {
      const rng = new FieldRng(555n);
      const x = share(xVal, n, rng);
      const y = share(yVal, n, rng);
      const a = mod(xVal - dWant);
      const b = mod(yVal - eWant);
      const triple = tripleFor(a, b, rng);
      const transcript: OpenedMsg[] = [];
      const z = beaverMul(x, y, triple, transcript);
      return { opened: transcript, product: reconstruct(z) };
    };

    const r1 = runWith(3n, 9n);
    const r2 = runWith(1000n, 7n); // completely different inputs

    // identical opened transcript despite different inputs
    expect(r1.opened.map((m) => [m.label, m.value.toString()])).toEqual(
      r2.opened.map((m) => [m.label, m.value.toString()]),
    );
    expect(r1.opened[0]!.value).toBe(dWant);
    expect(r1.opened[1]!.value).toBe(eWant);
    // ...and each run still computes the correct product (protocol is sound)
    expect(r1.product).toBe(mod(3n * 9n));
    expect(r2.product).toBe(mod(1000n * 7n));
  });

  it('openings are masked: d != x and spread across the field over random triples', () => {
    const xVal = 5n;
    const yVal = 6n;
    const seen = new Set<string>();
    for (let i = 0; i < 300; i++) {
      const rng = new FieldRng(BigInt(i + 1));
      const x = share(xVal, n, rng);
      const y = share(yVal, n, rng);
      const triple = tripleFor(rng.next(), rng.next(), rng); // random a,b => c = a*b
      const transcript: OpenedMsg[] = [];
      beaverMul(x, y, triple, transcript);
      const d = transcript[0]!.value;
      expect(d).not.toBe(xVal);
      seen.add(d.toString());
    }
    expect(seen.size).toBe(300); // masks are all distinct
  });
});

describe('PRIVACY: end-to-end — a corrupted party cannot read another party\'s decision', () => {
  it('a non-last party\'s held shares are identical whether another party allows or denies', () => {
    // Same seed => same RNG draw order => the independent (non-last) shares are fixed. A corrupted
    // non-last party therefore sees byte-identical shares regardless of other parties' private
    // decisions; only the LAST party holds the secret-dependent complement (and alone cannot
    // reconstruct — see the "reconstruction needs all shares" test).
    const Q = 8;
    const base: DecisionVector[] = [
      { allow: 0, t: 1, rQuant: 1 }, // party 0 (corrupted, non-last) denies
      { allow: 1, t: 2, rQuant: 3 }, // party 1 (last)
    ];
    const flipped: DecisionVector[] = [
      { allow: 0, t: 1, rQuant: 1 },
      { allow: 0, t: 3, rQuant: 7 }, // party 1 changed its ENTIRE private decision
    ];
    const a = composeSecure(base, { Q, seed: 2024n });
    const b = composeSecure(flipped, { Q, seed: 2024n });
    // party 0's share of every secret is identical across the two worlds
    expect(a.views[0]!.heldShares).toEqual(b.views[0]!.heldShares);
  });

  it('reconstruction needs ALL shares: a proper subset is uniform, not the secret', () => {
    const n = 3;
    const secret = 777n;
    const shares = share(secret, n, new FieldRng(11n));
    for (const drop of [0, 1, 2]) {
      const subsetSum = shares.filter((_, i) => i !== drop).reduce((x, y) => mod(x + y), 0n);
      expect(subsetSum).not.toBe(secret); // partial reconstruction is meaningless
    }
    expect(reconstruct(shares)).toBe(secret); // only the full set recovers it
  });
});
