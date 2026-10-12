import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { R, bytesToScalar, isIllFormedUtf16, scalarToBytes } from '../bls';
import { recoverSecret, splitSecret } from '../sss';
import { b64u, unb64u } from '../wire';
import { decrypt, encryptForPolicy, keygenForAttributes, setup } from '../index';

const scalar = fc.bigInt({ min: 0n, max: R - 1n });

describe('Shamir sharing over Z_r (fast-check)', () => {
  it('any t of n shares reconstruct, for random secret / t / n / subset', () => {
    fc.assert(
      fc.property(scalar, fc.integer({ min: 1, max: 6 }), fc.integer({ min: 0, max: 4 }), fc.infiniteStream(fc.nat()), (secret, t, extra, rnd) => {
        const n = t + extra;
        const shares = splitSecret(secret, t, n);
        const order = shares.map((s, i) => ({ s, k: rnd.next().value as number, i })).sort((a, b) => a.k - b.k || a.i - b.i);
        const pick = order.slice(0, t).map((o) => o.s);
        return recoverSecret(pick) === secret;
      }),
      { numRuns: 200 },
    );
  });

  it('t-1 shares are consistent with EVERY secret (information-theoretic hiding): for any candidate secret there is a degree t-1 polynomial through the shares', () => {
    fc.assert(
      fc.property(scalar, scalar, fc.integer({ min: 2, max: 5 }), (secret, candidate, t) => {
        const shares = splitSecret(secret, t, t);
        const known = shares.slice(0, t - 1);
        // The point (0, candidate) together with the t-1 known shares determines a unique degree t-1 polynomial.
        // Interpolating it at the withheld x must produce a share value; both secrets are therefore consistent.
        const withheld = shares[t - 1]!;
        const through = [{ x: 0n, y: candidate }, ...known];
        // Lagrange-evaluate at withheld.x over Z_r using the same primitive via a shift: evaluate by recoverSecret on re-based points.
        const ev = lagrangeAt(through, withheld.x);
        const pointsForCandidate = [...known, { x: withheld.x, y: ev }];
        return recoverSecret(pointsForCandidate) === candidate;
      }),
      { numRuns: 100 },
    );
  });

  it('rejects duplicate x, zero x and empty input; refuses invalid t/n', () => {
    expect(recoverSecret([])).toBeNull();
    expect(recoverSecret([{ x: 1n, y: 1n }, { x: 1n, y: 2n }])).toBeNull();
    expect(recoverSecret([{ x: 0n, y: 5n }])).toBeNull();
    for (const [t, n] of [[0, 1], [2, 1], [1.5, 2], [-1, 3], [1, 0]] as const) expect(() => splitSecret(5n, t, n)).toThrow();
  });

  it('x and x+r alias (mod-r evaluation points) is not a way to forge a duplicate-free set from one share', () => {
    const [s1] = splitSecret(42n, 2, 2);
    // two "different" x values that are the same field element: recovery must not return a bogus value silently
    expect(recoverSecret([s1!, { x: s1!.x + R, y: s1!.y }])).toBeNull();
    expect(recoverSecret([{ x: R, y: 1n }])).toBeNull(); // x = r is the field element 0
  });

  it('share distribution of one share does not depend on the secret (bucketed uniformity sanity)', () => {
    const buckets = (secret: bigint) => {
      const b = new Array<number>(8).fill(0);
      for (let i = 0; i < 800; i++) b[Number((splitSecret(secret, 2, 2)[0]!.y * 8n) / R)]!++;
      return b;
    };
    for (const secret of [0n, 1n, R - 1n]) {
      for (const c of buckets(secret)) expect(c).toBeGreaterThan(45); // expected 100 per bucket; a leaky share would pile up
    }
  });
});

function lagrangeAt(points: { x: bigint; y: bigint }[], at: bigint): bigint {
  const mod = (a: bigint) => ((a % R) + R) % R;
  const inv = (a: bigint): bigint => {
    let [r0, r1, s0, s1] = [R, mod(a), 0n, 1n];
    while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    return mod(s0);
  };
  let total = 0n;
  for (let i = 0; i < points.length; i++) {
    let num = 1n, den = 1n;
    for (let j = 0; j < points.length; j++) if (i !== j) { num = mod(num * mod(at - points[j]!.x)); den = mod(den * mod(points[i]!.x - points[j]!.x)); }
    total = mod(total + points[i]!.y * num * inv(den));
  }
  return total;
}

describe('wire canonicality (fast-check)', () => {
  it('unb64u accepts exactly the canonical encodings: decode(encode(x)) == x and re-encoding is the identity', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 80 }), (bytes) => {
        const s = b64u(bytes);
        const back = unb64u(s);
        return back !== null && Buffer.from(back).equals(Buffer.from(bytes));
      }),
    );
  });
  it('any string that decodes also re-encodes to itself (no two strings decode to the same bytes)', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 40 }), (s) => {
        const d = unb64u(s);
        return d === null || b64u(d) === s;
      }),
      { numRuns: 1000 },
    );
  });
  it('scalar encoding is a bijection on [0, r) and bytesToScalar reduces mod r only for 32-byte inputs', () => {
    fc.assert(fc.property(scalar, (k) => bytesToScalar(scalarToBytes(k)) === k), { numRuns: 200 });
    expect(bytesToScalar(new Uint8Array(31))).toBeNull();
    expect(bytesToScalar(new Uint8Array(33))).toBeNull();
  });
});

describe('end-to-end properties (fast-check)', () => {
  it('encrypt/decrypt round-trips arbitrary payloads under arbitrary non-empty well-formed attributes, and a key for another attribute never opens it', () => {
    const { mpk, msk } = setup();
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 200 }), fc.string({ minLength: 1, maxLength: 20 }).filter((s) => !isIllFormedUtf16(s)), (pt, attr) => {
        const { ciphertext } = encryptForPolicy(mpk, { attr }, pt);
        const ok = decrypt(keygenForAttributes(msk, [attr]), ciphertext);
        const no = decrypt(keygenForAttributes(msk, [attr + '\u0001']), ciphertext);
        return ok !== null && Buffer.from(ok).equals(Buffer.from(pt)) && no === null;
      }),
      { numRuns: 25 },
    );
  });
});
