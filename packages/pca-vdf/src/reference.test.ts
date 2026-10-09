import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';
import {
  type VdfRejection,
  bigIntToBytes,
  hashToPrime,
  isProbablePrime,
  vdfEval,
  vdfVerify,
  vdfVerifyDetailed,
} from './vdf';

const execFileAsync = promisify(execFile);
const root = join(__dirname, '..');

interface Positive {
  modulus: string;
  x: string;
  T: number;
  y: string;
  pi: string;
  l: string;
}
interface Negative {
  modulus: string;
  label: string;
  x: string;
  y: string;
  pi: string;
  T: number;
  reason: VdfRejection;
}
interface Vectors {
  provenance: { kind: string; libraries: { gmpy2: string; GMP: string; python: string } };
  moduli: Record<string, unknown>;
  positives: Positive[];
  negatives: Negative[];
}

function readJson(rel: string): unknown {
  return JSON.parse(readFileSync(join(root, rel), 'utf8'));
}

const vectors = readJson('fixtures/wesolowski-reference-vectors.json') as Vectors;
const rsa = readJson('fixtures/rsa-2048.json') as { decimal: string };

function modulusOf(name: string): bigint {
  if (name === 'rsa-2048-challenge') return BigInt(rsa.decimal);
  const m = vectors.moduli[name] as { N: string } | undefined;
  if (m === undefined) throw new Error(`unknown modulus ${name}`);
  return BigInt(m.N);
}

describe('reference vectors from an independent Python/GMP implementation (self-written, not official)', () => {
  it('declares itself as self-written, never as an official vector set', () => {
    expect(vectors.provenance.kind).toMatch(/SELF-WRITTEN/);
    expect(vectors.provenance.kind).toMatch(/NOT official/);
    expect(vectors.provenance.libraries.gmpy2).toBe('2.3.2');
    expect(vectors.positives.length).toBeGreaterThanOrEqual(40);
    expect(vectors.negatives.length).toBeGreaterThanOrEqual(20);
  });

  it('TypeScript eval reproduces the reference y, pi and challenge prime l exactly', () => {
    for (const v of vectors.positives) {
      const N = modulusOf(v.modulus);
      const x = BigInt(v.x);
      const got = vdfEval(x, v.T, N);
      expect(got.y.toString(), `y ${v.modulus} T=${v.T}`).toBe(v.y);
      expect(got.pi.toString(), `pi ${v.modulus} T=${v.T}`).toBe(v.pi);
      expect(hashToPrime(x, got.y, v.T, N).toString(), `l ${v.modulus} T=${v.T}`).toBe(v.l);
    }
  }, 120_000);

  it('TypeScript verify accepts every reference proof', () => {
    for (const v of vectors.positives) {
      const N = modulusOf(v.modulus);
      expect(vdfVerify(BigInt(v.x), BigInt(v.y), BigInt(v.pi), v.T, N), `${v.modulus} T=${v.T}`).toBe(true);
    }
  });

  it('TypeScript verify rejects every reference negative with the SAME reason code', () => {
    const reasons = new Set<string>();
    for (const n of vectors.negatives) {
      const N = modulusOf(n.modulus);
      const verdict = vdfVerifyDetailed(BigInt(n.x), BigInt(n.y), BigInt(n.pi), n.T, N);
      expect(verdict, n.label).toEqual({ ok: false, reason: n.reason });
      reasons.add(n.reason);
    }
    // the negatives exercise every refusal path except the type/steps guards covered below
    expect([...reasons].sort()).toEqual(['bad-input-x', 'equation-mismatch', 'non-canonical-pi', 'non-canonical-y']);
  });

  it('guards that need no vector: malformed types, bad modulus, bad step count', () => {
    const N = modulusOf('rsa-2048-challenge');
    expect(vdfVerifyDetailed(2n, 4n, 1n, -1, N)).toEqual({ ok: false, reason: 'bad-steps' });
    expect(vdfVerifyDetailed(2n, 4n, 1n, 1.5, N)).toEqual({ ok: false, reason: 'bad-steps' });
    expect(vdfVerifyDetailed(2n, 4n, 1n, 1, 100n)).toEqual({ ok: false, reason: 'bad-modulus' }); // even
    expect(vdfVerifyDetailed(2n, 4n, 1n, 1, 3n)).toEqual({ ok: false, reason: 'bad-modulus' });
    // @ts-expect-error deliberately wrong runtime types
    expect(vdfVerifyDetailed('2', 4n, 1n, 1, N)).toEqual({ ok: false, reason: 'malformed-input' });
  });

  it('the hash-to-prime transcript matches a hand-built byte string (framing is part of the spec)', () => {
    // Re-derive l from first principles with node:crypto (not @noble/hashes) for one vector.
    const v = vectors.positives[5]!;
    const N = modulusOf(v.modulus);
    const u32 = (n: number): Buffer => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(n);
      return b;
    };
    const lp = (b: Uint8Array): Buffer => Buffer.concat([u32(b.length), Buffer.from(b)]);
    const transcript = Buffer.concat([
      Buffer.from('atlas-pca/vdf/wesolowski/hash-to-prime/v1\0'),
      lp(bigIntToBytes(BigInt(v.x) % N)),
      lp(bigIntToBytes(BigInt(v.y) % N)),
      lp(bigIntToBytes(BigInt(v.T))),
      lp(bigIntToBytes(N)),
      lp(u32(256)),
    ]);
    const seed = createHash('sha256').update(transcript).digest();
    let counter = 0n;
    for (;;) {
      const ctr = Buffer.alloc(8);
      ctr.writeBigUInt64BE(counter);
      const raw = Buffer.concat(
        [0, 1].map((i) => createHash('sha256').update(Buffer.concat([seed, ctr, u32(i)])).digest()),
      ).subarray(0, 32);
      const cand = (BigInt('0x' + raw.toString('hex')) & ((1n << 256n) - 1n)) | (1n << 255n) | 1n;
      if (isProbablePrime(cand)) {
        expect(cand.toString()).toBe(v.l);
        return;
      }
      counter += 1n;
    }
  });
});

// ---------------------------------------------------------------------------------------------
// Live differential check against the Python reference (set PCA_VDF_REFERENCE_PYTHON to an
// interpreter with gmpy2==2.3.2, e.g. `uv venv .venv && uv pip install --python .venv/bin/python gmpy2==2.3.2`).
// Skipped (and reported as skipped) otherwise; the committed vectors above always run.
// ---------------------------------------------------------------------------------------------
const py = process.env['PCA_VDF_REFERENCE_PYTHON'];

async function runPy(cmd: string, input: unknown): Promise<unknown> {
  if (py === undefined) throw new Error('PCA_VDF_REFERENCE_PYTHON not set');
  const dir = mkdtempSync(join(tmpdir(), 'pca-vdf-ref-'));
  try {
    writeFileSync(join(dir, 'in.json'), JSON.stringify(input));
    await execFileAsync(py, [join(root, 'reference', 'wesolowski_ref.py'), cmd, join(dir, 'in.json'), join(dir, 'out.json')]);
    return JSON.parse(readFileSync(join(dir, 'out.json'), 'utf8'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Small deterministic PRNG so the differential inputs are reproducible. */
function lcg(seed: number): () => bigint {
  let s = BigInt(seed);
  return () => {
    s = (s * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    return s;
  };
}

describe.skipIf(py === undefined)('live differential check vs Python/GMP reference', () => {
  const N = BigInt(rsa.decimal);

  it('fresh random (x, T) on RSA-2048: both implementations produce identical y, pi, l and cross-verify', async () => {
    const rnd = lcg(20261008);
    const cases: Array<{ N: string; x: string; T: number }> = [];
    for (let i = 0; i < 12; i++) {
      const x = ((rnd() << 192n) ^ (rnd() << 128n) ^ (rnd() << 64n) ^ rnd()) % (N - 4n) + 2n;
      cases.push({ N: N.toString(), x: x.toString(), T: Number(rnd() % 3000n) });
    }
    const ref = (await runPy('eval', cases)) as Array<{ y: string; pi: string; l: string }>;
    const toVerify: Array<{ N: string; x: string; y: string; pi: string; T: number }> = [];
    cases.forEach((c, i) => {
      const mine = vdfEval(BigInt(c.x), c.T, N);
      expect(mine.y.toString()).toBe(ref[i]!.y);
      expect(mine.pi.toString()).toBe(ref[i]!.pi);
      expect(hashToPrime(BigInt(c.x), mine.y, c.T, N).toString()).toBe(ref[i]!.l);
      // TS proof -> Python verify; Python proof -> TS verify
      toVerify.push({ N: c.N, x: c.x, y: mine.y.toString(), pi: mine.pi.toString(), T: c.T });
      expect(vdfVerify(BigInt(c.x), BigInt(ref[i]!.y), BigInt(ref[i]!.pi), c.T, N)).toBe(true);
      // and a tampered one: both must refuse, with the same reason
      toVerify.push({ N: c.N, x: c.x, y: mine.y.toString(), pi: (mine.pi + 1n).toString(), T: c.T });
    });
    const verdicts = (await runPy('verify', toVerify)) as Array<{ ok: boolean; reason: string | null }>;
    toVerify.forEach((v, i) => {
      const mine = vdfVerifyDetailed(BigInt(v.x), BigInt(v.y), BigInt(v.pi), v.T, N);
      expect(verdicts[i]!.ok).toBe(mine.ok);
      if (!mine.ok) expect(verdicts[i]!.reason).toBe(mine.reason);
    });
    expect(verdicts.filter((v) => v.ok)).toHaveLength(cases.length);
  }, 300_000);

  it('Miller-Rabin agrees with GMP on random odd numbers, Carmichael numbers and strong pseudoprimes', async () => {
    const rnd = lcg(7);
    const nums: bigint[] = [];
    for (let i = 0; i < 3000; i++) nums.push(((rnd() << 64n) | rnd()) | 1n);
    for (let i = 0; i < 300; i++) nums.push((((rnd() << 128n) | (rnd() << 64n) | rnd()) << 100n) | 1n | (1n << 255n));
    nums.push(
      561n, 1105n, 1729n, 2465n, 2821n, 6601n, 8911n, // Carmichael
      2047n, 3277n, 4033n, 4681n, 8321n, 15841n, 29341n, 42799n, 49141n, 52633n, 65281n, 74665n, 80581n, 85489n, 88357n, // strong pseudoprimes to base 2
      3215031751n, // strong pseudoprime to bases 2,3,5,7
      318665857834031151167461n, // strong pseudoprime to the first 12 prime bases
      3317044064679887385961981n, // strong pseudoprime to the first 13 prime bases
      (1n << 127n) - 1n, (1n << 521n) - 1n, (1n << 607n) - 1n, // Mersenne primes
      (1n << 128n) - 1n, // composite
    );
    const ref = (await runPy('isprime', nums.map((n) => n.toString()))) as boolean[];
    const disagreements = nums.filter((n, i) => isProbablePrime(n) !== ref[i]);
    expect(disagreements).toEqual([]);
  }, 120_000);
});
