import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, randomBytes as nobleRandomBytes } from '@noble/hashes/utils';

/**
 * ============================================================================
 *  Wesolowski Verifiable Delay Function (VDF) over an RSA group
 * ============================================================================
 *
 * A VDF is a function whose evaluation REQUIRES a prescribed number `T` of
 * *sequential* steps (here, modular squarings in Z_N* — a chain that cannot be
 * parallelised because each square needs the previous one), yet whose result
 * carries a proof anyone can check in O(log) work. There is no clock to trust:
 * the only thing a verifier learns is that `T` squarings provably happened.
 *
 * Construction (Wesolowski, EUROCRYPT 2019):
 *
 *   eval(x, T, N):
 *     y  = x^(2^T) mod N                 -- computed by T sequential squarings
 *     l  = hashToPrime(x, y, T, N)       -- a Fiat-Shamir challenge prime
 *     pi = x^( floor(2^T / l) ) mod N    -- the Wesolowski proof
 *
 *   verify(x, y, pi, T, N):
 *     l  = hashToPrime(x, y, T, N)
 *     r  = 2^T mod l
 *     accept  iff  pi^l * x^r  ==  y   (mod N)
 *
 * Soundness identity: write 2^T = l*q + r with q = floor(2^T/l) and r = 2^T mod
 * l. Then x^(2^T) = x^(l*q+r) = (x^q)^l * x^r = pi^l * x^r. A prover who did not
 * actually iterate the squaring chain cannot produce a `pi` that satisfies the
 * check for the random prime `l` (except with negligible probability), because
 * `l` is fixed by a hash of `y` and `y` itself requires the full chain.
 *
 * The prover computes `pi` WITHOUT ever materialising the astronomically large
 * integer 2^T, via a running long-division by `l` (see {@link wesolowskiProof}).
 * Verification is cheap: `2^T mod l` is one modpow with a ~log2(T)-bit exponent,
 * and `pi^l`, `x^r` are modpows with |l|-bit exponents. OFFLINE and clock-free.
 *
 * ----------------------------------------------------------------------------
 *  TRUSTED SETUP — read this honestly
 * ----------------------------------------------------------------------------
 * An RSA-group VDF is only a delay function if the modulus `N` has UNKNOWN
 * factorisation. Anyone who knows `N = p*q` knows the group order
 * phi(N) = (p-1)(q-1) and can shortcut the whole chain:
 *
 *     y = x^( 2^T mod phi(N) ) mod N
 *
 * i.e. they reduce the exponent `2^T` modulo phi(N) with a single modpow and
 * skip the T squarings entirely. So the holder of the factors has a TRAPDOOR
 * that destroys the delay. Consequences:
 *
 *   - {@link setup} GENERATES N = p*q itself, so IT KNOWS THE TRAPDOOR. It is
 *     for development, tests, and local experiments ONLY — never a production
 *     timelock. It returns `p` and `q` precisely so an operator who insists on
 *     a self-generated modulus can run a trusted/MPC ceremony and provably
 *     DESTROY the factors.
 *
 *   - For a real deployment, use a modulus whose factors nobody holds:
 *       * {@link RSA_2048_CHALLENGE_MODULUS} — the RSA Factoring Challenge
 *         RSA-2048 number, whose factorisation has never been published
 *         (verify the digits against the published challenge before trusting
 *         it; see the constant's doc), OR
 *       * a modulus from a multi-party RSA-UFO / "RSA modulus of unknown order"
 *         ceremony where no single party ever sees the primes.
 *
 *   - The genuinely TRUSTLESS alternative is a VDF over an imaginary quadratic
 *     CLASS GROUP, whose order is hard to compute from public parameters, so no
 *     trusted setup is needed at all. That construction is OUT OF SCOPE here
 *     (it needs class-group arithmetic, not native bigint modmul); this package
 *     deliberately ships the simpler, well-understood RSA-group VDF and is
 *     honest that it inherits the RSA unknown-order assumption.
 */

/** A Wesolowski VDF proof: the output `y` and the succinct proof `pi`. */
export interface VdfProof {
  /** `y = x^(2^T) mod N`. */
  readonly y: bigint;
  /** The Wesolowski proof `pi = x^floor(2^T / l) mod N`. */
  readonly pi: bigint;
}

/** Result of {@link setup}: the modulus plus the (TRAPDOOR) factors it was built from. */
export interface VdfSetup {
  /** The RSA modulus `N = p*q`. */
  readonly N: bigint;
  /** First prime factor — KNOWING THIS IS THE TRAPDOOR. Destroy it for any real use. */
  readonly p: bigint;
  /** Second prime factor — KNOWING THIS IS THE TRAPDOOR. Destroy it for any real use. */
  readonly q: bigint;
  /** Approximate bit length of `N`. */
  readonly bits: number;
}

/** Bit length of the Fiat-Shamir challenge prime `l` (the soundness parameter). */
export const CHALLENGE_PRIME_BITS = 256;

/** Default bit length {@link setup} targets for `N` when the caller gives none. */
export const DEFAULT_SETUP_BITS = 2048;

/**
 * The RSA Factoring Challenge **RSA-2048** modulus (617 decimal digits, 2048
 * bits). Its factorisation has never been published, which is exactly the
 * property an RSA-group VDF needs. Shipped as a documented honest default so a
 * caller need not run a setup ceremony.
 *
 * INTEGRITY NOTE: verify these digits against the published RSA-2048 value from
 * the RSA Factoring Challenge before relying on it for anything of value — a
 * transcription slip would still leave a ~2048-bit composite of unknown
 * factorisation (so the VDF stays sound), but it would NOT be the number whose
 * provenance the challenge documents. If you need a provenance you have checked
 * yourself, pass your own `N`.
 */
export const RSA_2048_CHALLENGE_MODULUS: bigint = BigInt(
  '2519590847565789349402718324004839857142928212620403202777713783604366202070' +
    '7595556264018525880784406918290641249515082189298559149176184502808489120072' +
    '8449926873928072877767359714183472702618963750149718246911650776133798590957' +
    '0009733045974880842840179742910064245869181719511874612151517265463228221686' +
    '9987549182422433637259085141865462043576798423387184774447920739934236584823' +
    '8242811981638150106748104516603773060562016196762561338441436038339044149526' +
    '3443219011465754445417842402092461651572335077870774981712577246796292638635' +
    '6373289912154831438167899885040445364023527381951378636564391212010397122822' +
    '120720357',
);

/**
 * Honest large default modulus = {@link RSA_2048_CHALLENGE_MODULUS}. Prefer a
 * caller-supplied `N` (or a class-group VDF) when the provenance of this value
 * matters to you; see the module trusted-setup note.
 */
export const DEFAULT_MODULUS: bigint = RSA_2048_CHALLENGE_MODULUS;

// ---------------------------------------------------------------------------
// bigint / byte helpers
// ---------------------------------------------------------------------------

/** Big-endian bytes -> non-negative bigint. */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let r = 0n;
  for (const byte of bytes) r = (r << 8n) | BigInt(byte);
  return r;
}

/** Non-negative bigint -> minimal big-endian bytes (`0n` -> a single `0x00`). */
export function bigIntToBytes(value: bigint): Uint8Array {
  if (value < 0n) throw new RangeError('bigIntToBytes: negative value');
  if (value === 0n) return new Uint8Array([0]);
  const out: number[] = [];
  let v = value;
  while (v > 0n) {
    out.push(Number(v & 0xffn));
    v >>= 8n;
  }
  out.reverse();
  return Uint8Array.from(out);
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

function u64be(value: bigint): Uint8Array {
  const b = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

/** Length-prefixed (4-byte BE) framing so concatenations are unambiguous. */
function lenPrefixed(bytes: Uint8Array): Uint8Array {
  return concatBytes(u32be(bytes.length), bytes);
}

/** Normalise an integer step count `T`, rejecting anything that is not a non-negative safe integer. */
function normalizeSteps(T: number): bigint {
  if (!Number.isSafeInteger(T) || T < 0) throw new RangeError(`VDF: steps T must be a non-negative safe integer, got ${String(T)}`);
  return BigInt(T);
}

// ---------------------------------------------------------------------------
// modular exponentiation
// ---------------------------------------------------------------------------

/** `base^exp mod mod` by square-and-multiply. `exp >= 0`, `mod > 0`. */
export function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod <= 0n) throw new RangeError('modpow: modulus must be positive');
  if (mod === 1n) return 0n;
  if (exp < 0n) throw new RangeError('modpow: negative exponent (no inverse in a group of unknown order)');
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) result = (result * b) % mod;
    e >>= 1n;
    if (e > 0n) b = (b * b) % mod;
  }
  return result;
}

// ---------------------------------------------------------------------------
// primality (deterministic Miller-Rabin with a fixed base set)
// ---------------------------------------------------------------------------

const SMALL_PRIMES: readonly bigint[] = [
  2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n,
];

/**
 * Miller-Rabin bases. Fixed and deterministic so the prover and an offline
 * verifier that both run {@link hashToPrime} agree on the SAME `l` regardless of
 * platform. With these bases the probabilistic error for the 256-bit challenge
 * prime is far below any adversary's reach; a verifier that wants certified
 * primality can re-test `l` with its own primality routine (the VDF check is
 * unaffected — both sides already derived the identical `l`).
 */
const MR_BASES: readonly bigint[] = SMALL_PRIMES;

/** Probabilistic primality test (deterministic given {@link MR_BASES}). */
export function isProbablePrime(n: bigint): boolean {
  if (n < 2n) return false;
  for (const p of SMALL_PRIMES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  // n - 1 = d * 2^s, d odd.
  let d = n - 1n;
  let s = 0n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s += 1n;
  }
  witness: for (const a of MR_BASES) {
    const base = a % n;
    if (base === 0n) continue;
    let x = modpow(base, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let i = 1n; i < s; i += 1n) {
      x = (x * x) % n;
      if (x === n - 1n) continue witness;
    }
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// hash-to-prime (Fiat-Shamir challenge l)
// ---------------------------------------------------------------------------

const HASH_TO_PRIME_DOMAIN = 'atlas-pca/vdf/wesolowski/hash-to-prime/v1\0';

/**
 * Derive the Fiat-Shamir challenge prime `l` deterministically from the full
 * transcript `(x, y, T, N)`. Binding `l` to `y` and `T` is what makes the proof
 * sound: a prover cannot pick `l` before computing the real `y`. `x`, `y` are
 * reduced mod `N` first so prover and verifier hash identical values.
 *
 * It hashes the transcript to a seed, then walks a counter: for each counter it
 * expands `sha256(seed ‖ counter ‖ block)` into `bits` bits, forces the top and
 * bottom bits set (so the candidate is exactly `bits` long and odd), and returns
 * the first probable prime. Fully deterministic -> reproducible offline.
 */
export function hashToPrime(x: bigint, y: bigint, T: number, N: bigint, bits: number = CHALLENGE_PRIME_BITS): bigint {
  if (!Number.isSafeInteger(bits) || bits < 8) throw new RangeError('hashToPrime: bits must be a safe integer >= 8');
  const steps = normalizeSteps(T);
  const xr = ((x % N) + N) % N;
  const yr = ((y % N) + N) % N;
  const transcript = concatBytes(
    new TextEncoder().encode(HASH_TO_PRIME_DOMAIN),
    lenPrefixed(bigIntToBytes(xr)),
    lenPrefixed(bigIntToBytes(yr)),
    lenPrefixed(bigIntToBytes(steps)),
    lenPrefixed(bigIntToBytes(N)),
    lenPrefixed(u32be(bits)),
  );
  const seed = sha256(transcript);
  const bytesNeeded = Math.ceil(bits / 8);
  const topBit = 1n << BigInt(bits - 1);
  const mask = (1n << BigInt(bits)) - 1n;

  for (let counter = 0n; ; counter += 1n) {
    const chunks: Uint8Array[] = [];
    let have = 0;
    for (let blockIndex = 0; have < bytesNeeded; blockIndex += 1) {
      const block = sha256(concatBytes(seed, u64be(counter), u32be(blockIndex)));
      chunks.push(block);
      have += block.length;
    }
    const raw = concatBytes(...chunks).subarray(0, bytesNeeded);
    const candidate = (bytesToBigInt(raw) & mask) | topBit | 1n;
    if (isProbablePrime(candidate)) return candidate;
  }
}

// ---------------------------------------------------------------------------
// the VDF: eval / verify
// ---------------------------------------------------------------------------

/**
 * Compute the enforced delay `y = x^(2^T) mod N` by T REAL sequential squarings.
 * This is the work that cannot be skipped without the factorisation of `N`.
 */
export function sequentialSquare(x: bigint, T: number, N: bigint): bigint {
  if (N <= 1n) throw new RangeError('VDF: modulus N must be > 1');
  const steps = normalizeSteps(T);
  let y = ((x % N) + N) % N;
  for (let i = 0n; i < steps; i += 1n) {
    y = (y * y) % N;
  }
  return y;
}

/**
 * The Wesolowski prover's long-division trick. Returns `pi = x^floor(2^T/l) mod
 * N` using T squarings and a running remainder of `2^i mod l`, so the enormous
 * integer `2^T` is NEVER formed.
 *
 * Invariant after step `i`: `pi = x^floor(2^i / l) mod N` and `r = 2^i mod l`.
 * Step: `2^{i+1} = 2*(q_i*l + r_i) = (2*q_i + b)*l + r_{i+1}` where
 * `b = floor(2*r_i / l) in {0,1}` and `r_{i+1} = 2*r_i mod l`, hence
 * `q_{i+1} = 2*q_i + b` and `pi <- pi^2 * x^b`.
 */
function wesolowskiProof(x: bigint, T: bigint, l: bigint, N: bigint): bigint {
  const xr = ((x % N) + N) % N;
  let pi = 1n % N;
  let r = 1n % l;
  for (let i = 0n; i < T; i += 1n) {
    const twoR = r * 2n;
    const b = twoR / l; // 0 or 1 since r < l
    r = twoR % l;
    pi = (pi * pi) % N;
    if (b === 1n) pi = (pi * xr) % N;
  }
  return pi;
}

/**
 * Evaluate the VDF: `y = x^(2^T) mod N` by T sequential squarings (the delay),
 * plus the Wesolowski proof `pi`. The challenge prime is
 * `l = hashToPrime(x, y, T, N)`.
 */
export function vdfEval(x: bigint, T: number, N: bigint): VdfProof {
  if (N <= 3n) throw new RangeError('VDF: modulus N must be > 3');
  const steps = normalizeSteps(T);
  const y = sequentialSquare(x, T, N);
  const l = hashToPrime(x, y, T, N);
  const pi = wesolowskiProof(x, steps, l, N);
  return { y, pi };
}

/**
 * Verify a VDF proof in O(log) work: recompute `l = hashToPrime(x, y, T, N)`,
 * compute `r = 2^T mod l`, and accept iff `pi^l * x^r == y (mod N)`.
 *
 * FAIL CLOSED: any malformed input, out-of-range value, or mismatch returns
 * `false` (never throws). Because `l` is bound to `x`, `y`, `T` and `N`, a wrong
 * `x` (e.g. one not derived from the intended action), wrong `y`, wrong `pi`, or
 * wrong `T` all change the equation and are rejected.
 */
export function vdfVerify(x: bigint, y: bigint, pi: bigint, T: number, N: bigint): boolean {
  try {
    if (typeof x !== 'bigint' || typeof y !== 'bigint' || typeof pi !== 'bigint' || typeof N !== 'bigint') return false;
    if (N <= 3n) return false;
    if (!Number.isSafeInteger(T) || T < 0) return false;
    const yr = ((y % N) + N) % N;
    const xr = ((x % N) + N) % N;
    const pir = ((pi % N) + N) % N;
    const l = hashToPrime(x, yr, T, N);
    if (l <= 1n) return false;
    const r = modpow(2n, BigInt(T), l);
    const lhs = (modpow(pir, l, N) * modpow(xr, r, N)) % N;
    return lhs === yr;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// setup (DEV / TEST ONLY — generates and therefore KNOWS the trapdoor)
// ---------------------------------------------------------------------------

function randomPrime(bits: number, rnd: (n: number) => Uint8Array): bigint {
  if (bits < 16) throw new RangeError('randomPrime: bits too small');
  const bytes = Math.ceil(bits / 8);
  const topBit = 1n << BigInt(bits - 1);
  const mask = (1n << BigInt(bits)) - 1n;
  for (;;) {
    const candidate = (bytesToBigInt(rnd(bytes)) & mask) | topBit | 1n;
    if (isProbablePrime(candidate)) return candidate;
  }
}

/**
 * Generate an RSA modulus `N = p*q` for DEVELOPMENT / TESTS ONLY.
 *
 * It knows `p` and `q`, i.e. it holds the TRAPDOOR that lets the holder shortcut
 * the delay (see the module trusted-setup note). Never use a self-generated `N`
 * as a real timelock unless the factors were produced and destroyed by a trusted
 * / MPC ceremony. `p` and `q` are returned precisely so they can be destroyed.
 *
 * @param opts.bits         target bit length of `N` (default {@link DEFAULT_SETUP_BITS}).
 * @param opts.randomBytes  randomness source (default `@noble/hashes` CSPRNG).
 */
export function setup(opts?: { bits?: number; randomBytes?: (n: number) => Uint8Array }): VdfSetup {
  const bits = opts?.bits ?? DEFAULT_SETUP_BITS;
  if (!Number.isSafeInteger(bits) || bits < 32) throw new RangeError('setup: bits must be a safe integer >= 32');
  const rnd = opts?.randomBytes ?? ((n: number) => nobleRandomBytes(n));
  const half = Math.floor(bits / 2);
  let p = randomPrime(half, rnd);
  let q = randomPrime(bits - half, rnd);
  while (p === q) q = randomPrime(bits - half, rnd);
  const N = p * q;
  return { N, p, q, bits: N.toString(2).length };
}

/**
 * Ergonomic namespace mirroring the spec's `setup` / `eval` / `verify` names
 * (`eval` is a reserved identifier, so the free functions are `vdfEval` /
 * `vdfVerify`; this object exposes them under the spec names).
 */
export const vdf = {
  setup,
  eval: vdfEval,
  verify: vdfVerify,
  hashToPrime,
  sequentialSquare,
  modpow,
  isProbablePrime,
} as const;
