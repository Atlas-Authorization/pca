/**
 * Cryptographically-secure randomness — the default source for ALL protocol randomness (docs §7.1
 * item c). Every secret the protocol samples — base-OT scalars `x`/`y`, the Schnorr nonce, IKNP seeds,
 * Gilboa masks `ρ`, the MAC key shares `α_i`, triple shares `a_i`/`b_i`, and the sacrifice / input /
 * MAC-check coefficients — is drawn here from `node:crypto.randomBytes` unless a test explicitly asks
 * for a reproducible seeded stream.
 *
 * The deterministic SplitMix64 path (`field.ts` / `ot.ts`) is retained ONLY behind an explicit
 * `testSeed`, so tests stay bit-reproducible while production never silently runs on a deterministic
 * PRNG. The one deliberately-NON-secret source is the KOS challenge `χ` (`ot.ts`), which is a
 * public-coin Fiat–Shamir value derived from the committed transcript — it must be reproducible by
 * both parties and is therefore a transcript hash by design, not a secret the CSPRNG governs.
 *
 * NOTE on the remaining boundary (honest, docs §7.1): a real deployment also needs a *secure coin-flip*
 * among the parties for the public MAC-check / sacrifice coefficients (here a CSPRNG stands in for that
 * interactive sub-protocol), and a secret per-session seed management story. Using `randomBytes` closes
 * the "deterministic PRNG" caveat; it does not itself provide the multiparty coin-flip, which is a
 * network/protocol layer (§7.1 item: real async network).
 */

import { randomBytes } from 'node:crypto';
import { FieldRng, PRIME } from './field';
import { L } from './ec';
import type { OtRandom } from './ot';

const MASK64 = (1n << 64n) - 1n;

/** A minimal field-random source: `next()` yields a uniform element of F_p. `FieldRng` satisfies it. */
export interface FieldSource {
  next(): bigint;
}

/**
 * A CSPRNG-backed field RNG. Drop-in for `FieldRng` everywhere (it extends it and overrides `next()`),
 * so `share` / `setupMac` / `macCheck` / the no-dealer offline all accept it with no signature change.
 * Draws unbiased elements of F_p by rejection sampling over fresh `randomBytes`.
 */
export class SecureFieldRng extends FieldRng {
  constructor() {
    // The super ctor seeds the (now-unused) SplitMix64 state; `next()` below ignores it entirely.
    super(0n);
  }

  override next(): bigint {
    // Largest multiple of p that fits in 64 bits; reject anything at/above it so `% p` is exactly uniform.
    const limit = ((MASK64 + 1n) / PRIME) * PRIME;
    for (;;) {
      const buf = randomBytes(8);
      let u = 0n;
      for (let i = 0; i < 8; i++) u = (u << 8n) | BigInt(buf[i]!);
      if (u < limit) return u % PRIME;
    }
  }
}

/**
 * A CSPRNG-backed `OtRandom` (scalars in `[1, L)` by rejection, raw bytes from `randomBytes`). This is
 * the default randomness for every base OT / OT-extension / Schnorr nonce when no test seed is set.
 */
export function secureOtRandom(): OtRandom {
  return {
    scalar(): bigint {
      // 32 bytes → reject the top `2^256 mod L` residues so reduction mod L is exactly uniform; reject 0.
      const bound = (1n << 256n) - ((1n << 256n) % L);
      for (;;) {
        const buf = randomBytes(32);
        let acc = 0n;
        for (let i = 0; i < 32; i++) acc = (acc << 8n) | BigInt(buf[i]!);
        if (acc >= bound) continue;
        const s = acc % L;
        if (s !== 0n) return s;
      }
    },
    bytes(n: number): Uint8Array {
      return new Uint8Array(randomBytes(n));
    },
  };
}

/**
 * The field-randomness policy for the whole package: a CSPRNG by default, or a reproducible seeded
 * `FieldRng` ONLY when an explicit `testSeed` is given. Production calls this with no argument.
 */
export function fieldRandom(opts?: { testSeed?: bigint }): FieldSource {
  return opts?.testSeed === undefined ? new SecureFieldRng() : new FieldRng(opts.testSeed);
}
