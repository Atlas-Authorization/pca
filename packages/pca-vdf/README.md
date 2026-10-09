# @atlasauth/pca-vdf

A Verifiable Delay Function (VDF) timelock for Proof-Carrying Authority. It gives irreversible actions a
mandatory cooling-off period that is verifiable offline with no trusted clock: an action is released only
when a Wesolowski VDF proof shows that `steps` sequential modular squarings were performed on an input
derived from that exact action. Proving is slow by design (the work is the wait); verifying is cheap.

## Install

```sh
npm i @atlasauth/pca-vdf @atlasauth/pca
```

## Usage

```ts
import {
  RSA_2048_CHALLENGE_MODULUS as N, // a modulus of unknown factorisation: the production default
  requireTimelock, proveTimelockElapsed, verifyTimelock,
} from '@atlasauth/pca-vdf';

const steps = 2000;

// `action` is a PCActn from @atlasauth/pca, or any precomputed action digest string.
const action = 'digest-of-the-irreversible-action';

// Policy side: the requirement (derives the VDF input x from the action).
const requirement = requireTimelock(action, { steps, N });

// Prover side: runs `steps` sequential squarings, so this call is the cooling-off.
const proof = proveTimelockElapsed(action, steps, N);

// Verifier side: cheap, offline, fail-closed (returns false, never throws).
verifyTimelock(action, proof, { steps, N });          // true
verifyTimelock('another-action', proof, { steps, N }); // false: proof is bound to the action
```

### Development and tests

`insecureDevSetup({ bits })` generates a modulus whose factors the calling process knows. Whoever knows the
factors skips the delay with a single modular exponentiation, so it is for development and tests only. Its
result is branded `insecureDevOnly: true`, and the timelock functions refuse such a modulus (and any modulus
under 2048 bits, an even or prime modulus, a perfect square, or one with a small factor) unless you pass the
deliberately loud `allowInsecureDevModulus: true`:

```ts
import { insecureDevSetup, proveTimelockElapsed, verifyTimelock } from '@atlasauth/pca-vdf';

const dev = insecureDevSetup({ bits: 256 });
const proof = proveTimelockElapsed('a', 200, dev.N, { allowInsecureDevModulus: true });
verifyTimelock('a', proof, { steps: 200, N: dev.N, allowInsecureDevModulus: true }); // true, but delays nobody who holds dev.p and dev.q
```

## API

- `requireTimelock(action, { steps, N })`, `proveTimelockElapsed(action, steps, N)`,
  `verifyTimelock(action, proof, { steps, N })` - the PCA timelock layer. All three refuse a modulus that
  fails `checkProductionModulus` (`verifyTimelock` returns `false`).
- `deriveTimelockInput(action, N)`, `actionDigest(action)` - the action-to-VDF-input binding.
- `calibrateSteps({ N, desiredSeconds, adversaryAdvantage? })` - helper that converts a target duration
  into a step count by timing squarings on this machine.
- `vdfEval(x, T, N)`, `vdfVerify(x, y, pi, T, N)`, `vdfVerifyDetailed(...)` (returns the refusal reason),
  `hashToPrime`, `modpow`, `isProbablePrime` (also grouped as the `vdf` object) - the underlying Wesolowski
  VDF over an RSA group.
- `insecureDevSetup(opts?)` - DEV/TEST ONLY modulus generator (formerly `setup`; the old name is removed so
  it cannot be mistaken for a production setup). `checkProductionModulus(N)` - the screen the timelock layer
  applies.
- `RSA_2048_CHALLENGE_MODULUS` / `DEFAULT_MODULUS` - the RSA-2048 challenge number, as a modulus of
  unknown factorisation.

## Status

Experimental and unaudited. What the test suite now establishes, and what it does not:

**Validated**

- The bundled `RSA_2048_CHALLENGE_MODULUS` is compared digit for digit with the decimal published by RSA
  Laboratories for the RSA-2048 challenge (Internet Archive capture) and with the Wikipedia "RSA numbers"
  listing; both captures are recorded with URL, date and sha256.
- The Wesolowski prover and verifier are checked against an independent implementation written separately
  (Python 3.12 with gmpy2 2.3.2 / GMP 6.3.0 for modular exponentiation and primality, `hashlib` for SHA-256;
  `y` by one big-exponent modpow and `pi` by direct floor division, not the running long-division the
  TypeScript uses). On 40+ committed vectors over RSA-2048 and a 512-bit test modulus the outputs `y`, `pi`
  and the challenge prime are identical, and 20+ tampered or malformed proofs are refused with the same
  reason code. With a Python environment available, a live run also cross-verifies fresh random proofs in both
  directions and checks the Miller-Rabin routine against GMP on random numbers, Carmichael numbers and strong
  pseudoprimes. These vectors are self-written; no official vectors exist for this construction (the
  challenge-prime derivation is specific to this package, and chiavdf is a class-group VDF).
- Timelock input derivation is re-computed independently with Node's crypto and matches.
- The production path refuses a modulus produced by `insecureDevSetup`, anything under 2048 bits, and
  structurally weak moduli, each with a specific reason.

**Defect found by these tests and fixed**

- `vdfVerify` used to accept `y = 0, pi = 0` (and any multiple of the modulus) for every input and step
  count, so a timelock could be released with no work at all. Verification now requires `y`, `pi` and `x` to
  be canonical units of the group.

**Not validated**

- An RSA-group VDF is only a delay if nobody knows the factors of `N`. The RSA-2048 challenge number is
  unfactored as far as is publicly known; that is a statement about public knowledge, not a guarantee.
  `checkProductionModulus` is a screen for obviously unsuitable moduli, not proof that a well-formed
  semiprime has unknown factors, and it cannot recognise a dev modulus generated in another process. For real
  use supply a modulus from an unknown-order ceremony or the challenge number. A class-group VDF, which needs
  no trusted setup, is not implemented.
- The challenge prime is derived with a fixed set of Miller-Rabin bases rather than a certified-prime proof.
- A VDF measures sequential work, not seconds. Use `calibrateSteps` with a conservative adversary speedup
  and treat the resulting wall-clock time as a floor, not an exact timer.
- No side-channel review (BigInt arithmetic is not constant time) and no independent audit.

## License

MIT - see LICENSE
