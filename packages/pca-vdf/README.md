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
import { setup, requireTimelock, proveTimelockElapsed, verifyTimelock } from '@atlasauth/pca-vdf';

// DEV/TEST ONLY: generates a modulus whose factors this process knows (see Status).
const { N } = setup({ bits: 512 });
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

## API

- `requireTimelock(action, { steps, N })`, `proveTimelockElapsed(action, steps, N)`,
  `verifyTimelock(action, proof, { steps, N })` - the PCA timelock layer.
- `deriveTimelockInput(action, N)`, `actionDigest(action)` - the action-to-VDF-input binding.
- `calibrateSteps({ N, desiredSeconds, adversaryAdvantage? })` - helper that converts a target duration
  into a step count by timing squarings on this machine.
- `vdfEval(x, T, N)`, `vdfVerify(x, y, pi, T, N)`, `setup(opts?)`, `hashToPrime`, `modpow`,
  `isProbablePrime` (also grouped as the `vdf` object) - the underlying Wesolowski VDF over an RSA group.
- `RSA_2048_CHALLENGE_MODULUS` / `DEFAULT_MODULUS` - the RSA-2048 challenge number, as a modulus of
  unknown factorisation.

## Status

Experimental. Read before relying on it:

- An RSA-group VDF is only a delay if nobody knows the factors of `N`. `setup()` generates `N` itself and
  therefore knows the trapdoor; use it for development and tests only. For real use supply a modulus from
  an unknown-order ceremony, or the bundled RSA-2048 challenge modulus (verify its digits yourself against
  the published challenge). A class-group VDF, which needs no trusted setup, is not implemented.
- A VDF measures sequential work, not seconds. Use `calibrateSteps` with a conservative adversary speedup
  and treat the resulting wall-clock time as a floor, not an exact timer.
- The cryptography has not been independently audited.

## License

MIT - see LICENSE
