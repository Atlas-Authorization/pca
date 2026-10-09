# @atlasauth/pca-invariants

Property-based checking of the core safety invariants of Proof-Carrying Authority (PCA). It generates thousands of random capability chains, policies, risk inputs and actions, runs them through the real `@atlasauth/pca` core (nothing is re-implemented), and asserts universal properties:

1. Attenuation monotonicity: a delegation step can only shrink or preserve authority.
2. Budget soundness: auto-admitted cost is always covered, cumulative machine-only risk stays within the bound, risk is clamped to its range and monotone in its inputs.
3. Fail closed: undecidable predicates, unknown caveat types and forged or garbage chains deny or fail to verify.
4. Determinism: deciding the same input twice yields the same result.

## Install

```sh
npm i @atlasauth/pca-invariants @atlasauth/pca
```


## Usage

```ts
import { checkInvariants } from '@atlasauth/pca-invariants';

const results = checkInvariants({ numRuns: 1000, seed: 20260108 });
for (const r of results) {
  console.log(r.ok ? 'ok  ' : 'FAIL', r.name, r.error ?? '');
}
if (results.some((r) => !r.ok)) process.exit(1);
```

Each result is `{ name, ok, numRuns, seed, error? }`; a failure carries the shrunk counterexample in `error`. Defaults are 1000 runs and a fixed seed, so runs are reproducible. Pass `bail: true` to stop at the first failure.

## API

- `checkInvariants(options?)` and the `INVARIANTS` registry (`{ name, run(numRuns, seed) }`).
- The individual `fast-check` properties (`attenuationMonotonicityProperty`, `admissionSoundnessProperty`, `forgedChainRejectedProperty`, `determinismProperty`, and others) for use with `fc.assert`.
- The generators (`arbChain`, `arbKeyPair`, `arbCondition`, `arbRiskPolicy`, `arbRiskInputs`, ...) for writing your own properties over PCA chains and policies.

## Status

Property-based testing gives strong evidence, not a proof: it samples a large input space and cannot rule out a counterexample outside it. A failing property indicates a candidate bug in the PCA core. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
