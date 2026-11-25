# @atlasauth/pca-invariants

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

`numRuns` must be a positive integer and `seed` an integer: a run of zero cases would pass without checking anything, so `checkInvariants` throws a `RangeError` instead. Each result is `{ name, ok, numRuns, seed, error? }`; a failure carries the shrunk counterexample in `error`. Defaults are 1000 runs and a fixed seed, so runs are reproducible. Pass `bail: true` to stop at the first failure.

## API

- `checkInvariants(options?)` and the `INVARIANTS` registry (`{ name, run(numRuns, seed) }`).
- The individual `fast-check` properties (`attenuationMonotonicityProperty`, `admissionSoundnessProperty`, `forgedChainRejectedProperty`, `determinismProperty`, and others) for use with `fc.assert`.
- The generators (`arbChain`, `arbKeyPair`, `arbCondition`, `arbRiskPolicy`, `arbRiskInputs`, ...) for writing your own properties over PCA chains and policies.

## The checks have teeth

The test suite runs each fail-closed and soundness property against a deliberately broken copy of the core function it guards (an `admit` that always admits, a caveat evaluator that accepts unknown types, a chain verifier that accepts everything, a risk score that is not deterministic) and requires the property to fail. A property that cannot fail proves nothing.

## Failure modes

| Missing or wrong | Result |
|---|---|
| `numRuns` not a positive integer, or `seed` not an integer | `checkInvariants` throws `RangeError` (a run of nothing would pass) |
| A property finds a counterexample | that result has `ok: false` and the shrunk counterexample in `error`; `bail: true` stops at the first |
| A new invariant without a negative control | the suite fails (`every registered invariant has a negative control`) |

## Mutation testing

The package is in the mutation set and runs alone in the last shard, with `PCA_INVARIANTS_RUNS` (default 120 under mutation) capping the cases per property and a longer per-mutant timeout. The seeds are fixed, so a mutant the properties can reach is killed deterministically.

## Limits

- Property testing samples a space; it is strong evidence, not proof. The negative controls show each property can fail, not that it covers every input.
- It checks `@atlasauth/pca` as built; a bug in `fast-check` generators can hide a counterexample, which is why the generators are exported for review.

## Status

Property-based testing gives strong evidence, not a proof: it samples a large input space and cannot rule out a counterexample outside it. A failing property indicates a candidate bug in the PCA core. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
