# @atlasauth/pca-conformance

> Maturity: **stable** (stable core). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Canonical Proof-Carrying Authority (PCA) conformance vectors and a differential harness, so every PCA verifier implementation can show it agrees on accept or reject for the same inputs. The vectors are generated deterministically (fixed keys, fixed clock) and each one carries the full expected per-check outcome, not just allow or deny: the first failed check and the status of every check in evaluation order.

The harness is language-neutral. A verifier under test is a plain function from a PCActn and its verify input to a verdict, so a Go, Rust, Python or other runner can mirror it over the same serialized vector set.

## Install

```sh
npm i @atlasauth/pca-conformance
```

Depends on `@atlasauth/pca` (installed automatically).

## Usage

Run the reference verifier (or your own) over the vectors:

```ts
import { runConformance, coreVerify, VECTORS } from '@atlasauth/pca-conformance';
import type { HarnessVerify } from '@atlasauth/pca-conformance';

// Any verifier is (pcactn, input) => { allow, checks, reason? }. coreVerify wraps the TypeScript reference.
const myVerify: HarnessVerify = async (pcactn, input) => coreVerify(pcactn, input);

const report = await runConformance(myVerify);
// { version, total, passed, failed, ok, results: [{ id, matched, expected, actual, divergences }] }
if (!report.ok) {
  for (const r of report.results.filter((x) => !x.matched)) console.error(r.id, r.divergences);
}
```

A vector matches only if `allow`, the first failed check, and the entire per-check map all equal the expectation.

To feed a verifier written in another language, serialize the vector set and read it there:

```ts
import { serializeVectorSet, VECTOR_SET } from '@atlasauth/pca-conformance';
import { writeFileSync } from 'node:fs';

writeFileSync('vectors.json', serializeVectorSet(VECTOR_SET));
```

Each vector has `id`, `description`, `pcactn`, `aud` (the verifier's own audience, or `null` for any), `verifyOptions` (deterministic `nowEpoch`, optional enforcement gates and an optional `intent` policy `{require?, min_fidelity_ppm?, max_residual_risk_ppm?}`) and `expect`. The `intent` check is reported only when the action carries the signed `intent` member or the policy is active (the `intent_*` vectors).

## API

- `VECTORS`, `VECTOR_SET`, `generateVectorSet()`, `serializeVectorSet()`
- `runConformance(verify?, vectors?)`, `coreVerify`, `firstFailedCheck`
- `CONFORMANCE_VERSION`, `CHECK_ORDER`, `CANONICAL_GRANT`
- Types: `ConformanceVector`, `ConformanceVectorSet`, `HarnessVerify`, `ConformanceReport`, `VectorRunResult`

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| A verifier that disagrees with a vector on `allow`, on the first failed check, or on any entry of the per-check map | that vector is `matched: false` with the divergences listed, and the report is `ok: false` |
| A verifier that returns no per-check detail (for example `{ allow: true, checks: {} }`) | every vector diverges; `ok: false` |
| A vector with no capability in its chain | the canonical grant is used for the run |
| A vector whose `intent` policy or gates are absent | those checks are not requested, and the vector's expectation says so |

## Limits

- Passing shows agreement with the reference on these vectors only. It is not an audit and does not cover inputs outside the set.
- A verifier that throws makes `runConformance` reject; it does not record a failed vector. Wrap it if you want a per-vector result.
- An empty `vectors` argument yields `total: 0` and `ok: true`. Always run the shipped set (the default) for a real claim.
- It checks verdicts, not performance, timing or resource limits.

## Status

This is a test-support package for verifier implementers. Passing it shows agreement with the reference on these vectors; it is not a security audit of an implementation.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
