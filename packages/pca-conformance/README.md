# @atlasauth/pca-conformance

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

Each vector has `id`, `description`, `pcactn`, `aud` (the verifier's own audience, or `null` for any), `verifyOptions` (deterministic `nowEpoch` and optional enforcement gates) and `expect`.

## API

- `VECTORS`, `VECTOR_SET`, `generateVectorSet()`, `serializeVectorSet()`
- `runConformance(verify?, vectors?)`, `coreVerify`, `firstFailedCheck`
- `CONFORMANCE_VERSION`, `CHECK_ORDER`, `CANONICAL_GRANT`
- Types: `ConformanceVector`, `ConformanceVectorSet`, `HarnessVerify`, `ConformanceReport`, `VectorRunResult`

## Status

This is a test-support package for verifier implementers. Passing it shows agreement with the reference on these vectors; it is not a security audit of an implementation. Cryptography in PCA is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
