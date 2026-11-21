# @atlasauth/pca-verified-core

> Maturity: **stable** (stable core). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

The **decision logic** of the Proof-Carrying Authority (PCA) verifier, written in [Dafny](https://dafny.org), machine-proved
for all inputs (no bounds on chain length, share count or operation sequence), and compiled to JavaScript.

It does not do cryptography. You (the glue) evaluate signatures, hashes and parsing with your primitives and hand the
**results** (booleans, small enums, integers, opaque messages, lazy pure closures) to this package, which decides:

| area | function | proved (see `docs/pca/security/verified-core.md`) |
|---|---|---|
| capability chain | `decideChain` | order + first failure, depth bound (16), append-only caveats (attenuation), soundness + completeness |
| threshold | `decideThreshold` | one key per role / one role per key, count of **distinct** roles, `ok` iff count >= t, t in {1,2,3} |
| replay guard | `replayPre`, `replayNonceStage`, `replayDecide`, `VerifiedReplayStoreModel` | deny order, accept implies every precondition and store answer, nonce replay freedom, strictly increasing counters |
| check fold | `CoreState`, `VerdictState`, `enforceRequired`, `withDeniedFallback` | allow iff no check failed, first reason wins, reasons append-only, required checks all `pass` |
| per-check rules | `audienceStatus`, `validityDecision`, `grantRefBoundStatus`, `counterStatus`, `suitePolicy`, `pqBinding`, `leafDecision`, `thresholdRule`, `reversibilityDecision`, ... | audience fail-closed, expiry/skew window, suite policy, F-2 PQ binding, F-1 hook-enforced t |

```ts
import { decideChain, decideThreshold, CoreState, validityDecision } from '@atlasauth/pca-verified-core';

validityDecision(true, iat, exp, now); // 'pass' | 'expired' | 'future' | ...
```

No Dafny runtime type appears in the API. The generated JavaScript is committed in `generated/pca_core.js`; regenerate and
re-verify with `formal/dafny/build.sh`, and check that the committed file is byte-identical to a fresh compile with
`formal/dafny/build.sh --check` (script `check:generated`). Requires Dafny 4.11.0 (z3 4.12.1), run on a cloud box if not local.

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| A clock that is `NaN`, infinite or not an integer | the validity check is `fail`; the action is denied |
| An expiry beyond the maximum lifetime, or an issue time beyond the skew window | `too-long` / `future`, never `pass` |
| A chain deeper than 16, or one that drops or alters an earlier caveat | refused with the first failure in order |
| Fewer distinct signing roles than the threshold, or a role or key used twice | not counted; `ok` is false |
| A required check that is not `pass` | `enforceRequired` denies |
| A value that is not a safe integer where one is required | `RangeError`; nothing is decided |
| A regular expression with no document budget, an unsafe pattern, or a budget already spent | throws or refuses the match; never matches by default |
| A throwing regex or schema oracle | treated as unsafe or false |
| A cyclic, sparse, accessor-bearing or non-plain value given to the policy VM or the canonicalizer | refused with a typed error |
| Non-finite thresholds or an unknown taint label | throws; no verdict |
| A nonce store with `max` or `retentionMs` that is not a positive integer | the constructor throws |
| An attestation root set that is empty, duplicated or has a threshold outside 1..n | the constructor throws |

## Limits

- It does no cryptography. Signatures, hashes and parsing are the glue's job, and the proofs assume those results are right.
- The proofs cover the decision logic only, not the glue, the Dafny compiler or the JavaScript engine.
- Only the proved bounds hold: chain depth 16, thresholds 1 to 3, and the stated size limits of the canonical printer.
- It has no I/O and no persistent store of its own; the replay model is a specification, and a production store must meet it.

The only runtime dependency is `bignumber.js` (Dafny's integer representation).
