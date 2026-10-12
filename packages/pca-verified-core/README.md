# @atlasauth/pca-verified-core

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

The only runtime dependency is `bignumber.js` (Dafny's integer representation).
