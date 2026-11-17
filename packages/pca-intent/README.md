# @atlasauth/pca-intent

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

The PCA intent layer: intent as a measurable object. It derives a typed outcome space from the grant vocabulary, learns grant hypotheses with exact Bayesian and version-space elicitation, picks maximal-disagreement questions, estimates residual risk and fidelity, synthesises conservative grants, and produces content-addressed intent maps and signed intent statements. It also holds the exact Clopper-Pearson upper bound (integer arithmetic, rounded outward) that `@atlasauth/pca-actions` and `@atlasauth/pca-goal` use for their published rates.

```sh
npm install @atlasauth/pca-intent
```

```ts
import { clopperPearsonUpper } from '@atlasauth/pca-intent';

// the upper confidence bound on a rate when 2 of 400 trials failed, at alpha = 0.05
const upper = clopperPearsonUpper(2, 400, 0.05);
```

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| `clopperPearsonUpper` with no trials (`n = 0`) or all failures | the bound is 1, the widest possible |
| `k` or `n` not integers, `k > n`, negative, or `alpha` outside (0, 1) | throws |
| `verifyOutcome` for a verb outside the outcome space | throws |
| `routeAction` for a verb outside the outcome space | route `deny` |
| `commitIntentMap` for a map missing a cell, or with a wrong-arity or out-of-range cell | throws; nothing is committed |
| `DriftDetector` options outside 0 < rho0 < rho1 < 1 or h <= 0 | throws |
| A signed intent statement that does not verify (`verifyIntent`) | a refusing verdict naming the reason; nothing is bound |

## Limits

The estimates describe the model you give them; they do not prove that a classifier, an oracle or a label issuer was right. Statements are signed with the core package's suites; nothing here is new cryptography.

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca).
