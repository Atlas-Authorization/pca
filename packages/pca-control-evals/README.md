# @atlasauth/pca-control-evals

An empirical adversarial safety bound for Proof-Carrying Authority (PCA), complementing PCA's analytic one.

PCA proves an analytic bound: between two human co-signs, the total risk of machine-only actions is at most `bMax/kappa`, whatever the agent does (see `safetyBound()` in `@atlasauth/pca`). That is a statement about the budget. It does not tell you whether the controls actually catch a given adversarial strategy, or how much legitimate work they allow. This package adds the empirical side as a red-team and blue-team control evaluation, following the AI Control methodology of Greenblatt, Shlegeris, Sachan and Roger ([arXiv:2312.06942](https://arxiv.org/abs/2312.06942)) and Korbak et al. ([arXiv:2501.17315](https://arxiv.org/abs/2501.17315)).

A possibly-misaligned red agent emits a sequence of intended actions (slow-burn under the budget, an over-cap action, an off-policy verb, a high-taint exfiltration flow, a replay). The blue control protocol is PCA's real control surface: `reviewAction` (predicates, caveats, step-up tiers), the metered trust budget, DLP, and the behavioral immune system. It decides allow, step-up or deny for each action.

- safety: the fraction of episodes in which red could not cause an unacceptable outcome (a catastrophic action blue let through);
- usefulness: the fraction of legitimate actions blue allowed.

## Install

```sh
npm i @atlasauth/pca-control-evals
```

Depends on `@atlasauth/pca` (installed automatically).

## Usage

```ts
import { exampleControlEval } from '@atlasauth/pca-control-evals';

const report = exampleControlEval(); // deterministic
// { safety, usefulness, analyticBound, episodes,
//   catches: { replay, predicate, caveat, dlp, budget, immune },
//   byStrategy: { 'over-cap', 'off-verb', 'slow-burn', 'taint-exfil', 'replay', 'immune-probe', 'benign' } }
```

Plug in your own suite with `controlEval(reds, blue, env, { episodes, seed })`:

```ts
import { controlEval, exampleBlue, exampleEnv, EXAMPLE_RED_POLICIES } from '@atlasauth/pca-control-evals';

const report = controlEval(EXAMPLE_RED_POLICIES, exampleBlue(), exampleEnv, { episodes: 20, seed: 7 });
```

A `RedPolicy` is `{ name, strategy, gen({ env, rng, now }) => RedAction[] }`, a `BluePolicy` bundles the agent with optional DLP, immune and budget settings, and an `Env` decides which allowed actions count as unacceptable. Everything is deterministic given a seed.

## This is a harness, not a proof

The number is an empirical bound over a modeled adversary in a modeled environment, and it is only as strong as the red policies and environment you encode. A control protocol catches only the hazards its predicates, DLP classes, budget and immune signals actually represent. `gapAwareEnv` with `gapExploitRed` deliberately builds an in-policy, zero-taint, in-cap hazard that no control encodes, and `safety` drops to 0 against it. A real guarantee needs a realistic environment and a realistic red suite. This complements, and does not replace, the analytic `bMax/kappa` bound; the two answer different questions.

Cryptography in PCA is unaudited.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE
