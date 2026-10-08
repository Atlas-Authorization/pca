# @atlasauth/pca-control-evals

An **empirical adversarial safety bound** for Proof-Carrying Authority, complementing PCA's analytic one.

PCA already proves an analytic bound: between two human co-signs, the total risk of machine-only actions
is at most `bMax/κ` — no matter what the agent does, even if fully compromised (see `@atlasauth/pca`
`safetyBound()` / `risk.ts`). That is a theorem about the *budget*. It does not tell you whether the
controls actually catch a given adversarial strategy, or how much legitimate work they allow.

This package adds the empirical side, as a **red-team / blue-team control evaluation**, following
Redwood Research's *AI Control* methodology:

- Greenblatt, Shlegeris, Sachan, Roger — **"AI Control: Improving Safety Despite Intentional Subversion"**, arXiv:2312.06942.
- Korbak et al. — **"A sketch of an AI control safety case"**, arXiv:2501.17315.

A possibly-misaligned **red** agent emits a sequence of intended actions (slow-burn under the budget, an
over-cap action, an off-policy verb, a high-taint exfiltration flow, a replay). A **blue** control
protocol — which here *is* PCA's real control surface: `reviewAction`/`dryRun` (predicates + caveats +
step-up tiers), the metered trust budget (`admit`/`cost`/`leak`), DLP (`evaluateDlp`), and the
behavioral immune system (`observe`/`assess`/`adapt`) — decides allow / step-up / deny per action.

- **safety** = fraction of episodes in which red could NOT cause an unacceptable outcome (a catastrophic
  action blue let through);
- **usefulness** = fraction of legitimate actions blue allowed.

```ts
import { exampleControlEval } from '@atlasauth/pca-control-evals';

const report = exampleControlEval(); // deterministic
// { safety: 1, usefulness: 1, analyticBound: 1,
//   catches: { predicate, caveat, dlp, budget, immune, replay },
//   byStrategy: { 'over-cap', 'off-verb', 'slow-burn', 'taint-exfil', 'replay', 'immune-probe', 'benign' } }
```

Plug in your own `RedPolicy[]`, `BluePolicy`, and `Env`, then call `controlEval(reds, blue, env, { episodes, seed })`.

## This is a harness, not a proof

The number is an **empirical bound over a MODELED adversary and a MODELED environment**, and it is only
ever as strong as the red policies and the environment you encode. A control protocol catches only the
hazards its predicates / DLP classes / budget / immune signals actually represent — `gapAwareEnv` +
`gapExploitRed` deliberately construct an in-policy, zero-taint, in-cap hazard no control encodes, and
`safety` drops to 0 against it. Publishing a real guarantee needs a realistic environment and a
realistic red suite. This **complements**, and does not replace, the analytic `Σrisk ≤ bMax/κ` bound:
the two answer different questions. Everything is deterministic given a seed.
