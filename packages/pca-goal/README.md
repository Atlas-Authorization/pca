# @atlasauth/pca-goal

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Published to npm as `@atlasauth/pca-goal`. Its machine-checked proofs, benchmark and mutation gates run in the repository's continuous integration. It depends on `@atlasauth/pca-intent` for the exact Clopper-Pearson bound.

Intent-fidelity program for goal-to-decision: signed domain ontologies and a checker, typed template interpreters (deterministic, form and model adapters with recorded-output replay), active disambiguation, boundary examples with signed goal tests and a policy pin, the N-version meet, a lossless policy card with a measured round-trip detector, signed precedents, tighten-only drift monitors, conformal risk control and the hostile corpus.

Offline tests and benchmarks replay recorded model outputs (`benchmarks/recorded`); `node` scripts are not needed. The scheduled live evaluation reads its API keys only from environment variables supplied by repository secrets.

## Quick start

```ts
import { approveGoal, loadApprovedGoal, signerId } from '@atlasauth/pca-goal';

// 1. A person reviews the policy card of the goal and signs exactly that goal (the reviewer secret is a 32-byte Ed25519 seed you hold).
const approval = approveGoal({ goal, ontology, instruction, model_set: [] }, reviewerSecret);

// 2. The enforcing side recompiles everything from the submission and trusts nothing the approval says about itself.
const loaded = loadApprovedGoal({ goal, ontology, instruction, model_set: [] }, approval, { reviewers: [signerId(reviewerSecret)] });
if (!loaded.ok) throw new Error(loaded.reason); // a typed refusal, never a partial load
// loaded.approved.goal_string is what a wallet passes when it mints the root grant; loaded.approved.intent_policy opens it.
```

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| No pinned reviewer (empty or absent list) | `loadApprovedGoal` returns `{ ok: false, reason: 'no_reviewers_pinned' }` |
| An approval or submission of the wrong shape | `malformed_approval` or `malformed_submission`; `loadApprovedGoal` never throws |
| A goal with an unresolved hole, a wildcard nobody acknowledged, a card over the size cap, or an unrenderable clause | `holes`, `wildcard_unacknowledged`, `card_too_large`, `unrenderable`; `approveGoal` throws and nothing is signed |
| An instruction whose digest differs from the goal's | `instruction_mismatch` |
| A goal the compiler or the analyzer refuses | `compile_error` or `analyzer_error` |
| A confirmed example the compiled policy contradicts, or that cannot be decided | `tests_contradicted` or `tests_unverifiable` |
| Any digest in the approval that differs from the one recomputed (goal, policy, card, ontology, tests, instruction, model set) | the matching `*_mismatch` reason |
| A reviewer key that is not pinned, a bad signature, an approval over 24 hours, not yet valid, or expired | `reviewer_not_pinned`, `bad_signature`, `ttl_too_long`, `not_yet_valid`, `expired` |
| A change from the base goal beyond the reviewer-fatigue caps | `approveGoal` throws `diff_too_large` or `too_many_widenings`; limits can only be tightened by the caller |
| A signed artifact of another kind, an unpinned signer, a tampered body or a float | `verifyGoalArtifact` returns `false`; signing a non-canonical body throws |
| A drift signal (rate, novelty, magnitude) | the decision can only tighten; it never widens |
| Too few calibration cases for the risk target | the top (escalate-all) level is chosen and reported `feasible: false` |

## Limits

- The goal compiler is a deterministic function of a typed goal; deciding what the principal meant from free text is done by interpreters whose output a person must review and sign. A model never widens what is enforced.
- Round-trip and disambiguation reduce, and measure, the chance that a card misstates a goal; they do not make a mistaken approval impossible.
- The conformal guarantee holds for exchangeable calibration cases and the stated loss; the report prints its assumptions.
- Recorded model outputs make the offline benchmarks reproducible; the scheduled live evaluation measures real models and is not a gate on a single run.
- Reviewer fatigue caps bound the card and the diff a person is asked to read; a goal over the caps is split, not truncated.
