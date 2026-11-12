# Suggestion corpus and honest measurement

**What these numbers are for.** Classifier recall now affects review effort only, never enforcement. An action without a signed human confirmation is treated as having every trait (the top of the trait registry), whatever the suggestion rules, the catalog packs or a model said, so a missed trait cannot lower a floor, widen a grant or hide an action from a forbid. The recall below tells you how much of the right answer a reviewer is handed before they start, and how many traits they must add by hand; it is not a safety claim. The floors in `recall-floors.json` keep that review work from getting worse.

What is measured: the deterministic suggestion rules (`src/import/rules.ts`) run on operations as an importer would see them (name, method, path, parameter names and types; no vendor prose). A trait counts as "flagged" when the reviewer would be shown it: the traits the importer's facts imply plus the rules' suggestions. Recall lower bounds are one-sided exact Clopper-Pearson at alpha = 0.05. **These are heuristic numbers on a labeled corpus, not a safety guarantee: every suggested def stays at the unreviewed floor.**

## Four sets, and which number to believe

| set | file | operations | labels come from | use |
|---|---|---:|---|---|
| real, hold-out | `real.jsonl` (specs on the `holdout` side of `realSplit`) | 4003 | a person reading each operation of public specifications | **the honest number; floors come from this** |
| real, tuning half | `real.jsonl` (`tune` side) | rest of 9,578 | same | rules were tuned by reading misses here; optimistic |
| hand | `hand.tsv` | 325 | a person, from memory of real APIs; used for tuning in earlier rounds | small, optimistic |
| generated | `synthetic.jsonl` | 2,319 | a word list written by the rule author | **regression set only**: it measures nothing about real APIs |

`real.jsonl` is 9578 operations from 89 public specifications (OpenAPI 3 / Swagger 2, AWS service models, Google discovery documents, the Telegram Bot API description) read in full or, for GitHub and Kubernetes, as fixed 1-in-4 / 1-in-6 samples of every operation (no filtering by name). Each operation was labeled by reading what it does (not by running the rules): money_moving, destructive, external_communication, privilege_change, code_execution, public_exposure, financial_data_read, scheduled. An operation with no label line is a labeled negative for all eight. Labeled positives in the real set: money_moving 157, destructive 1,217, external_communication 152, privilege_change 472, code_execution 157, financial_data_read 246, public_exposure 57, scheduled 35 (the last three were labeled less systematically than the first five, so their precision is not meaningful and their recall is on small n).

Hold-out: `realSplit(spec)` (FNV hash of the specification name) puts each specification wholly in `tune` or `holdout`. Rules were edited after reading misses on `tune` specs only; the hold-out specifications were never read for tuning. The hold-out numbers below are therefore the ones that say something about specs the rules have not seen.

## Measured recall (rules 1.1.0, after the second tuning round)

Rules 1.1.0 differ from 1.0.0 in two ways, both chosen on the tuning half only (see "Adjudicated disagreements" below): the name rules for the traits that only a write can have (money_moving, external_communication, privilege_change, code_execution, public_exposure, destructive) now match writes only, and a third group of rules was added for gaps found on the tuning side of the adjudicated pack defs (access material and boundaries, retire/expire/detach, verification codes, standing publications). The hold-out specifications were consulted only to accept or reject a whole step (four times); a step that lowered hold-out recall (pruning name tokens that fired often with no true positive on the tuning half) was reverted whole, not token by token.

Hold-out columns show 1.0.0 -> 1.1.0.

| trait | hold-out positives | hold-out recall | **hold-out recall lower bound** | hold-out precision | hold-out false alarms | all real positives | all real lower bound (1.1.0) | hand lower bound | generated lower bound | recorded floor (hold-out) |
|---|---:|---|---|---|---|---:|---:|---:|---:|---:|
| money_moving | 42 | 78.6% -> 78.6% | **65.6% -> 65.6%** | 12.4% -> 12.6% | 233 -> 229 | 157 | 86.4% | 88.3% | 98.4% | 0.62 |
| destructive | 506 | 96.6% -> 99.0% | **95.0% -> 97.9%** | 83.0% -> 82.4% | 100 -> 107 | 1217 | 97.7% | 92.3% | 98.7% | 0.94 |
| external_communication | 78 | 82.1% -> 83.3% | **73.4% -> 74.8%** | 13.5% -> 14.7% | 410 -> 376 | 152 | 80.0% | 93.6% | 98.5% | 0.71 |
| privilege_change | 211 | 64.0% -> 66.4% | **58.2% -> 60.6%** | 26.6% -> 34.1% | 372 -> 271 | 472 | 73.5% | 88.9% | 98.3% | 0.57 |
| code_execution | 66 | 89.4% -> 89.4% | **81.0% -> 81.0%** | 12.3% -> 15.1% | 421 -> 331 | 157 | 91.0% | 85.6% | 98.3% | 0.78 |
| public_exposure | 19 | 63.2% -> 63.2% | **41.8% -> 41.8%** | 3.0% -> 3.1% | 393 -> 380 | 57 | 78.2% | 89.5% | 94.2% | 0.38 |
| financial_data_read | 80 | 71.3% -> 71.3% | **61.8% -> 61.8%** | 28.9% -> 28.9% | 140 -> 140 | 246 | 69.8% | 62.3% | 95.1% | 0.58 |
| scheduled | 11 | 90.9% -> 90.9% | **63.6% -> 63.6%** | 3.6% -> 3.6% | 265 -> 265 | 35 | 87.1% | 71.7% | 92.8% | 0.6 |

Read it as: on specifications the rules were not tuned on, the rules surface at least (95% bound) 98% of destructive operations, 81% of code execution, 75% of external communication, 66% of money moving and 61% of privilege change. The 85% recall target is met on the tuning half and the generated set, **not on the hold-out** (destructive only); public exposure and scheduled rest on 19 and 11 hold-out positives, so their bounds are wide and mean little. **Precision is low (roughly 3 to 34 percent, 82 for destructive):** the rules flag a lot, because they only ever add. A flag is a prompt for the reviewer, never a conclusion; a missed trait is a miss until review, and an unreviewed def is held at the maximal floor whatever the rules found. The earlier figures near 0.97 to 0.98 were measured on the generated set and do not describe real specifications.

`recall-floors.json` records the floors (3 points under the hold-out lower bound) and the minimum labeled positives each floor needs; CI (`scripts/eval-suggest.ts`) fails below them. 1.1.0 raised the floors for destructive (0.92 to 0.94), external_communication (0.70 to 0.71) and privilege_change (0.55 to 0.57) and lowered the generated-set regression floor for public_exposure (0.93 to 0.91: the write-only restriction costs a few synthetic read-shaped names). The generated set has its own regression floors only.

## Cross-check against the catalog packs (track A6)

`scripts/xcheck-packs.ts <packs dir>` compares the rules with the trait annotations of the A6 packs, whose traits come from separate per-pack rules. The rules see only names, bindings and parameter names/types (the pack's traits, roles, tags and effects are stripped first). Snapshot against 16,598 pack defs: `xcheck-a6-snapshot.md` (per trait, and per pack), regenerated after the adjudication round (rules 1.1.0, packs regenerated). Headline, "rules reach the pack" (of what the pack carries, the share the rules also show) / "pack confirms the rules", before -> after: destructive 95% / 89% -> 97% / 91%, privilege_change 80% / 40% -> 84% / 67%, external_communication 94% / 3% -> 94% / 6%, money_moving 99% / 6% -> 99% / 6%, code_execution 70% / 8% -> 79% / 16%, financial_data_read 100% / 1% -> 84% / 8%, public_exposure 66% / 3% -> 66% / 3%, scheduled 19% / 4% -> 35% / 9%. The low "pack confirms" figures are mostly the rules over-flagging (next section), not the packs being right by default. This is agreement between two heuristic labelers, not accuracy.

## Adjudicated disagreements (track ADJ)

Agreement is not accuracy, so the disagreements were read. `adjudication.tsv` holds 2,541 verdicts on pack defs the two labelers disagreed about: for each of nine traits (money_moving, external_communication, code_execution, privilege_change, destructive, public_exposure, data_export, financial_data_read, scheduled) a stratified (by pack, proportional) random sample of at least 200 of the "rules say it, the pack does not" set and of the "pack says it, the rules do not" set (all of a set when it is smaller). The verdict (`y`, `n`, `u`) is a reading of what the operation does from its name, method, path, parameter names and the pack title; neither the pack's label, the rules' label nor which set the def came from was shown (the samples were shuffled together and read blind). The file stores facts (verb, method, path, parameter names), the verdict and a one-line reason, no vendor prose. `adjudication-population.json` has the stratum sizes so the rates can be re-estimated. Caveats: the reasons are category-level rather than per-operation; the readings were done quickly and lean lenient on borderline "could be" cases (k8s workload patches, restore/clean operations); defs both labelers agreed on were not sampled and are assumed correct.

`scripts/adjudicate.ts estimate <packs> adjudication.tsv adjudication-population.json` re-estimates, against whichever packs and rules are checked out, per trait: the pack under-labelling (true-trait defs neither carrying the trait nor left `unreviewed`), the pack over-label rate, the rule over-flag rate (exact Clopper-Pearson 95% bounds on the sampled share, scaled to the stratum) and the rule miss rate. Findings (before -> after the fixes in this track):

| trait | pack under-label, defs [95% CI] | pack under-label, share of true carriers | rule over-flag rate (before) | rule over-flag rate (after) |
|---|---|---|---|---|
| money_moving | 17 [2, 51] -> 17 [2, 51] | 16% -> 16% | 93% | 91% |
| external_communication | 86 [44, 152] -> 32 [9, 79] | 55% -> 21% | 91% | 89% |
| code_execution | 131 [70, 208] -> 47 [15, 104] | 43% -> 15% | 86% | 82% |
| privilege_change | 133 [79, 217] -> 54 [19, 110] | 9% -> 4% | 55% | 30% |
| destructive | 48 [34, 65] -> 23 [13, 35] | 2.0% -> 0.9% | 9% | 9% |
| public_exposure | 0 [0, 39] -> 0 [0, 39] | 0% -> 0% | 98% | 97% |
| data_export | 36 [22, 53] -> 5 [1, 15] | 35% -> 5% | 78% | 78% |
| financial_data_read | 145 [89, 222] -> 31 [8, 77] | 88% -> 19% | 90% | 90% |
| scheduled | 93 [52, 153] -> 34 [11, 76] | 58% -> 21% | 90% | 90% |

So both labelers were wrong, in different directions and by different amounts. The rules over-flag heavily on every trait except destructive (most of what they flag is not that: 85 to 98 percent of the flags on money, communication, code, public exposure, export, financial reads and scheduled operations were judged wrong). The packs also under-labelled, most for financial reads (the generator had no rule at all), exports (four per-pack rules downgraded exports to plain creates), communication, code execution and standing schedules. The pack side was fixed in the generator (`scripts/actions-packs/lib/infer.ts`); the remaining under-labelled defs are the ones no systematic signal reached (for example AWS `register_daemon_task_definition`, Stripe billing alerts, a handful of purchase-like creates for money_moving) and the Teams/mail/GitHub comment family where the pack deliberately says `publish`, not communication. The pack over-label figures (scheduled 70%, public_exposure 33%, code_execution 30%) come from core-trait implications (`provision` implies `scheduled` and `persistence`; terraform resource writes carry it) and from the pack author's own `publish` calls; they are stricter than needed, which is not a security gap, and were left to the owner of the core trait table.

Pack side of the numbers: 606 of 16,598 pack defs changed their effective trait set, all stricter, none looser. 115 of them were left `unreviewed` (the maximal floor) because the evidence said something more was going on but a required parameter rule could not be met; the pack now has 201 unreviewed defs (86 before). `scripts/pack-trait-diff.ts <old packs> <new packs>` recomputes those counts.

Rule side: `scripts/adj-rules.ts` scores the rules on the adjudicated defs, split by a hash of `pack:verb` into a tune side (read when editing rules) and a hold-out side (not read). On the hold-out side, rules 1.0.0 -> 1.1.0: privilege_change precision 7% -> 36% and recall 16% -> 44%, destructive recall 59% -> 66%, external_communication false alarms 92 -> 68, code_execution false alarms 96 -> 72, other traits unchanged. These are comparison figures on a sample made of disagreements, not population estimates. `scripts/rule-stats.ts` and `scripts/tune-tokens.ts` print per-rule and per-token precision on the tune data only.


### Fail-strict union and residual under-labelling (second follow-up)

Pack generation now carries a high-risk trait (money_moving, external_communication, code_execution, privilege_change, destructive, data_export, financial_data_read, credential_access) when EITHER the pack's own inference OR the suggestion rules flag it, unless `adjudication.tsv` records an `n` for that def and trait (`scripts/actions-packs/lib/union.ts`). A def that cannot take the trait because a required parameter rule would fail (a recipient parameter for communication, an export bound) is left `unreviewed`, the maximal floor; a money-moving def without an idempotency key gets the optional key parameter a `pay` def gets.

Residual check: `scripts/adjudicate.ts resample` draws a fresh stratified sample (about 310 per trait) of the defs that still LACK each trait and are not `unreviewed`; the same blind reading is applied; `adjudicate.ts residual` gives the share judged to have the trait and its exact one-sided 95% upper bound (a doubtful `u` verdict counts against the pack). The files are `adjudication-residual-r1..r4.tsv` (+ populations). Rounds changed the inference between samples, so a round's bound describes the packs as they were for that round; the last round per trait describes the shipped packs (r1 for money_moving, code_execution, data_export; r2 for external_communication; r4 for the rest).

| trait | lacking defs | sample | y / doubtful | upper 95% bound, doubtful counted | upper 95% bound, y only |
|---|---:|---:|---|---:|---:|
| money_moving | 14,057 | 312 | 0 / 0 | **0.96%** | 0.96% |
| external_communication | 14,705 | 314 | 0 / 0 | **0.95%** | 0.95% |
| code_execution | 13,835 | 312 | 0 / 0 | **0.96%** | 0.96% |
| data_export | 14,969 | 314 | 0 / 0 | **0.95%** | 0.95% |
| destructive | 11,719 | 311 | 0 / 2 | 2.01% | **0.96%** |
| credential_access | 11,551 | 313 | 0 / 3 | 2.46% | **0.95%** |
| financial_data_read | 12,468 | 312 | 1 / 1 | **2.00%** | 1.51% |
| privilege_change | 11,690 | 314 | 0 / 1 | **1.50%** | 0.95% |

Final round (r5, `adjudication-residual-r5.tsv`) for financial_data_read and privilege_change: drawn fresh after the last inference edit, with no edit afterwards, so it is an unbiased estimate of the shipped packs. Both are at or under 2% even counting the doubtful verdicts (financial_data_read sits exactly at the line, 2.00%). The earlier rounds (r3, r4: 3.3 and 2.9 percent) preceded the last edits and are kept as the history of the iteration. credential_access and destructive meet the target only on clear verdicts (their last samples were r4, before no further edits to those traits' inference, so r4 still describes the shipped packs).

### Trait provenance and batch review of union-added traits

Every pack def that gained a trait through the union records it in `review.provenance` (`union`: traits added from the suggestion rules; `adjudicated`: traits the rules flagged that a person judged absent, so they were not added). Provenance is review metadata: it is not part of the def digest. A trait that is neither listed is pack-inferred. The pack ships 5,000+ union-added traits (money_moving 1,045, credential_access 1,549, financial_data_read 1,275, code_execution 1,060, privilege_change 466, data_export 135, external_communication 74, destructive 66) and 990 adjudicated exemptions.

`pca actions confirm --origin union [--trait money_moving] [--file F] --kid ID` (alias `review`) lists the defs carrying union-added traits (add `--yes --reviewer-key K` to sign). Keeping the trait attests it; dropping it needs `--dismiss pca.money_moving=reason`, which the signed attestation records. A trait that leaves a def without a signed dismissal naming it is lint error LD-011 (`the union-added trait ... was removed without a signed dismissal`), so a silent edit cannot drop one.

## Licence ledger (sources read for the real set)

Only names, HTTP methods, paths, parameter names and types, and our own labels are stored; no vendor description text. Specifications are public descriptions of public APIs: Stripe, Square, Plaid, PayPal, Adyen, Paddle, Alpaca, Xero, Twilio, SendGrid, Slack, Discord, Telegram, Intercom, Lob, PagerDuty, Datadog, LaunchDarkly, CircleCI, Vercel, OpenAI, Replicate, Docker, Kubernetes, GitHub, Argo Workflows, Apache Airflow (OpenAPI or Swagger documents from the vendors' public repositories or endpoints, mostly MIT or Apache-2.0); AWS service models (botocore, Apache-2.0); Google API discovery documents. Third-party specs are not redistributed; `real.jsonl` is a table of facts about operation names and our judgements of them. The licence of each spec must be re-checked by the owner before the corpus is published outside the repository.

| Source | Use | Licence | Redistribution of derived data |
|---|---|---|---|
| `hand.tsv`, `synthetic.jsonl` | names, labels | ours | yes |
| `real.jsonl` | operation names/paths/parameter names + our labels | facts about public APIs; underlying specs under their own licences (see above) | owner to confirm before publishing |
| User-supplied specs | never stored; `source.licence` records what the caller states (default `unknown`) | per spec | the pack generator (A6) decides per pack |

## Release signing of the rule set

`rules/suggest-rules.json` is the sealed rule set (digest, unsigned) and CI checks it against the rules in source. Signing is a release step: run `tsx scripts/emit-rules.ts --sign` with `PCA_RULES_SIGNING_KEY` (base64url Ed25519 secret) and `PCA_RULES_KID` in the environment. The script never reads the key from a file, prints or stores it. Which key that is (the rules-publisher key pinned in the registry, kept apart from reviewer keys) is the owner's decision; no key is generated or committed. Consumers verify with `verifyRules` against pinned publisher keys; CI verifies a signed file when `PCA_RULES_PUBKEY=<kid>:<b64u pk>` is set.

## Model assist

`pca actions import --suggest model --model <pinned id> [--provider anthropic|openai]` reads `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` (or `ATLAS_PCA_SUGGEST_MODEL`, `ATLAS_PCA_SUGGEST_PROVIDER`) from the environment only. The model sees names, descriptions and parameter names and types, never values; its answer is parsed against the closed trait vocabulary; the result is `suggested`, still unreviewed.
