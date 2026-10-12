# Tamarin v2 models (unbounded chains, clock/store rewriting, budget, scope/resource, allowlist rollback, FROST)

Tools: Tamarin 1.12.0, Maude 3.5.1 (`source ~/pcaenv.sh` on the cloud boxes); Lean 4.34.1 for `../pca-lean`.
Original (v1) models and results are untouched (`pca_actn.spthy`, `pca_threshold.spthy`, `pca_attest.spthy`, `run_all.sh`, `results/*.txt`).

| theory | what it adds | switches (`-D...`) |
|---|---|---|
| `pca_actn_unbounded.spthy` | verifier walks a delegation chain of ARBITRARY length, one hop per rule step | `NO_GREF_CHECK NO_ANCESTOR_CAV NO_AUD_CHECK NO_EXPIRY_CHECK NO_LEAF_SIG` |
| `pca_actn_time_store.spthy` | `Clock` thread over naturals + expiry in a rule premise; replay store as linear cells; counter as linear fact | `STORE_RACE_NONCE STORE_RACE_CTR NO_EXPIRY_CHECK NO_GREF_CHECK NO_AUD_CHECK NO_ANCESTOR_CAV NO_LEAF_SIG` |
| `pca_budget.spthy` | `budget_alloc` tree: monotone allocations, spends debit every node up to the root | `NO_PARENT_CHECK DEBIT_LEAF_ONLY NONATOMIC_DEBIT ROOT3` |
| `pca_scope_resource.spthy` | scope sets (verb_in) and resource prefixes (resource_in) narrow along chains of any length | `NO_ANCESTOR_SCOPE NO_ANCESTOR_RES` |
| `pca_attest_allowlist.spthy` | software-attestation measured model/weights/operator allowlist + manifest rollback + anchor | `NO_VERSION_CHECK STATE_WIPE ANCHORED ANCHOR_REPLAY NO_WEIGHTS_CHECK NO_OPERATOR_CHECK` (combine with `+` in `run_all_v2.sh`) |
| `pca_frost_sign.spthy` | FROST two-round signing, binding factors, t-of-n, nonce reuse | `NONCE_REUSE NO_BINDING` |
| `pca_frost_dkg.spthy` | DKG proof of possession vs rogue-key | `NO_POP` |

`pca_budget_v4.spthy` (structural node ids, root meter `RCnt`) and `pca_budget_v5_focus.spthy` (v4 + one focused node
whose meter is the separate fact `FCnt`) carry `root_bound` / `node_bound`. Prove node_bound with
`--heuristic=o --oraclename=oracle_nodebound.sh`, which leaves `!Lim`/`!Node` and `Debit` tokens until last; any oracle
that solves `!Lim` early unfolds the ancestor chain without bound. Bounded TLC mirrors of the budget and scope models
(attack witnesses) are in `../tla/BudgetTree.tla` and `../tla/ScopeChain.tla`. Results and ledger:
`docs/pca/security/formal-verification.md` ("Budget and scope closure").

`oracle_walk.sh` is a goal-ranking oracle (`--heuristic=O --oraclename=./oracle_walk.sh`) that solves the
recursive `Walk(...)` premise last.

## Reproduce
```sh
cd formal/tamarin
./run_all_v2.sh 900 3                       # all v2 theories, 900 s per lemma (per heuristic list), 3 parallel jobs
./run_all_v2.sh 900 3 pca_frost             # filter by result-name prefix (theory[__VARIANT])
MEM=4g ./run_all_v2.sh 900 2 pca_budget     # cap tamarin's heap (+RTS -M) so a blow-up cannot take the box down
# one lemma by hand:
tamarin-prover --prove=root_bound --heuristic=c -DDEBIT_LEAF_ONLY pca_budget.spthy
# Lean:
cd ../pca-lean && lake build               # PcaProof.ChainLink: walk-style recursion == fold (Eff) definition
```
Results land in `results/v2/<theory>[__VARIANT].txt`; a line `... TIMEOUT/KILLED/no-result ... (NOT proved)` means
the lemma was NOT proved (a timeout is not a proof). Each result is followed by `# wall=..s heuristic=.. tamarin-prover 1.12.0`.
