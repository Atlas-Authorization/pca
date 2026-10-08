# The PCA loop (runnable example)

`pca-loop.ts` walks the whole Proof-Carrying Authority loop and prints it as a story, the way the
"OAuth dance" is usually taught. `src/e2e.test.ts` runs the same loop with assertions, so the example
cannot silently rot.

## Run it

```
pnpm --filter @atlasauth/pca example     # or, inside packages/pca:  pnpm example
```

This runs `tsx examples/pca-loop.ts` (`tsx` is a devDependency of this package). Tests:
`pnpm --filter @atlasauth/pca test`.

## The eight steps

| # | Who | What | API used |
|---|-----|------|----------|
| 1 | Principal | Generates a root key and mints a **Root Intent Grant** G: salted goal commitment, semantic predicates (`list_sessions` on `session:*`; `revoke_session` where `device != current_device`), caveats, risk policy | `generateKeyPair`, `mintGrant`, `verifyChain` |
| 2 | Principal -> Agent | Agent gets its own key; G is **delegated** to a task capability bound to that key (caveats can only be appended) | `delegate`, `verifyChain` |
| 3 | Agent | Builds a plan of nodes and **commits** its Merkle root | `commitPlan` |
| 4 | Agent | Emits a **PCActn** for `list_sessions`: the action, the capability chain, the plan root plus Merkle inclusion proof; signs it with the agent key | `signPCActn` |
| 5 | Guardian | **Policy VM** decides: predicates, caveats, risk `r`, threshold `t`, budget. Low `r` gives `t=1`, share released | `decide` |
| 6 | Verifier | Checks the PCActn offline: chain, plan inclusion, leaf signature, counter. Prints per-clause results; later-milestone clauses show `not-enforced`. Anchors to a **stub** ledger (array + Merkle root; M3 replaces it) | `verifyPCActnCore`, `pcactnDigest`, `merkleRoot` |
| 7 | Agent (rogue) | Attempts out-of-plan `delete_account` using a replayed proof. **REJECTED**: `plan_inclusion` fails; the Policy VM also withholds the share | `verifyPCActnCore`, `decide` |
| 8 | Agent + human | Routine actions each cost `kappa*r` of trust budget (printed before/after, "battery drains"). When the budget cannot cover the next action, `decide` demands `t=3` even though `r` is low. A human co-sign recharges it. An irreversible, high-blast action is in policy but needs `t=3` regardless | `decide`, `recharge` |

## What is real and what is stubbed

- Real: canonical hashing, Ed25519, Merkle plan commitment and inclusion, capability chain,
  PCActn signing/verification, predicates and caveats, risk functional, trust budget.
- Reported as `not-enforced` by `verifyPCActnCore` (later milestones): plan-root authorization,
  taint gate, attestation (M5), threshold signatures (M2/M4), revocation (M3), zk, bond.
- Stubbed in the example: the ledger (in-memory array, M3), attestation/freshness/provenance fields
  of the PCActn (empty values), the principal-device human co-sign (just calls `recharge`).
- Note: a valid proof is not the same as a signed-off action. `verifyPCActnCore` does not yet check
  that the threshold required by `decide` was met; the example prints this explicitly at step 8.

## PCA vs OAuth vs WebAuthn

| | OAuth 2.0 | WebAuthn | PCA |
|---|-----------|----------|-----|
| Question answered | authZ: may this client act for this user? | authN: is this the user? | authF (faithfulness): is this action within what the principal intended? |
| Credential | bearer **token** | signed **assertion** over a challenge | **proof-carrying action**: signed action + capability chain + plan inclusion proof |
| Granularity | one consent, then any call within the scope | one login ceremony | a proof per action |
| Bound to | scopes | an origin and a user-verifying device | a committed plan, a signed policy envelope, a holder key, a trust budget |
| If the agent is compromised | token is replayable within scope until expiry | not applicable (human present) | out-of-plan actions fail inclusion; in-plan ones are bounded by risk and the budget |
| Verified | by the AS / RS via introspection or JWT | by the RP | offline by anyone holding G's issuer key and the plan root |

In one line: where OAuth returns a bearer token after one consent, PCA verifies a proof per action bound to committed intent.
