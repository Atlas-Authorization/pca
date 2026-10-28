# pca-demo: the whole PCA story in one command

A runnable, zero-dependency-on-the-cloud demonstration of **Proof-Carrying Authority**. One command starts
a real HTTP resource server, a guardian that cosigns with FROST 3-of-5, and an agent, then plays nine
scripted outcomes and prints what was allowed, what was denied, and exactly why.

No cloud account. No Docker. No API keys. No network beyond `127.0.0.1`. About 1 second to run.

The process **exits nonzero if any outcome deviates** (or is denied for the wrong reason), so it doubles as
a smoke test for your PCA install.

## Run it

From a checkout of this repo (build once, then run):

```bash
pnpm install
pnpm --filter @atlasauth/pca-fetch... build     # builds @atlasauth/pca, backend, pca-fetch
node examples/pca-demo/run.mjs
```

Flags:

```bash
node examples/pca-demo/run.mjs --step       # pause before each step (press Enter)
node examples/pca-demo/run.mjs --json       # machine-readable result on stdout, nothing else
node examples/pca-demo/run.mjs --no-color   # (also honors NO_COLOR)
node examples/pca-demo/run.mjs --break      # run against a mis-configured server: must exit 1
```

Scaffold it as your own project (default template of `create-pca-app`):

```bash
npm create pca-app@latest my-pca-demo && cd my-pca-demo && npm install && npm start
```

Once the packages are published, a bare `npx pca-demo` does the same with no checkout. (The PCA packages depend only on `@atlasauth/pca` and
nothing from any other product. The `0.1.0` builds already on npm predate that and still pull in a separate
backend package, so a registry install works only after the next release of the `pca-*` packages; installing from
tarballs packed out of this repo works today, see below.)

### Prove it works from an empty directory

```bash
examples/pca-demo/scripts/fresh-install-check.sh
```

It packs the five workspace packages the demo needs into tarballs (what `npm publish` would upload),
installs only those into an empty temp project, runs the demo from there, and prints the time of each
phase. Measured on a laptop: pack 1-2 s, `npm install` 2-3 s (55 packages, 75 MB in `node_modules`, most
of it optional ZK tooling that the demo does not touch), first run under 1 s: about 5 seconds end to end.

Tests (spawn the demo and assert every outcome and every denial reason):

```bash
cd examples/pca-demo && npm test
```

## What you will see

```
== Step 4: Risky action escalates to step-up
   $450 is 90% of the cap: the agent alone is not enough. Needs t=3 cosigners.
   -> refund $450 with only the agent signature                          DENIED  HTTP 403
      why: threshold: only 1 distinct valid key(s), need 3
   guardian nodes 1+2 alone try to sign -> frostCosign: quorum of 2 is below the threshold t=3
   guardian Policy VM: release=true, r=0.90, requires t=3
   guardian FROST 3-of-5: nodes 1,3,5 produced ONE 64-byte Ed25519 signature under the group key
   principal approved on their device (Ed25519 share)
   -> refund $450 with agent + guardian(FROST) + principal               ALLOWED HTTP 200

Summary
step  action                                             expected  actual    reason
1     grant + plan minted and registered                 VERIFIED  VERIFIED  grant K3mnJ0qnMzAP, 8-node plan
2     in-plan refund $42                                 ALLOWED   ALLOWED   all checks passed
3     off-plan refund (charge not in plan)               DENIED    DENIED    plan_root_authorized: known plan does not match plan.root
4a    refund $450, agent signature only                  DENIED    DENIED    threshold: only 1 distinct valid key(s), need 3
4b    2 of 5 guardian nodes try to cosign                REFUSED   REFUSED   frostCosign: quorum of 2 is below the threshold t=3
4c    refund $450 with t=3 cosigners                     ALLOWED   ALLOWED   all checks passed
5     replay of accepted action                          DENIED    DENIED    replay: 1 is not greater than last seen 3 (replay)
6a    bit-flipped signature                              DENIED    DENIED    leaf_signature: signature does not verify under the leaf holder key...
6b    widened delegation (caveat removed)                DENIED    DENIED    cap_chain: hop 1: body digest mismatch
6c    swapped audience                                   DENIED    DENIED    audience: aud does not match this resource server / instance
7a    refund $140 while budget remains                   ALLOWED   ALLOWED   all checks passed
7b    refund $140 after budget is spent                  DENIED    DENIED    policy: trust budget depleted: human recharge required
8a    sub-agent refund $60 (inside delegation)           ALLOWED   ALLOWED   all checks passed
8b    sub-agent refund $200 (exceeds delegation)         DENIED    DENIED    delegated_caveats: delegation caveat(s) not satisfied: predicates
8c    sub-agent action the parent never held             DENIED    DENIED    policy: no predicate permits gmail.send on msg:thread-1
9     receipt + inclusion proof verify offline           VERIFIED  VERIFIED  opening, inclusion, signed head, receipt chain all check out
9b    tampered receipt log (a deny rewritten as allow)   REFUSED   REFUSED   failed: receipt hash-chain is intact

All 17 outcomes matched expectations in 386 ms. PCA behaved as specified.
```

## What each step proves

| Step | What happens | PCA guarantee it demonstrates |
|---|---|---|
| 1 | Principal mints a signed grant (`stripe.refund` up to $500, $300 trust budget) and registers the committed plan root with the server. | **Authority is explicit and bounded.** Scope, limits, budget and plan are signed by the human; the agent cannot enlarge them. The grant also states the autonomy bound: the most a fully compromised agent can auto-spend. |
| 2 | Agent refunds $42 on a planned charge. **ALLOWED.** | **Faithful execution.** The action is a node of the pre-committed plan (Merkle inclusion), inside the signed predicates, signed by the leaf key, for this audience, with a fresh counter. |
| 3 | Agent refunds $42 on a charge that is not in the plan. **DENIED** (`plan_root_authorized`). | **Plan commitment.** Being permitted by the policy is not enough; the action must be one the principal authorized. Off-plan actions fail even when the verb and amount are legal. |
| 4 | A $450 refund (90% of the cap). Agent alone: **DENIED**, needs t=3. Two guardian nodes alone: **REFUSED** by FROST. Agent + guardian (FROST 3-of-5, nodes 1,3,5) + principal device: **ALLOWED.** | **Risk-adaptive threshold step-up.** Higher risk demands more independent signers. The guardian runs its own Policy VM, and its key is a FROST group key: no fewer than 3 of 5 nodes can produce its signature, and the result is an ordinary Ed25519 signature the verifier checks. |
| 5 | The step-2 request is replayed byte for byte. **DENIED** (`replay: ... (replay)`). | **Anti-replay.** Counters are strictly increasing per holder; a captured proof is worthless. |
| 6a-c | A bit-flipped signature, a sub-agent that strips its own caveat from its delegation, and an action re-addressed to another server. **All DENIED** (`leaf_signature`, `cap_chain`, `audience`). | **Integrity and binding.** Every field is covered by a signature; delegation chains cannot be widened; a proof for one server is useless at another. |
| 7 | Two auto-approved $140 refunds against a $300 budget. The first is **ALLOWED**; the second is **DENIED** (`trust budget depleted: human recharge required`). | **The trust budget.** Machine-only authority is metered. When the budget is spent the action escalates to a human; it does not silently continue. |
| 8 | A sub-agent holding a "refunds up to $100" delegation: $60 **ALLOWED**; $200 **DENIED** (delegation caveat); an email the parent never had **DENIED** (no predicate). | **Attenuation only.** Authority can shrink down a delegation chain, never grow. |
| 9 | An auditor, holding only public keys and a JSON bundle, verifies the headline receipt offline: salted ledger commitment, Merkle inclusion proof, signed tree head, hash-chained access log. A second bundle with one denial rewritten as an allowance is **REFUSED**. | **Offline auditability.** No server or database is needed to check what happened, and history cannot be rewritten without detection. |

## How it is put together

- `story.mjs` is the script and is meant to be read top to bottom (one file, heavily commented).
- The resource server is plain `node:http` wrapping `withPCA` from `@atlasauth/pca-fetch`, the real
  default-deny verifier. Its `guard` options object (`audience`, `resolveGrant`, `budgetStore`, `hooks`,
  `context`) is what you would copy into your own server.
- The agent is built with the `agent()` facade from `@atlasauth/pca`; plan nodes and proofs use
  `commitPlan` / `buildPCActn`.
- The guardian uses `frostTrustedDealerKeygen`, `frostCosign` and the `decide()` Policy VM.
- `load.mjs` resolves `@atlasauth/pca*` from `node_modules`, falling back to the repo's built `dist/`.

## What this demo is not

- The five FROST key shares and the principal key all live in one process, so the *threshold property*
  (no signature without 3 independently held shares) is demonstrated by the API refusing a 2-node
  quorum, not enforced by separate trust domains. In production the shares sit on separate hosts or HSMs.
- State (counters, budget, ledger) is in memory. Back the `budgetStore` with Redis or a database.
- Revocation is wired to "never revoked" and there is no hardware attestation; both are covered in the
  [guides](../../docs/README.md).
- This is not an external security audit. See the [trust model](../../docs/security/trust-model.md).
