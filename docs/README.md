---
title: Proof-Carrying Authority
order: 0
---

# Proof-Carrying Authority (PCA)

> **Status.** The libraries are published (TypeScript on npm under [`@atlasauth/pca*`](https://www.npmjs.com/org/atlasauth), with native verifiers in nine more languages) and the conformance suite is stable and shared across all of them. The hosted `/v1/pca/*` surface is gated off by default (`auth_config.pca.enabled = false`; every public route answers `404` while off), and PCA has not had an external security audit — see [Trust model](./security/trust-model.md) for what is and is not production-hardened before you rely on it as a sole control over high-value actions.

> **See it run (about a minute, no accounts, no Docker):** `npm create pca-app@latest my-demo && cd my-demo && npm install && npm start` plays an allow, a denial, a t=3 FROST step-up, a replay, three tampering attempts, budget exhaustion, a sub-agent that cannot exceed its parent, and an offline-verified receipt. See [Run the end-to-end demo](./guides/run-the-demo.md).

Classic auth answers two questions. **authN**: who are you? **authZ**: what may you do? Both are enough for a human, because the human is the policy engine and their identity implies faithfulness. An autonomous agent is a stochastic, externally steerable process: what it will do is unknown when authority is granted and can be manipulated while it runs.

PCA adds a third question, **authF**:

> Is this specific action a *faithful, uncompromised execution* of an authority the principal actually conferred?

PCA makes authF cheaply verifiable by replacing the bearer token with a **proof-carrying action (PCActn)**. The resource server does not check that the caller holds a secret. It verifies a proof that the action is a node of a pre-committed plan, inside a signed policy, reached through an intact attenuating capability chain, co-signed by as many parties as its risk demands, and affordable within a decaying trust budget. Verification is offline and deterministic.

## The loop

1. **Mint a Root Intent Grant.** The principal signs an envelope (goal commitment, action predicates, caveats, risk policy, agent binding) with their root key. `mintGrant()`.
2. **Attenuate or delegate.** The agent (or a sub-agent) receives a capability that can only be narrowed. `delegate()` / `attenuate()`.
3. **Commit a plan.** The agent commits the Merkle root of a DAG of intended actions. `commitPlan()`.
4. **Act.** Each action is a signed PCActn carrying an inclusion proof for its plan node, the capability chain, a monotonic counter and a risk claim. `buildPCActn()` / `agent.act()`.
5. **Decide.** The Policy VM evaluates predicates, caveats, the risk functional and the trust budget, and either releases the guardian signing share or refuses. `decide()`.
6. **Verify.** The resource server checks every clause. `verifyPCActn()` / `requirePCA()`.
7. **Outcome.** `allowed` (anchored in the transparency ledger, receipt returned), `denied`, or `step_up` (the risk needs a principal-device co-signature).
8. **Audit and revoke.** The ledger yields inclusion proofs per action; capabilities can be revoked, and an instance can be frozen.

## Documentation map

Read in this order the first time; every page links onward.

**Concepts** (the model)

| Page | What it covers |
|---|---|
| [PCA Core](./core.md) | The minimal spec on one page: grant, delegation chain, PCActn, caveats, the verify algorithm, what is an extension, and the Core conformance profile |
| [Maturity tiers](./maturity.md) | Stable core, production enforcement, experimental: the tier of every published package and of every feature inside `@atlasauth/pca` |
| [authN, authZ, authF](./concepts/authf.md) | Why a third question, and the six broken primitives it answers |
| [Credential model](./concepts/credential-model.md) | Root Intent Grant, attenuable capability chains, the PCActn |
| [Plan commitment](./concepts/plan-commitment.md) | L1: committing a plan DAG and proving inclusion |
| [Policy and risk](./concepts/policy-and-risk.md) | Predicates, caveats, the risk functional, the trust-budget control system and its safety bound |
| [Threshold and step-up](./concepts/threshold-and-step-up.md) | t-of-n multi-signature, FROST and DKG, guardian and principal shares |
| [Attestation](./concepts/attestation.md) | L0: software attestation and the hardware seam |
| [Ledger and revocation](./concepts/ledger-and-revocation.md) | Transparency ledger, crypto-shredding, revocation proofs, beacons and the kill switch |
| [Optimistic and ZK](./concepts/optimistic-and-zk.md) | Bonded fast-path with fraud proofs; compliance proofs that hide intent |
| [Intent layer](./concepts/intent-layer.md) | Binding an action to a signed intent: schemas, sessions, caps, facts, classifier dimensions, and what the layer does not prove |
| [Why PCA: a comparison](./concepts/comparison.md) | Seven agent attacks run against OAuth scopes, RAR, macaroons/Biscuit, UCAN and PCA, with the results |

**Guides** (do things)

| Page | What it covers |
|---|---|
| [Run the end-to-end demo](./guides/run-the-demo.md) | One command, no accounts: the nine-outcome story with a pass/fail exit code |
| [MCP quickstart](./guides/mcp-quickstart.md) | An MCP server whose tools require a proof-carrying action, and an agent that sends one: an allowed call and a refused one |
| [Agent quickstart](./guides/agent-quickstart.md) | Mint a grant, commit a plan, act, step up, delegate |
| [Resource-server quickstart](./guides/resource-server-quickstart.md) | `verifyPCActn`, `requirePCA`, hooks, and the hosted endpoints |
| [Playground](./guides/playground.md) | The browser demo that runs the real library |
| [Optimistic claims and bond settlement](./guides/optimistic-bonds.md) | Durable internal accounting for the optimistic path: atomic, retry-safe, with a challenge-window clock the claimant cannot move |
| [The transparency ledger and its witnesses](./guides/transparency-ledger.md) | A durable append-only log with checkpoints verified at every boundary; what it proves and what needs an independent witness |
| [Operate a ledger witness](./guides/operate-a-witness.md) | Run the reference witness: a minimal container that cosigns only consistent checkpoints |
| [Verify in your language](./guides/verify-in-your-language.md) | The conformance suite and the reference verifiers |

**Reference**

| Page | What it covers |
|---|---|
| [API](./reference/api.md) | Every `/v1/pca/*` and dashboard route |
| [Wire formats](./reference/wire-formats.md) | Canonicalization, hashing domains, signed messages: the normative bytes |
| [Glossary](./reference/glossary.md) | Terms and symbols |

**Security**

| Page | What it covers |
|---|---|
| [Threat model](./security/threat-model.md) | The reachable-action theorem, kill-chain cuts, defense-in-depth matrix |
| [Trust model](./security/trust-model.md) | What each party is trusted for, and the preview-status caveats |
| [Verifying releases](./security/verifying-releases.md) | Check that a package you install was built and published by the project's release workflow |
| [Trust model](./security/trust-model.md) | What each party is trusted for, what each verifier surface enforces, and the preview-status caveats |
| [Security contract](./security/security-contract.md) | The eleven invariants a resource server relies on, with enforcing function, failure behaviour, tests and current status per surface |

**Adoption**

| Page | What it covers |
|---|---|
| [PCA vs OAuth vs WebAuthn](./migration.md) | When to use which and how they compose |

## Where things live

| What | Where |
|---|---|
| Specification (protocol, verifier algorithm) | The Internet-Draft `draft-atlas-pca-authf`, and the [concepts](./concepts/authf.md) and [reference](./reference/wire-formats.md) pages |
| Primitives: grants, capabilities, plans, PCActn, policy VM, threshold, FROST, ledger, revocation, beacons, attestation, optimistic, zk | `@atlasauth/pca` |
| Agent client | `@atlasauth/pca-agent` (`createAgent`) |
| Resource-server verifier and guard | `@atlasauth/pca` (`verifyPCActn`, `requirePCA`) |
| Hosted endpoints | `/v1/pca/*` (gated by `auth_config.pca.enabled`) |
| Runnable end-to-end example | `pnpm --filter @atlasauth/pca example` |
| Playground | [Playground guide](./guides/playground.md) |
| Conformance suite and native verifiers (Go, Python, Rust, Java, Ruby, PHP, .NET, Swift, Kotlin) | [`conformance/`](https://github.com/Atlas-Authorization/pca/tree/main/conformance) in the PCA repository; [Verify in your language](./guides/verify-in-your-language.md) |

## Adoption ladder

PCA degrades to today's stack, so each rung is independently adoptable.

| Rung | Adds | Status in this codebase |
|---|---|---|
| 0 | OAuth 2.1 + PKCE + PoP (a PCActn with only scope and a PoP signature is an OAuth PoP request) | existing Atlas OAuth surface |
| 1 | Plan commitment, Policy VM cosign, transparency ledger, risk functional, declarative taint input | built |
| 2 | Real threshold signatures (multi-signature default, FROST optional), revocation proofs, dead-man beacons | built (hosted uses the multi-signature for agent and principal shares, a FROST aggregate for the guardian co-sign with every guardian share held by the one server, and revocation proofs; its kill switch is `freeze`, and signed liveness beacons gate adjudication when the instance enables them) |
| 3 | Attestation (software mode hosted; TEE-rooted agent identity), optimistic fast-path with fraud proofs | built; hardware verifiers for AMD SEV-SNP, Intel TDX, Azure Attestation, Google Confidential Space and NVIDIA GPUs are implemented and tested on evidence from real machines (a live attestation needs an actual confidential VM); the hosted surface verifies software attestors only |
| 4 | Weights-level attestation, zero-knowledge compliance | built; Groth16 compliance and Policy VM circuits (BN254, BLS12-381) plus transparent STARK (Winterfell / Plonky3) and RISC Zero zkVM provers; no circuit yet covers the full predicate language or custom caveats |
