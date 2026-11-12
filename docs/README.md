---
title: Proof-Carrying Authority
order: 0
---

# Proof-Carrying Authority (PCA)

## Why this is not "API keys with scopes"

| | API key with scopes | PCA |
|---|---|---|
| What is authorized | A category, held for a long time (`payments:write`) | One concrete action with its arguments ("refund $40 on charge ch_1") |
| Parameters | Not seen | Checked per call against limits (amount, merchant, repo) |
| If stolen | Full access until rotated | Useless: single-use, bound to audience, operation and parameters |
| Delegation | Share the key or mint an equal one | Signed chain person → agent → sub-agent; each hop can only narrow |
| Purpose | None | Must fit the signed goal and plan, compiled to policy with proofs |
| Totals over time | None | Durable totals across sessions, agents, fleet; replay and revocation freshness |
| Outcome | Yes / no | Allow / deny / escalate to a person who answers with a signature |
| Model judgement | n/a | Classifier output can only tighten, never widen |
| Audit | "This key called this endpoint" | Signed record of chain, goal, limits; transparency log |

Neighbours: OAuth RAR (rich authorization requests), Macaroons and Biscuit (attenuating tokens), Cedar and OPA (policy engines). Each does one or two of these; PCA's claim is the combination, verified the same way in 10 languages. Where PCA is overkill: plain service-to-service calls with no agent acting on someone's behalf.

> **Status.** PCA 0.5 is the first production release. The libraries are published (TypeScript on npm under [`@atlasauth/pca*`](https://www.npmjs.com/org/atlasauth), with native verifiers in nine more languages) and the conformance suite is stable and shared across all of them. Every package declares a [maturity tier](./maturity.md): stable, production, or hardened (finished and evidenced, awaiting one named outside action). The hosted `/v1/pca/*` surface is feature-gated and off by default (`auth_config.pca.enabled = false`; every public route answers `404` while off). PCA has not had an external security audit; see the [Trust model](./security/trust-model.md) for what each tier does and does not establish before you rely on it as a sole control over high-value actions.

### Hardened, awaiting an outside action

The proof format and verification are stable, the enforcement path (the full verifier, `requirePCA`, the HTTP and agent adapters, the action kit, grants, the goal compiler, the harness and the product-layer modules) is production, and nothing in the main path is labelled experimental. A production unit carries a `pending_ci` flag until the CI and mutation gates have passed once on the release candidate; the flip is mechanical. The units below are opt-in extensions outside the main path.

| Unit | Awaiting |
|---|---|
| FROST threshold signing and the DKG (`ext/frost`), `@atlasauth/pca-pq-threshold` | independent audit |
| Hybrid key encapsulation (`ext/kem`) | independent audit |
| Zero-knowledge compliance, the SNARK modes (`ext/zk`; the attested-VM mode is a trusted signer, not a proof) | trusted-setup ceremony and independent review |
| Hardware attestation verifiers: AMD SEV-SNP, Intel TDX, Azure Attestation, Google Confidential Space, NVIDIA GPU, PUF (`ext/attestation`), `@atlasauth/pca-attest-eat` | independent audit and hardware evaluation on real hosts |
| QRNG entropy (`entropy`) | hardware evaluation on real quantum entropy devices |
| Transparency ledger (`ext/ledger`) | independent witnesses and independent audit |
| `@atlasauth/pca-bbs`, `@atlasauth/pca-fndsa`, `@atlasauth/pca-fndsa-wasm`, `@atlasauth/pca-less-wasm` | final standard (and independent audit) |
| `@atlasauth/pca-aggsig`, `-oprf`, `-ratchet`, `-mpc` (and its two wasm cores), `-fhe`, `-abe`, `-vdf`, `stark-pca`, `pca-folding-ivc` | independent audit |

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

New here? Start with [Start here](./start-here.md). Otherwise read in this order the first time; every page links onward.

**Concepts** (the model)

| Page | What it covers |
|---|---|
| [PCA Core](./core.md) | The minimal spec on one page: grant, delegation chain, PCActn, caveats, the verify algorithm, what is an extension, and the Core conformance profile |
| [Maturity tiers](./maturity.md) | Stable core, production, hardened (awaiting an outside action), experimental: the tier of every published package and of every feature inside `@atlasauth/pca` |
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
| [How PCA relates to other offerings](./concepts/positioning.md) | One answer per claim from identity products, authorization servers, guardrails and the MCP and A2A protocols, with sources |

**Guides** (do things)

| Page | What it covers |
|---|---|
| [Start here](./start-here.md) | Pick the path that matches what you want to do, by task and by role |
| [Golden paths](./guides/golden-paths.md) | Six jobs with a runnable scaffold each: an MCP server, payments with approval, your own actions, goal to policy, a sub-agent, an A2A hop |
| [Add PCA to your framework](./guides/framework-recipes.md) | The complete guard for Express, FastAPI, Gin, axum, Rails, Laravel, Spring, Ktor, ASP.NET Core and Vapor |
| [Run the end-to-end demo](./guides/run-the-demo.md) | One command, no accounts: the nine-outcome story with a pass/fail exit code |
| [MCP quickstart](./guides/mcp-quickstart.md) | An MCP server whose tools require a proof-carrying action, and an agent that sends one: an allowed call and a refused one |
| [Agent quickstart](./guides/agent-quickstart.md) | Mint a grant, commit a plan, act, step up, delegate |
| [Resource-server quickstart](./guides/resource-server-quickstart.md) | `verifyPCActn`, `requirePCA`, hooks, and the hosted endpoints |
| [Playground](./guides/playground.md) | The browser demo that runs the real library |
| [Optimistic claims and bond settlement](./guides/optimistic-bonds.md) | Durable internal accounting for the optimistic path: atomic, retry-safe, with a challenge-window clock the claimant cannot move |
| [Undo windows instead of approvals](./guides/undo-windows.md) | Confirmed-reversible actions run now with a one-click undo for the person; irreversible ones still ask first |
| [Agent payments, risk-priced approvals and wallet permissions](./guides/agent-payments-and-approvals.md) | Bind a card-network agent token to a grant, ask a person only when the expected loss exceeds the cost of asking, and map a grant to an ERC-7715 wallet permission |
| [The transparency ledger and its witnesses](./guides/transparency-ledger.md) | A durable append-only log with checkpoints verified at every boundary; what it proves and what needs an independent witness |
| [Operate a ledger witness](./guides/operate-a-witness.md) | Run the reference witness: a minimal container that cosigns only consistent checkpoints |
| [Analyze, author and test a policy](./guides/policy-analysis.md) | Most that can leave, what needs a human, what a change widens, what the agent may do now, least-privilege proposals, coverage, repairs, forbid certificates and linked templates |
| [Carry a PCA grant in your OAuth server](./guides/pca-grant-oauth.md) | The `pca_grant` authorization-details type: any OAuth server carries the grant, the resource server still requires a per-action proof |
| [Caveat language](./guides/caveat-language.md) | Third-party caveats and discharges, `seal`, narrowing, `max_uses` and `derive`, with a runnable example |
| [Workflow authorization](./guides/workflow-authorization.md) | Authorize a multi-step plan as a graph, not step by step |
| [Read-side authorization](./guides/read-side-authorization.md) | Masks, the read vault and aggregates: what a reader may see |
| [Blueprints and group kill](./guides/blueprints.md) | Mint grants from a blueprint and revoke a whole group at once |
| [Obligations, leases and break-glass](./guides/obligations-leases-break-glass.md) | Duties that must be met, time-boxed authority, and emergency override |
| [Token vault proxy](./guides/token-vault-proxy.md) | The agent never holds the credential; the vault re-derives the signed action |
| [Spend rails](./guides/spend-rails.md) | Real-time card authorization against a grant, with Stripe Issuing events |
| [Sandbox](./guides/sandbox.md) | Run a tool in a sandbox and record the containment class in the receipt |
| [MCP pca_need](./guides/mcp-pca-need.md) | A tool says what proof it needs; the agent resumes with exactly that |
| [Agent-to-agent (A2A)](./guides/a2a.md) | Attach a proof to an A2A task and verify it on the receiving side |
| [Verify in your language](./guides/verify-in-your-language.md) | The conformance suite and the reference verifiers |

**Reference**

| Page | What it covers |
|---|---|
| [API](./reference/api.md) | Every `/v1/pca/*` and dashboard route |
| [Wire formats](./reference/wire-formats.md) | Canonicalization, hashing domains, signed messages: the normative bytes |
| [Glossary](./reference/glossary.md) | Terms and symbols |
| [Refusal reasons](./reference/refusals.md) | Every refusal, what it means, how to fix it |
| [What runs in which language](./reference/language-parity.md) | Agent side and server side across the ten languages |
| [Product-layer modules](./reference/product-layer.md) | DLP, connector catalog, kill switch, mesh witness store: quick start, failure table, limits |

**Security**

| Page | What it covers |
|---|---|
| [Threat model](./security/threat-model.md) | The reachable-action theorem, kill-chain cuts, defense-in-depth matrix |
| [Verifying releases](./security/verifying-releases.md) | Check that a package you install was built and published by the project's release workflow |
| [Trust model](./security/trust-model.md) | What each party is trusted for, what each verifier surface enforces, and the limits by maturity tier |
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
