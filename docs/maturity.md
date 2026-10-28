---
title: Maturity tiers
order: 2
---

# Maturity tiers

PCA is published as about ninety packages on npm, PyPI and crates.io, and they are not equally mature. Every published package declares one of four tiers, and so does every feature inside `@atlasauth/pca`. This page defines the tiers, lists every package and feature with its tier, and explains the classifications that are not obvious.

PCA 0.5 is the first production release: everything on the main path is production or stable, and what is not is labelled with exactly what it awaits. No published unit is experimental in 0.5; the tier remains defined for new work.

Two things hold for every tier. PCA is pre-1.0, so breaking changes arrive in minor releases with a changelog entry and a migration note. PCA has not had an independent security audit: the units whose claims depend on one are the hardened ones, and each says what it awaits. The tiers describe how much the project itself stands behind a package. They are not a substitute for your own security review.

## The tiers

| Tier | What it covers | What you can rely on | Evidence behind it |
|---|---|---|---|
| **Stable** (stable core) | The wire format and the proof check ([PCA Core](./core.md)): canonical encoding, capability chains, plan inclusion, Ed25519 and the post-quantum and hybrid signature suites, the nine core checks. Also the conformance corpus, the JSON Schemas, and the core verifiers published on PyPI and crates.io. | The wire format changes only through a new version identifier. Changes to what a check accepts are listed in the changelog with a migration note. Every language reproduces the shared corpus. The [security contract](./security/security-contract.md) invariants C-1 (no invalid proof authorizes) and C-2 (nothing outside the capability chain authorizes) hold on every surface. | The shared conformance corpus and adversarial vector set, run by every language with zero disagreements allowed. Formal models of the verifier and the protocol. Mutation testing in which every surviving mutant must be a reviewed equivalent. |
| **Production** (production enforcement) | What you deploy to authorize real actions: `requirePCA` and the full verifier (Policy VM, caveats, risk, budgets, replay and revocation state, approvals), the HTTP adapters built on it, `authorizeToolCall` for MCP tool calls, the agent-side wrappers that sign tool calls, and the tools you need to build and test a deployment. | Supported for production use. Breaking changes to APIs or defaults are never made in a patch release, and they are listed in the changelog with a migration note. On this surface the security contract holds except where its "Full TS" column says otherwise. | Package tests on every change. The authorization decision is made by `@atlasauth/pca`, which carries the stable-tier evidence and is mutation tested. |
| **Hardened** (hardened, awaiting an outside action) | Units whose engineering is finished and evidenced but whose claims need something the project cannot supply by itself. Each README header says exactly what it awaits: independent audit, trusted-setup ceremony, hardware evaluation, independent witnesses or final standard. It is never shown as Production until that outside action is done. | What its README's Status section says it has: for example secret scalar arithmetic on a fixed-width path with a timing test, test vectors cross-checked against an independent implementation, durable nonce handling, fuzzed parsers and known-answer tests. The API may still change. Do not rely on it as the only control over anything of value until the review it awaits has been done. | The evidence list in the [audit package](./validation/audit-package.md), including the cross-implementation vectors and the timing report. |
| **Experimental** | Units that are new, heuristic by design, or lack evidence the higher tiers require (a clean mutation record, an independent review, a run on real hardware). | Only what its own README states. Its API may change, or the package may be removed, in any release. Do not make it the only control protecting anything of value. | Package tests on every change. Some packages are also mutation tested. Each README's Status section says what is validated and what is not. |

A security evidence report is attached to every release. It lists which of these gates ran for that release, their results, and any outstanding exceptions. See [Verifying a release](./security/verifying-releases.md).

## Where the tier is declared

| Registry | Field | Where you can read it |
|---|---|---|
| npm | `"pca": { "maturity": "<tier>" }` in `package.json` (`@atlasauth/pca` also has `pca.features`) | the installed package's `package.json` |
| PyPI | `[tool.pca]` `maturity = "<tier>"` in `pyproject.toml` | the source distribution's `pyproject.toml` |
| crates.io | `[package.metadata.pca]` `maturity = "<tier>"` in `Cargo.toml` | `cargo metadata` (the `metadata.pca` field of the package) |

Every README also opens with a `Maturity: **<tier>**` line, which the npm, PyPI and crates.io pages display. The release checks fail when any of the following is true:

- a published package declares no tier;
- its README line disagrees with its manifest;
- an experimental package's README does not say it is experimental;
- a stable or production package's README calls it experimental;
- a module of `@atlasauth/pca` has no tier.

## Packages

### npm

<!-- maturity:npm:start -->
| Package | Tier |
|---|---|
| `@atlasauth/pca` | stable |
| `@atlasauth/pca-conformance` | stable |
| `@atlasauth/pca-schema` | stable |
| `@atlasauth/pca-verified-core` | stable |
| `@atlasauth/pca-a2a` | production |
| `@atlasauth/pca-acp` | production |
| `@atlasauth/pca-actions` | production |
| `@atlasauth/pca-agent` | production |
| `@atlasauth/pca-agentcard` | production |
| `@atlasauth/pca-ai-sdk` | production |
| `@atlasauth/pca-analyzer` | production |
| `@atlasauth/pca-anthropic` | production |
| `@atlasauth/pca-ap2` | production |
| `@atlasauth/pca-authzen` | production |
| `@atlasauth/pca-ciba` | production |
| `@atlasauth/pca-cli` | production |
| `@atlasauth/pca-compliance` | production |
| `@atlasauth/pca-connect` | production |
| `@atlasauth/pca-connectors` | production |
| `@atlasauth/pca-control-evals` | production |
| `@atlasauth/pca-dataflow` | production |
| `@atlasauth/pca-doctor` | production |
| `@atlasauth/pca-dpop` | production |
| `@atlasauth/pca-events` | production |
| `@atlasauth/pca-explain` | production |
| `@atlasauth/pca-express` | production |
| `@atlasauth/pca-fastify` | production |
| `@atlasauth/pca-fetch` | production |
| `@atlasauth/pca-gateway` | production |
| `@atlasauth/pca-gnap` | production |
| `@atlasauth/pca-goal` | production |
| `@atlasauth/pca-grants` | production |
| `@atlasauth/pca-harness` | production |
| `@atlasauth/pca-hono` | production |
| `@atlasauth/pca-idjag` | production |
| `@atlasauth/pca-intent` | production |
| `@atlasauth/pca-invariants` | production |
| `@atlasauth/pca-langchain` | production |
| `@atlasauth/pca-llamaindex` | production |
| `@atlasauth/pca-mastra` | production |
| `@atlasauth/pca-mcp` | production |
| `@atlasauth/pca-mcp-rs` | production |
| `@atlasauth/pca-next` | production |
| `@atlasauth/pca-notary` | production |
| `@atlasauth/pca-oauth` | production |
| `@atlasauth/pca-oidc` | production |
| `@atlasauth/pca-openai` | production |
| `@atlasauth/pca-openai-agents` | production |
| `@atlasauth/pca-otel` | production |
| `@atlasauth/pca-payments` | production |
| `@atlasauth/pca-policy-bridge` | production |
| `@atlasauth/pca-policy-ci` | production |
| `@atlasauth/pca-rag` | production |
| `@atlasauth/pca-revoke` | production |
| `@atlasauth/pca-rotate` | production |
| `@atlasauth/pca-sandbox` | production |
| `@atlasauth/pca-scim` | production |
| `@atlasauth/pca-scitt` | production |
| `@atlasauth/pca-sdjwt` | production |
| `@atlasauth/pca-siem` | production |
| `@atlasauth/pca-signals` | production |
| `@atlasauth/pca-spiffe` | production |
| `@atlasauth/pca-store-conformance` | production |
| `@atlasauth/pca-testing` | production |
| `@atlasauth/pca-txn-tokens` | production |
| `@atlasauth/pca-vc` | production |
| `@atlasauth/pca-vercel-ai` | production |
| `@atlasauth/pca-webauthn` | production |
| `@atlasauth/pca-webbotauth` | production |
| `create-pca-app` | production |
| `@atlasauth/pca-abe` | hardened |
| `@atlasauth/pca-aggsig` | hardened |
| `@atlasauth/pca-attest-eat` | hardened |
| `@atlasauth/pca-bbs` | hardened |
| `@atlasauth/pca-fhe` | hardened |
| `@atlasauth/pca-fndsa` | hardened |
| `@atlasauth/pca-fndsa-wasm` | hardened |
| `@atlasauth/pca-less-wasm` | hardened |
| `@atlasauth/pca-mpc` | hardened |
| `@atlasauth/pca-mpc-lwe-ot-wasm` | hardened |
| `@atlasauth/pca-mpc-wasm` | hardened |
| `@atlasauth/pca-oprf` | hardened |
| `@atlasauth/pca-pq-threshold` | hardened |
| `@atlasauth/pca-ratchet` | hardened |
| `@atlasauth/pca-vdf` | hardened |
<!-- maturity:npm:end -->

### PyPI

<!-- maturity:pypi:start -->
| Package | Tier |
|---|---|
| `atlas-pca` | stable |
| `atlas-pca-agent-framework` | production |
| `atlas-pca-crewai` | production |
| `atlas-pca-fastmcp` | production |
| `atlas-pca-google-adk` | production |
| `atlas-pca-haystack` | production |
| `atlas-pca-langgraph` | production |
| `atlas-pca-pydantic-ai` | production |
<!-- maturity:pypi:end -->

### crates.io

<!-- maturity:crates:start -->
| Package | Tier |
|---|---|
| `atlas-pca` | stable |
| `pca-folding-ivc` | hardened |
| `stark-pca` | hardened |
<!-- maturity:crates:end -->

`zkvm-pca` (the RISC Zero proof of the release gate) is not published: its guest build patches crates.io dependencies with git forks.

### Why these classifications

- **The core verifiers are stable, and their HTTP middleware only checks the proof.** `atlas-pca` on PyPI and `atlas-pca` on crates.io are stable as core verifiers: they reproduce the shared corpus. Their middleware (`require_pca`, the FastAPI and Django helpers, the axum layer) runs the core check only. It evaluates no caveats and checks no replay or revocation (see the "Native" column of the security contract). Use them as the proof check and add those checks yourself.
- **The gateway, the execution guards and the Python adapters are production (pending CI).** `@atlasauth/pca-gateway`, the execution guards `@atlasauth/pca-mastra`, `@atlasauth/pca-vercel-ai` and `@atlasauth/pca-openai-agents`, and the seven Python framework adapters run the full verifier by default: they evaluate the grant's limits and caveats, require a revocation check and consume the replay counter. Signature-only mode is an explicit opt-out and a pre-filter, and the OpenAI Agents guardrails stay signature-only by design.
- **The HTTP adapters are production.** `@atlasauth/pca-express`, `-fastify`, `-hono`, `-next` and `-fetch` are thin wiring over `requirePCA`, which makes every decision. In `@atlasauth/pca-mcp-rs` the production entry point is `authorizeToolCall`. Its `authorizeRequest` only checks admission.
- **Agent-side wrappers are production.** `@atlasauth/pca-mcp`, `-langchain`, `-llamaindex`, `-openai`, `-anthropic` and `-ai-sdk` sign tool calls and do not authorize them. The resource server's verifier decides.
- **The tools are production.** `@atlasauth/pca-cli`, `@atlasauth/pca-testing`, `@atlasauth/pca-store-conformance` and `create-pca-app` are supported. The test kit's helpers are for tests only, as its README says.
- **The action kit, grants, the goal compiler, the harness and the control evaluations are production (pending CI).** `@atlasauth/pca-actions` (action definitions, traits, importers, packs, approval rendering), `@atlasauth/pca-grants` (grant management, leases, blueprints, break-glass, workflow receipts), `@atlasauth/pca-goal` (the typed goal IR and compiler with machine-checked proofs; the package is private until the owner publishes it), `@atlasauth/pca-harness` (the mediator for black-box models; its measurement is self-asserted by the signer and is stated as a limit, not a tier) and `@atlasauth/pca-control-evals` (control-evaluation gates that never pass vacuously; the numbers depend on the red suites you supply). Each has a fail-closed table, exact-outcome tests, security-contract entries and a place in the mutation set.
- **The product layer is production (pending CI), and advisory features are production because of what they enforce.** The `product-layer` feature (import path `@atlasauth/pca/ext/research`) covers mesh, sessions, the behavioural immune system, reputation, safety certificates, natural-language policy review, DLP, guardian HA, contracts and their enforcer, console, budget forecast, policy simulation and debugging, and the connector catalog. The heuristic ones are advisory by construction: the immune system and DLP can only tighten, a reputation is never an authorization input, and a natural-language policy loads only after a signed, pinned review. What they enforce is exact and tested; what they estimate is labelled as an estimate.
- **QRNG entropy is hardened, awaiting hardware evaluation.** `entropy` is its own feature: the SP 800-90B health tests, fail-closed sources and `requireQuantum` are done, but no real quantum entropy device has been evaluated. The PUF root (`attest-puf`) is in the hardware attestation feature for the same reason.
- **The proof-system crates are hardened, awaiting independent audit.** `stark-pca` and `pca-folding-ivc` use a standard Nova and Poseidon construction, cross-checked against an independent Poseidon reference and fuzzed. The Winterfell STARK is not zero-knowledge: its trace is not blinded, so it gives soundness and succinctness but not witness privacy.

## Features inside `@atlasauth/pca`

`@atlasauth/pca` is a stable package that also carries production and hardened features. Its manifest lists each feature's tier under `pca.features`:

<!-- maturity:features:start -->
| Feature | Tier | Key | Modules |
|---|---|---|---|
| Proof format and core verification (@atlasauth/pca/core) | stable | `core` | 14 |
| Post-quantum and hybrid signature suites: ML-DSA and SLH-DSA (FIPS 204, FIPS 205) and their Ed25519 hybrids (the FN-DSA and LESS backends are separate, hardened packages) | stable | `pq-signatures` | 1 |
| Full verifier and requirePCA: Policy VM, predicates, caveats, risk, budgets, replay, revocation, approvals, discovery | production | `server` | 37 |
| Durable replay and budget state (@atlasauth/pca/durable-state) | production | `durable-state` | 1 |
| Default threshold step-up: independent Ed25519 / ML-DSA / hybrid shares bound to the signer set | production | `threshold-multisig` | 1 |
| Software attestation path: attestor-signed documents, signed allowlists and their transparency anchoring, post-quantum software roots, the agent passport and the strict X.509 reader | production | `attestation-software` | 8 |
| Optimistic execution: claims, challenge window, fraud proofs, bond settlement and its durable store (internal accounting only) | production | `optimistic` | 4 |
| Intent layer, binding and enforcement: signed intent statements and the envelope intent binding, action schemas, session roots and delta grants, accumulators and monitors, world facts and offer sets, parameter provenance and label receipts, classifier dimensions, committed maps, revocation epochs and intent questions | production | `intent` | 35 |
| Intent layer frontier, tighten-or-escalate only: semantic judge threshold, objective risk functional and its grant binding, proof of progress, and the signal typing that lets none of them grant anything | production | `intent-frontier` | 5 |
| Product-layer modules: agent mesh, multi-agent sessions, behavioural immune system, reputation, safety certificates, natural-language policy review, DLP, guardian HA, console, budget forecast, policy simulation and debugging, contracts, connector catalog (advisory features are production because what they enforce is tighten-only or advisory by construction; import path @atlasauth/pca/ext/research) | production | `product-layer` | 21 |
| FROST threshold signing (RFC 9591), the PedPoP DKG, networked FROST and FROST with a post-quantum co-signature | hardened | `frost` | 11 |
| Hardware attestation verifiers: AMD SEV-SNP, Intel TDX (DCAP), Azure Attestation, Google Confidential Space, NVIDIA SPDM / RIM / OCSP, and PUF (hardened, awaiting independent audit and hardware evaluation on real hosts) | hardened | `attestation` | 15 |
| Zero-knowledge compliance: the attested-VM mode (trusted signer, not a proof; fail-closed table, replay, freshness and rotation tests done) and the Groth16 / Policy-VM SNARK modes (awaiting the setup ceremony and an independent review, O-2) | hardened | `zk-compliance` | 3 |
| Transparency ledger with durable store and checkpoint verification, liveness beacons and the global kill switch | hardened | `ledger` | 4 |
| Hybrid key encapsulation: X25519 with ML-KEM-768 or ML-KEM-1024 (custom HKDF combiner) and X-Wing, with the FIPS 203 key checks | hardened | `kem` | 2 |
| QRNG entropy: SP 800-90B health tests, fail-closed sources, requireQuantum (hardened, awaiting hardware evaluation on real quantum entropy devices) | hardened | `entropy` | 1 |
<!-- maturity:features:end -->

Notes on the hardened features and on the intent layer. The [trust model](./security/trust-model.md) has the details.

- **FROST and the DKG** are hardened, awaiting independent audit. FROST signing matches the RFC 9591 test vectors byte for byte and uses a fixed-width scalar path with a timing test. RFC 9591 defines no DKG, so the PedPoP DKG has no official test vectors; it runs over an authenticated channel interface and awaits the audit. The default threshold step-up does not use FROST. It is a multi-signature of independent shares, which is in the production tier.
- **Hardware attestation** verifiers for AMD SEV-SNP, Intel TDX, Azure Attestation, Google Confidential Space and NVIDIA GPUs are implemented and tested on real evidence, fuzzed, and checked by a real-evidence canary. They are hardened, awaiting independent audit and hardware evaluation on real hosts, and the vendor roots of trust are classical (not post-quantum). The software path (attestor-signed documents, signed allowlists with rollback state and transparency anchoring, strict certificate reading, the agent passport) is its own feature, `attestation-software`, in the production tier: it is covered by exact-outcome, differential and cross-language tests and labelled `software` in the assurance report, never hardware. The hardware verifiers are hardened, never production, until the audit and the hardware evaluation are done.
- **Zero-knowledge compliance** uses Groth16 on BN254 or BLS12-381: classical curves with a trusted setup. The **attested-VM** mode gives the same privacy with a weaker trust model: the resource server trusts the prover VM's key, or, when you configure `proverAttestation`, a key bound to hardware evidence of an allowlisted VM measurement. Either way it is a trusted signer, not a proof (its engineering is complete: fail-closed table, replay, freshness and rotation tests). The feature is hardened, awaiting the SNARK setup ceremony and an independent review.
- **The intent layer** is in two parts. Its binding and enforcement (the `intent` feature: intent statements and the envelope binding, action schemas, sessions, accumulators and monitors, world facts, offer sets, provenance, classifier dimensions, committed maps, revocation epochs and questions) is in the production tier (CI pending: the mutation gate over all 24 modules must pass once) and covered by the security contract (C-15 to C-19) and threat model (T-053 to T-057). What it proves is binding and bounds: that a request is bound to a signed statement of intent and stays inside committed limits, using inputs signed by keys the verifier pinned. It does not prove that a classifier, an oracle or a label issuer was right: their outputs are signed assertions by their issuers. Its optional anchoring in a transparency log and its hardware-attested classifier gate use the `ledger` and `attestation` features and carry their tiers. The frontier modules (the semantic judge threshold, the objective risk functional and proof of progress, the `intent-frontier` feature) are in the production tier as proxies, not judgements: their results are typed as `ok`, `escalate` or `deny` signals that can only tighten a decision, and the objective risk inputs are folded with the server-held baseline so they can only raise risk. See [Intent layer](./concepts/intent-layer.md).
- **Multi-party computation, homomorphic evaluation, attribute-based encryption and the VDF timelock** ship as separate packages (`@atlasauth/pca-mpc` with its two wasm cores, `@atlasauth/pca-fhe`, `@atlasauth/pca-abe`, `@atlasauth/pca-vdf`). They are labelled hardened, awaiting independent audit: tests, differential checks against independent implementations and the mutation gate are in place, but no independent review has happened, so they are never production. `@atlasauth/pca-mpc` has no formal proof and its default offline phase is a trusted dealer; `@atlasauth/pca-abe` implements FAME, a published ciphertext-policy scheme for type-3 pairings, and awaits an independent review of the adaptation.

## Hardened, awaiting an outside action

These units are finished and evidenced, and none of them is on the production path: you opt in by importing them explicitly (`@atlasauth/pca/ext/*` or their own package). The main-path packages do not need them, with the exceptions listed under the table.

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

Opt-in edges: `@atlasauth/pca` lists `@atlasauth/pca-fndsa-wasm` as a dependency and `@atlasauth/pca-less-wasm` as an optional one for the FN-DSA and LESS signature suites, which are used only when you select those suites; `@atlasauth/pca-agent` imports the ledger's inclusion-proof check to verify a transparency receipt when a receipt is presented; `@atlasauth/pca-grants` accepts hardware attestation verifiers (type-only) for blueprint runtime pins. The product layer's agent mesh uses the ledger's Merkle log and consistency proof (not its witness path). None of them runs unless you use that feature.

## What changed in 0.5

The root `@atlasauth/pca` entry point used to export every feature, experimental ones included, and the Core entry point `@atlasauth/pca/core` loaded some experimental modules at run time because the core action verifier called into them. Both changed in 0.5:

1. **The optional features are extension entry points**, one per feature in the table above: `@atlasauth/pca/ext/frost`, `/ext/attestation`, `/ext/zk`, `/ext/optimistic`, `/ext/intent`, `/ext/ledger` and `/ext/research`. An import of an experimental feature now says so. The root entry exports Core, the post-quantum suites, the server path and threshold multisig; durable state stays its own subpath. [Upgrading to 0.5](./migration.md#41-experimental-features-moved-to-atlasauthpcaext) shows the import changes. A Rust feature flag, `experimental`, will do the same for the Rust modules that are not yet hardened.
2. **PCA Core loads no experimental module.** The intent layer is a parameter of the core action verifier (`extensions`), not an import; the root entry passes it, Core does not.
3. **The release checks enforce it.** They fail if PCA Core starts loading any experimental module. The allowed list is empty.
