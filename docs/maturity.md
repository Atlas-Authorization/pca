---
title: Maturity tiers
order: 2
---

# Maturity tiers

PCA is published as about ninety packages on npm, PyPI and crates.io, and they are not equally mature. Every published package declares one of four tiers, and so does every feature inside `@atlasauth/pca`. This page defines the tiers, lists every package and feature with its tier, and explains the classifications that are not obvious.

Two things hold for every tier. PCA is pre-1.0. Its cryptography and protocol have not been independently audited. The tiers describe how much the project itself stands behind a package. They are not a substitute for your own security review.

## The tiers

| Tier | What it covers | What you can rely on | Evidence behind it |
|---|---|---|---|
| **Stable** (stable core) | The wire format and the proof check ([PCA Core](./core.md)): canonical encoding, capability chains, plan inclusion, Ed25519 and the post-quantum and hybrid signature suites, the nine core checks. Also the conformance corpus, the JSON Schemas, and the core verifiers published on PyPI and crates.io. | The wire format changes only through a new version identifier. Changes to what a check accepts are listed in the changelog with a migration note. Every language reproduces the shared corpus. The [security contract](./security/security-contract.md) invariants C-1 (no invalid proof authorizes) and C-2 (nothing outside the capability chain authorizes) hold on every surface. | The shared conformance corpus and adversarial vector set, run by every language with zero disagreements allowed. Formal models of the verifier and the protocol. Mutation testing in which every surviving mutant must be a reviewed equivalent. |
| **Production** (production enforcement) | What you deploy to authorize real actions: `requirePCA` and the full verifier (Policy VM, caveats, risk, budgets, replay and revocation state, approvals), the HTTP adapters built on it, `authorizeToolCall` for MCP tool calls, the agent-side wrappers that sign tool calls, and the tools you need to build and test a deployment. | Supported for production use. Breaking changes to APIs or defaults are never made in a patch release, and they are listed in the changelog with a migration note. On this surface the security contract holds except where its "Full TS" column says otherwise. | Package tests on every change. The authorization decision is made by `@atlasauth/pca`, which carries the stable-tier evidence and is mutation tested. |
| **Hardened** (experimental: hardened, awaiting audit) | Cryptography whose engineering is finished and evidenced but which has not had the independent review, trusted-setup ceremony or hardware programme that its claims need: the threshold-signing and distributed-key-generation code is the first to be labelled this way. It is a stronger label than Experimental and is never shown as Production. | What its README's Status section says it has: for example secret scalar arithmetic on a fixed-width path with a timing test, test vectors cross-checked against an independent implementation, durable nonce handling, fuzzed parsers and known-answer tests. The API may still change. Do not rely on it as the only control over anything of value until the review it awaits has been done. | The evidence list in the [audit package](./validation/audit-package.md), including the cross-implementation vectors and the timing report. |
| **Experimental** | Everything else: research-grade cryptography, bridges to draft standards, proof-only guards, prototypes. | Only what its own README states. Its API may change, or the package may be removed, in any release. Do not make it the only control protecting anything of value. | Package tests on every change. Some packages are also mutation tested. Each README's Status section says what is validated and what is not. |

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
| `@atlasauth/pca-ai-sdk` | production |
| `@atlasauth/pca-anthropic` | production |
| `@atlasauth/pca-cli` | production |
| `@atlasauth/pca-express` | production |
| `@atlasauth/pca-fastify` | production |
| `@atlasauth/pca-fetch` | production |
| `@atlasauth/pca-hono` | production |
| `@atlasauth/pca-langchain` | production |
| `@atlasauth/pca-llamaindex` | production |
| `@atlasauth/pca-mcp` | production |
| `@atlasauth/pca-mcp-rs` | production |
| `@atlasauth/pca-next` | production |
| `@atlasauth/pca-openai` | production |
| `@atlasauth/pca-store-conformance` | production |
| `@atlasauth/pca-testing` | production |
| `create-pca-app` | production |
| `@atlasauth/pca-abe` | hardened |
| `@atlasauth/pca-control-evals` | hardened |
| `@atlasauth/pca-fhe` | hardened |
| `@atlasauth/pca-harness` | hardened |
| `@atlasauth/pca-less-wasm` | hardened |
| `@atlasauth/pca-mpc` | hardened |
| `@atlasauth/pca-mpc-lwe-ot-wasm` | hardened |
| `@atlasauth/pca-mpc-wasm` | hardened |
| `@atlasauth/pca-vdf` | hardened |
| `@atlasauth/pca-a2a` | experimental |
| `@atlasauth/pca-acp` | experimental |
| `@atlasauth/pca-agent` | experimental |
| `@atlasauth/pca-agentcard` | experimental |
| `@atlasauth/pca-aggsig` | experimental |
| `@atlasauth/pca-analyzer` | experimental |
| `@atlasauth/pca-ap2` | experimental |
| `@atlasauth/pca-attest-eat` | experimental |
| `@atlasauth/pca-authzen` | experimental |
| `@atlasauth/pca-bbs` | experimental |
| `@atlasauth/pca-ciba` | experimental |
| `@atlasauth/pca-compliance` | experimental |
| `@atlasauth/pca-connect` | experimental |
| `@atlasauth/pca-connectors` | experimental |
| `@atlasauth/pca-dataflow` | experimental |
| `@atlasauth/pca-doctor` | experimental |
| `@atlasauth/pca-dpop` | experimental |
| `@atlasauth/pca-events` | experimental |
| `@atlasauth/pca-explain` | experimental |
| `@atlasauth/pca-fndsa` | experimental |
| `@atlasauth/pca-fndsa-wasm` | experimental |
| `@atlasauth/pca-gateway` | experimental |
| `@atlasauth/pca-gnap` | experimental |
| `@atlasauth/pca-idjag` | experimental |
| `@atlasauth/pca-invariants` | experimental |
| `@atlasauth/pca-mastra` | experimental |
| `@atlasauth/pca-notary` | experimental |
| `@atlasauth/pca-oauth` | experimental |
| `@atlasauth/pca-oidc` | experimental |
| `@atlasauth/pca-openai-agents` | experimental |
| `@atlasauth/pca-oprf` | experimental |
| `@atlasauth/pca-otel` | experimental |
| `@atlasauth/pca-payments` | experimental |
| `@atlasauth/pca-policy-bridge` | experimental |
| `@atlasauth/pca-policy-ci` | experimental |
| `@atlasauth/pca-pq-threshold` | experimental |
| `@atlasauth/pca-rag` | experimental |
| `@atlasauth/pca-ratchet` | experimental |
| `@atlasauth/pca-revoke` | experimental |
| `@atlasauth/pca-rotate` | experimental |
| `@atlasauth/pca-scim` | experimental |
| `@atlasauth/pca-scitt` | experimental |
| `@atlasauth/pca-sdjwt` | experimental |
| `@atlasauth/pca-siem` | experimental |
| `@atlasauth/pca-signals` | experimental |
| `@atlasauth/pca-spiffe` | experimental |
| `@atlasauth/pca-txn-tokens` | experimental |
| `@atlasauth/pca-vc` | experimental |
| `@atlasauth/pca-vercel-ai` | experimental |
| `@atlasauth/pca-webauthn` | experimental |
| `@atlasauth/pca-webbotauth` | experimental |
<!-- maturity:npm:end -->

### PyPI

<!-- maturity:pypi:start -->
| Package | Tier |
|---|---|
| `atlas-pca` | stable |
| `atlas-pca-agent-framework` | experimental |
| `atlas-pca-crewai` | experimental |
| `atlas-pca-fastmcp` | experimental |
| `atlas-pca-google-adk` | experimental |
| `atlas-pca-haystack` | experimental |
| `atlas-pca-langgraph` | experimental |
| `atlas-pca-pydantic-ai` | experimental |
<!-- maturity:pypi:end -->

### crates.io

<!-- maturity:crates:start -->
| Package | Tier |
|---|---|
| `atlas-pca` | stable |
| `pca-folding-ivc` | hardened |
| `stark-pca` | experimental |
<!-- maturity:crates:end -->

`zkvm-pca` (the RISC Zero proof of the release gate) is not published: its guest build patches crates.io dependencies with git forks.

### Why these classifications

- **The core verifiers are stable, and their HTTP middleware only checks the proof.** `atlas-pca` on PyPI and `atlas-pca` on crates.io are stable as core verifiers: they reproduce the shared corpus. Their middleware (`require_pca`, the FastAPI and Django helpers, the axum layer) runs the core check only. It evaluates no caveats and checks no replay or revocation (see the "Native" column of the security contract). Use them as the proof check and add those checks yourself.
- **Proof-only guards are experimental.** `@atlasauth/pca-gateway`, the execution guards `@atlasauth/pca-mastra`, `@atlasauth/pca-vercel-ai` and `@atlasauth/pca-openai-agents`, and the seven Python framework adapters verify the proof but, by default, do not evaluate caveats, consume the replay counter or check revocation. They can be considered for the production tier once the full verifier is their default.
- **The HTTP adapters are production.** `@atlasauth/pca-express`, `-fastify`, `-hono`, `-next` and `-fetch` are thin wiring over `requirePCA`, which makes every decision. In `@atlasauth/pca-mcp-rs` the production entry point is `authorizeToolCall`. Its `authorizeRequest` only checks admission.
- **Agent-side wrappers are production.** `@atlasauth/pca-mcp`, `-langchain`, `-llamaindex`, `-openai`, `-anthropic` and `-ai-sdk` sign tool calls and do not authorize them. The resource server's verifier decides.
- **The tools are production.** `@atlasauth/pca-cli`, `@atlasauth/pca-testing`, `@atlasauth/pca-store-conformance` and `create-pca-app` are supported. The test kit's helpers are for tests only, as its README says.
- **The proof-system crates are unaudited.** `stark-pca` is experimental and `pca-folding-ivc` is hardened (a standard Nova and Poseidon construction, cross-checked against an independent Poseidon reference and fuzzed, awaiting an independent review). The Winterfell STARK is not zero-knowledge: its trace is not blinded, so it gives soundness and succinctness but not witness privacy.

## Features inside `@atlasauth/pca`

`@atlasauth/pca` is a stable package that also carries production and experimental features. Its manifest lists each feature's tier under `pca.features`:

<!-- maturity:features:start -->
| Feature | Tier | Key | Modules |
|---|---|---|---|
| Proof format and core verification (@atlasauth/pca/core) | stable | `core` | 14 |
| Post-quantum and hybrid signature suites: ML-DSA and SLH-DSA (FIPS 204, FIPS 205) and their Ed25519 hybrids (the FN-DSA and LESS backends are separate, experimental packages) | stable | `pq-signatures` | 1 |
| Full verifier and requirePCA: Policy VM, predicates, caveats, risk, budgets, replay, revocation, approvals, discovery | production | `server` | 31 |
| Durable replay and budget state (@atlasauth/pca/durable-state) | production | `durable-state` | 1 |
| Default threshold step-up: independent Ed25519 / ML-DSA / hybrid shares bound to the signer set | production | `threshold-multisig` | 1 |
| FROST threshold signing (RFC 9591), the PedPoP DKG, networked FROST and FROST with a post-quantum co-signature | hardened | `frost` | 9 |
| Optimistic execution: claims, challenge window, fraud proofs, bond settlement and its durable store (internal accounting only) | hardened | `optimistic` | 4 |
| Intent layer, binding and enforcement: signed intent statements and the envelope intent binding, action schemas, session roots and delta grants, accumulators and monitors, world facts and offer sets, parameter provenance and label receipts, classifier dimensions, committed maps, revocation epochs and intent questions | hardened | `intent` | 23 |
| Transparency ledger with durable store and checkpoint verification, liveness beacons and the global kill switch | hardened | `ledger` | 4 |
| Hardware and software attestation: AMD SEV-SNP, Intel TDX (DCAP), Azure Attestation, Google Confidential Space, NVIDIA SPDM / RIM / OCSP, PUF, software attestation, allowlists | experimental | `attestation` | 23 |
| Zero-knowledge compliance proofs (Groth16 on BN254 / BLS12-381, Policy-VM SNARK) and the attested-VM compliance mode | experimental | `zk-compliance` | 3 |
| Intent layer frontier: semantic judge threshold, objective risk functional and its grant binding, proof of progress | experimental | `intent-frontier` | 4 |
| Research and product-layer modules: agent mesh, multi-agent sessions, behavioural immune system, reputation, safety certificates, natural-language policy, DLP, QRNG entropy, hybrid KEM, guardian HA, console, budget forecast, policy simulation and debugging, contracts, connector catalog | experimental | `research` | 20 |
<!-- maturity:features:end -->

Notes on the experimental features. The [trust model](./security/trust-model.md) has the details.

- **FROST and the DKG** are reference implementations. FROST signing matches the RFC 9591 test vectors byte for byte, but it is not hardened against side channels. RFC 9591 defines no DKG, so the PedPoP DKG has no official test vectors and needs an audit. The default threshold step-up does not use FROST. It is a multi-signature of independent shares, which is in the production tier.
- **Hardware attestation** verifiers for AMD SEV-SNP, Intel TDX, Azure Attestation, Google Confidential Space and NVIDIA GPUs are implemented and tested on real evidence, fuzzed, and checked by a real-evidence canary. They are unaudited, and the vendor roots of trust are classical (not post-quantum). The software path (attestor-signed documents, signed allowlists with rollback state and transparency anchoring, strict certificate reading) is hardened and covered by exact-outcome, differential and cross-language tests, but the feature stays experimental until the mutation gate and an independent review are done.
- **Zero-knowledge compliance** uses Groth16 on BN254 or BLS12-381: classical curves with a trusted setup. The **attested-VM** mode gives the same privacy with a weaker trust model: the resource server trusts the prover VM's key, or, when you configure `proverAttestation`, a key bound to hardware evidence of an allowlisted VM measurement. Either way it is a trusted signer, not a proof.
- **The intent layer** is in two parts. Its binding and enforcement (the `intent` feature: intent statements and the envelope binding, action schemas, sessions, accumulators and monitors, world facts, offer sets, provenance, classifier dimensions, committed maps, revocation epochs and questions) is in the hardened tier (not production: the mutation gate over all 24 modules has not yet passed clean) and covered by the security contract (C-15 to C-19) and threat model (T-053 to T-057). What it proves is binding and bounds: that a request is bound to a signed statement of intent and stays inside committed limits, using inputs signed by keys the verifier pinned. It does not prove that a classifier, an oracle or a label issuer was right: their outputs are signed assertions by their issuers. Its optional anchoring in a transparency log and its hardware-attested classifier gate use the `ledger` and `attestation` features and carry their tiers. The frontier modules (the semantic judge threshold, the objective risk functional and proof of progress, the `intent-frontier` feature) stay experimental. See [Intent layer](./concepts/intent-layer.md).
- **Multi-party computation, homomorphic evaluation, attribute-based encryption and the VDF timelock** ship as separate packages (`@atlasauth/pca-mpc` with its two wasm cores, `@atlasauth/pca-fhe`, `@atlasauth/pca-abe`, `@atlasauth/pca-vdf`). They are labelled hardened, awaiting audit: tests, differential checks against independent implementations and the mutation gate are in place, but no independent review has happened, so they are never production. `@atlasauth/pca-mpc` has no formal proof and its default offline phase is a trusted dealer; `@atlasauth/pca-abe` is a type-3 adaptation of BSW07 with no published proof.

## What changed in 0.5

The root `@atlasauth/pca` entry point used to export every feature, experimental ones included, and the Core entry point `@atlasauth/pca/core` loaded some experimental modules at run time because the core action verifier called into them. Both changed in 0.5:

1. **The experimental features are extension entry points**, one per feature in the table above: `@atlasauth/pca/ext/frost`, `/ext/attestation`, `/ext/zk`, `/ext/optimistic`, `/ext/intent`, `/ext/ledger` and `/ext/research`. An import of an experimental feature now says so. The root entry exports Core, the post-quantum suites, the server path and threshold multisig; durable state stays its own subpath. [Upgrading to 0.5](./migration.md#7-experimental-features-moved-to-atlasauthpcaext) shows the import changes. A Rust feature flag, `experimental`, will do the same for preview modules.
2. **PCA Core loads no experimental module.** The intent layer is a parameter of the core action verifier (`extensions`), not an import; the root entry passes it, Core does not.
3. **The release checks enforce it.** They fail if PCA Core starts loading any experimental module. The allowed list is empty.
