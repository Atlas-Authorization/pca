---
title: What runs in which language
order: 6
---

# What runs in which language

PCA has two halves. The **agent side** mints a grant, delegates, and signs one proof per action. The **server side**
verifies a proof and decides. Since 0.5.0 both halves run natively in all ten languages: an agent written in Python, Go,
Rust, Ruby, PHP, Java, Kotlin, .NET or Swift signs its own proofs and needs no TypeScript process. This page says what
each language ships and the few places where they differ.

| Half | TypeScript | Python, Go, Rust, Ruby, PHP, Java, Kotlin, .NET, Swift |
|---|---|---|
| Server side: verify, authorize, replay, revocation, framework guard | yes | yes, the same checks, the same refusal names |
| Agent side: mint a grant, delegate, `act`, sub-agents, the one-call agent facade, the other principal and agent signers | yes (`agent()`) | yes, with the exceptions listed under [What stays TypeScript only](#what-stays-typescript-only) |
| Authoring and analysis: policy analyzer, residual policies, minimal flips, coverage, least privilege, action CLI, goal compiler | yes | TypeScript only, by design: these are build-time and review-time tools |
| Operational services: grant management, policy bundles and decision records, list-objects, AuthZEN and SSF endpoints | yes | TypeScript and the hosted service |

What a native agent signs is checked two ways: its Ed25519 and post-quantum outputs are compared byte for byte with the
shared producer vectors (except where a platform signer is randomised, see below), and the PCActns and artifacts it
produces are verified by the TypeScript reference.

## The agent side by language

The one-call facade does what TypeScript's `agent()` does: it compiles human-level permissions and limits (`"$500/day"`,
`"10/hour"`) against the built-in 21-action connector catalog into a signed root grant, pins the agent's provenance
recorder in that grant, and returns a handle. `act` builds one proof-carrying action per tool call and returns the PCActn,
its encoding, the headers to send (`PCA-Action`, and `PCA-Provenance` when the bundle fits), an advisory local dry run and
the provenance bundle. `subAgent` adds a narrower hop for a new holder (generated when you pass none). `compilePolicy` and
`parseLimit` are the pure compiler underneath, with the same output and the same error texts as TypeScript.

| Language | Facade | On the handle | Low-level agent | Mint a grant |
|---|---|---|---|---|
| TypeScript | `agent(opts)` | `act`, `dryRun`, `subAgent`, `encodeGrant` | `buildPCActn`, `delegate` | `mintGrant` |
| Go | `pca.CreateAgent(pca.AgentOptions{...})` | `Act`, `DryRun`, `SubAgent`, `EncodeGrant` | `pca.NewAgent`, `Act`, `Delegate`, `DelegatePq` | `pca.MintGrant` |
| Python | `atlas_pca.create_agent(...)` | `act`, `dry_run`, `sub_agent`, `encode_grant` | `Agent(...)`, `act`, `delegate` | `mint_grant` |
| Rust | `facade::create_agent(AgentOptions::new(...))` | `act`, `dry_run`, `sub_agent`, `encode_grant` | `agent::Agent::new`, `act`, `delegate`, `delegate_pq` | `agent::mint_grant` |
| Java | `Agent.fromPrincipal(new Facade.AgentOptions(...))` | `act`, `dryRun`, `subAgent`, `encodeGrant` | `Agent.create`, `act`, `delegate` | `Issue.mintGrant` |
| Kotlin | `Agent.fromPrincipal(Facade.AgentOptions(...))` | `act`, `dryRun`, `subAgent`, `encodeGrant` | `Agent(...)`, `act`, `delegate` | `Issue.mintGrant` |
| .NET | `Agent.FromPrincipal(new AgentOptions { ... })` | `Act`, `DryRun`, `SubAgent`, `EncodeGrant` | `new Agent(...)`, `Act`, `Delegate` | `Issue.MintGrant` |
| PHP | `Facade::createAgent(...)` or `Agent::fromPrincipal(...)` | `act`, `dryRun`, `subAgent`, `encodeGrant` | `new Agent(...)`, `act`, `delegate` | `Sign::mintGrant` |
| Ruby | `AtlasPca.create_agent(...)` | `act`, `dry_run`, `sub_agent`, `encode_grant` | `AtlasPca::Agent.new`, `act`, `delegate` | `AtlasPca.mint_grant` |
| Swift | `PCAAgent.fromPrincipal(PCAAgentOptions(...))` | `act`, `dryRun`, `subAgent`, `encodeGrant` | `PCAAgent(signer:aud:grant:)`, `act`, `delegate` | `PCAIssue.mintGrant` |

`compilePolicy` and `parseLimit` follow the same casing: `pca.CompilePolicy` / `pca.ParseLimit`,
`compile_policy` / `parse_limit` (Python, Rust, Ruby), `Facade.compilePolicy` / `Facade.parseLimit` (Java, Kotlin, PHP),
`Facade.CompilePolicy` / `Facade.ParseLimit` (.NET), `PCAFacade.compilePolicy` / `PCAFacade.parseLimit` (Swift).

**Sub-agents and post-quantum keys.** A sub-agent always gets its own key. Under a post-quantum or hybrid suite it also
gets its own post-quantum key (generated, or the one you pass), committed in the new hop as its `holder_pq`; it never
signs with its parent's post-quantum key. In Go, Java, Kotlin, .NET and Swift the facade itself takes a post-quantum
holder and its `subAgent` does this. In Python, Rust, PHP and Ruby the facade is Ed25519, as TypeScript's `agent()` is;
a post-quantum agent there uses the low-level agent (`Agent(..., alg=, pq=)` and `delegate(..., to_pq=)` in Python,
`Agent::delegate_pq` in Rust, `new Agent(..., alg:, pq:)` and `delegate($to, $caveats, $toPq)` in PHP,
`AtlasPca::Agent.new(..., alg:, pq:)` and `delegate(to, caveats, to_pq:)` in Ruby).

**Deterministic keys.** Every language derives keys from a seed, the same key TypeScript derives from the same seed:

| Language | Ed25519 from a seed | Post-quantum from a seed |
|---|---|---|
| Go | `KeyPairFromSeed` | `GeneratePqKeyPairFromSeed(family, seed)` |
| Python | `keypair_from_seed` | `generate_pq_keypair(family, seed=...)` |
| Rust | `KeyPair::from_seed` | `PqKeyPair::from_seed(family, seed)` |
| Java, Kotlin | `Keys.edFromSeed` | `Keys.pqFromSeed(prim, seed)` |
| .NET | `EdKey.FromSeed` | `PqKey.FromSeed(prim, seed)` |
| PHP | `new KeyPair($seed)` | `new PqKeyPair($family, $seed)` |
| Ruby | `KeyPair.new(seed)` | `PqKeyPair.from_seed(prim, seed)` |
| Swift | `PCAEdKey(seed:)` | `PCAPQKey.fromSeed(level, seed:)` (ML-DSA) |

Seeds are 32 bytes for Ed25519 and ML-DSA, 48 bytes for SLH-DSA-SHA2-128f and 96 bytes for SLH-DSA-SHA2-256s. A seed of
the wrong length is refused.

## Post-quantum signing

Every language signs the suites it verifies, with one exception (LESS):

| Suite family | Signs | Refused with `unsupported_suite: <alg>` |
|---|---|---|
| ML-DSA-65 / 87, their hybrids and the nested hybrid | every language | none |
| SLH-DSA-SHA2-128f / 256s and their hybrids | every language except Swift | Swift |
| FN-DSA-512 / 1024 | TypeScript, Rust (cargo feature `fndsa-sign`) | the other languages, and Rust built without the feature |
| LESS | TypeScript only | every native language |

Signatures are deterministic (FIPS 204 and FIPS 205 deterministic variants, FN-DSA with a seeded signer), so the same key
and message give the reference's bytes in Go, Python, Rust, Java, Kotlin, .NET, PHP and Ruby. Swift signs through CryptoKit,
which randomises both Ed25519 and ML-DSA signatures: they are valid signatures that every verifier accepts, but not
byte-equal to the vectors (its keys from a seed are). Where the post-quantum library comes from:

| Language | Library |
|---|---|
| Go | circl |
| Python | OpenSSL 3.5 or later when present; for ML-DSA only, `dilithium-py` (`atlas-pca[pq]`) otherwise |
| Rust | `fips204`, `fips205`, and `fn-dsa` behind `fndsa-sign` |
| Java, Kotlin, .NET | Bouncy Castle |
| PHP | OpenSSL 3.5 or later through FFI |
| Ruby | OpenSSL 3.5 or later |
| Swift | CryptoKit on OS 26 and later (liboqs on Linux); ML-DSA only |

## Other signers

Beyond grants and actions, each language signs the principal-, agent- and site-side artifacts it verifies, with the same
pre- and post-signing checks and the same suites per artifact as TypeScript: escalation answers, discharges, narrows, passports, workflows and step receipts, read and aggregate
grants, read receipts, `fresh_at`, revocation epochs, threshold and prepared shares, the post-quantum key binding,
caution, lease heartbeats, progress steps, mesh actions and mesh proofs, intent session roots and session grants, action
schemas, intent-required documents, labels, oracle facts, offer sets, policy templates and tighten overlays, constitutions
and safety evidence.

| Language | Where the extra signers live |
|---|---|
| Go | package functions (`pca.SignCaution`, `pca.SignMeshAction`, ...) |
| Python | `atlas_pca.signers_more` |
| Rust | `atlas_pca::signers_more` |
| Java, Kotlin | `SignersMore` |
| .NET | `Signers` (templates and overlays in `PolicyAuthoring`, epochs in `RevocationFreshness.SignEpoch`) |
| PHP | `SignersMore` |
| Ruby | `AtlasPca.sign_*` |
| Swift | `PCASigners` |

## What stays TypeScript only

- LESS signing (every language verifies LESS).
- FN-DSA signing outside Rust.
- FROST and post-quantum quorum co-signing (hybrid FROST co-signs, quorum and rotation shares).
- The service-side signers: transparency-ledger tree heads, budget releases, detector receipts, judge verdicts and the
  other artifacts a PCA service signs rather than a principal or an agent.

## Available in all ten languages

Verified by the shared conformance corpus, each replaying the same vectors:

- The structural verifier and the full `authorize` pipeline: operation binding, predicates, root and delegated caveats,
  revocation, replay counter under an atomic store.
- The agent side: grant minting, delegation, action signing, the facade, and the producer vectors above.
- The web-framework guard for that language (see [Add PCA to your framework](../guides/framework-recipes.md)).
- Run-once execution with operation records, and the plan lifecycle.
- Ternary decisions (allow, deny, escalate) and signed escalation answers, with the approval render check.
- Action definitions (loading, trait expansion, the registry) and the `pca_grant` authorization-details type.
- Consistency tokens (`fresh_at`), revocation staleness, leases and break-glass grants, agent blueprints and group kill.
- The caveat language: discharges, `max_uses`, sealing, derived facts.
- Obligations, typed missing context, policy classes, rollout modes, and policy template linking.
- Workflow (DAG) admission, read-side redaction and the read vault.
- Provenance gates, passports, mesh witness checks, ledger verification and optimistic claims.
- Hardware attestation verifiers and post-quantum signature suites.
- Network agent tokens, ERC-7715 wallet permissions, and spend-control math.
- A state-store conformance kit: run it against your own replay or operation store.

## Where the languages differ

| Capability | Where |
|---|---|
| Post-quantum signing suites | every language signs the suites it verifies: ML-DSA everywhere, SLH-DSA everywhere but Swift, FN-DSA in TypeScript and Rust; LESS signing is TypeScript only |
| Facade with a post-quantum holder | TypeScript, Python, Rust, PHP and Ruby facades are Ed25519 (use the low-level agent for a post-quantum agent); Go, Java, Kotlin, .NET and Swift facades take a post-quantum holder |
| Framework guards | Express, Fastify, Hono, Next (TypeScript); FastAPI, Django (Python); net/http and Gin via a small adapter (Go); axum and tower (Rust); Rack and Rails (Ruby); PSR-15 (PHP, Laravel through a bridge); servlets and Spring (Java); Ktor and Spring (Kotlin); ASP.NET Core (.NET); Vapor and Hummingbird (Swift) |

## Same names everywhere

The server-side inputs are named the same in every language, modulo that language's casing: `audience`,
`resolve_grant` / `resolveGrant`, `state_store` / `stateStore`, `is_revoked` / `isRevoked`, `operation`, `plan`
(default `single-step`). The refusal names are identical, so [Refusal reasons](./refusals.md) applies to all of them.
On the agent side the facade options are `principal`, `goal`, `permissions`, `limits`, `holder`, `aud`, `now`,
`goal_salt` / `goalSalt`, `catalog`, `risk_policy` / `riskPolicy`, `budget_model` / `budgetModel` and `provenance`, and
`act` takes `counter`, `aud`, `now`, `ttl_ms` / `ttlMs`, `nonce`, `caution` and `risk`. The facade sets no nonce unless you
pass one; the low-level agent draws a random base64url nonce per action.

Every language has a one-call `protect` helper with secure defaults (grant lookup from your list or function, in-memory replay store, revocation source, single-step plan; TypeScript also prices risk from the connector catalog) and an `explain_refusal` helper (`Refusals.Explain`, `ExplainRefusal`, `explainRefusal`, by language). HTTP refusal bodies carry an extra `doc` member pointing at the [refusal reasons](./refusals.md) page; the reason strings themselves are unchanged. Each native package ships a runnable server project for its main framework (FastAPI, Gin, axum, Rack/Rails, Laravel, Spring Boot, Ktor, ASP.NET minimal API, Vapor).
