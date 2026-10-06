# Proof-Carrying Authority (PCA)

**An execution-authentication framework for autonomous agents.**

> **Status: Preview.** PCA is in development. The hosted `/v1/pca/*` endpoints are gated and off by default. The libraries, reference verifiers and conformance suite can be used today. See the [trust model](docs/security/trust-model.md) for what is and is not production-hardened.

Live documentation: **<https://atlasauth.net/pca>** · Claude plugin: [Atlas-Authorization/atlas-claude-skills](https://github.com/Atlas-Authorization/atlas-claude-skills)

## The thesis: authN, authZ, authF

- **authN**: who are you?
- **authZ**: what may you do?
- **authF**: is *this specific action* a faithful, uncompromised execution of an authority the principal actually conferred?

<p align="center"><img src="docs/diagrams/authn-authz-authf.svg" alt="authN asks who you are, authZ asks what you may do, authF asks whether this action is a faithful execution; PCA adds the third and composes on top of the first two" width="900"></p>

For a human, authN and authZ are enough, because the human is the policy engine. An autonomous agent is a stochastic, externally steerable process: what it will do is unknown when authority is granted and can be manipulated while it runs. Knowing which agent is calling and which scopes it holds says nothing about whether the action is what was authorized.

PCA makes authF cheaply verifiable by replacing the bearer token with a **proof-carrying action (PCActn)**. The resource server does not check that the caller holds a secret; it verifies a proof that the action is a node of a pre-committed plan, inside a signed policy, reached through an intact attenuating capability chain, co-signed by as many parties as its risk demands, and affordable within a decaying trust budget. Verification is offline and deterministic.

## The PCA loop

<p align="center"><img src="docs/diagrams/pca-loop.svg" alt="Sequence of the PCA loop: mint, attenuate, commit plan, build PCActn, decide, release share, verify, anchor, with the step-up and out-of-plan reject branches" width="760"></p>

1. **Mint a Root Intent Grant.** The principal signs an envelope (goal commitment, action predicates, caveats, risk policy, agent binding).
2. **Attenuate or delegate.** The agent (or a sub-agent) receives a capability that can only be narrowed.
3. **Commit a plan.** The agent commits the Merkle root of a DAG of intended actions.
4. **Act.** Each action is a signed PCActn carrying an inclusion proof for its plan node, the capability chain, a monotonic counter and a risk claim.
5. **Decide.** The Policy VM evaluates predicates, caveats, the risk functional and the trust budget, then releases the guardian signing share or refuses.
6. **Verify.** The resource server checks every clause, offline.
7. **Outcome.** `allowed` (anchored in a transparency ledger, receipt returned), `denied`, or `step_up` (a principal-device co-signature is needed).
8. **Audit and revoke.** Per-action ledger inclusion proofs; capabilities can be revoked and an instance frozen.

## Architecture

No bearer token travels anywhere: possessing a PCActn replays one action at most once, and a compromised agent holds a single threshold share — short of anything above `t = 1`.

<p align="center"><img src="docs/diagrams/architecture.svg" alt="PCA roles: principal, attested agent and sub-agents, guardian with Policy VM and trust budget, resource-server verifier with its hooks, transparency ledger and attestation" width="960"></p>

### The stack

Each layer is one clause of the proof; a resource server verifies all of them, offline, per action. Adoption degrades gracefully — rung 0 is OAuth with proof of possession, and every layer above is independently adoptable.

<p align="center"><img src="docs/diagrams/pca-stack.svg" alt="The PCA stack from L0 attestation-derived identity up to L5 ledger, revocation and beacons, with optimistic and zero-knowledge accelerants alongside" width="960"></p>

### Authorization as a control system

Friction scales with risk and with how long the agent has gone without a human. The trust budget is a battery with no self-charge: idle authority leaks, each admitted action debits `κ·r`, and only a human step-up recharges it. This bounds the total risk of auto-admitted actions between two human touches — `Σ rᵢ ≤ bMax / κ` — whatever a compromised agent does.

<p align="center"><img src="docs/diagrams/trust-budget.svg" alt="Authorization as a control system: setpoint, risk sensor, controller, threshold actuator and plant around a depleting trust-budget battery, with the Sigma r bound" width="960"></p>

### Threshold and step-up

Risk sets how many distinct roles must sign: `t = 1` the agent alone (zero friction), `t = 2` the guardian auto-cosigns a compliant action, `t = 3` a human co-signs on their device. Shares aggregate as plain multi-signature by default, or as a single FROST threshold signature.

<p align="center"><img src="docs/diagrams/threshold-stepup.svg" alt="Threshold escalation across t=1, t=2 and t=3 showing which of agent, guardian and principal sign, the hosted step-up flow, and multi-signature versus FROST aggregation" width="960"></p>

All six diagrams, with GitHub-native Mermaid versions, are in [`docs/diagrams/`](docs/diagrams).

## Feature overview

- Root Intent Grants and attenuating capability chains
- Plan commitment (Merkle DAG) with per-action inclusion proofs
- Policy VM and a risk functional with a decaying trust budget
- Threshold and step-up co-signing (multi-signature, FROST threshold signatures, trustless DKG)
- Transparency ledger, revocation proofs and dead-man beacons
- Attestation, an optimistic fast-path with fraud proofs, and a zero-knowledge compliance seam
- A language-neutral wire format with a normative conformance suite and eight reference verifiers

## Install by language

The JavaScript/TypeScript packages ship on npm. Each other language has its own standalone, idiomatically-installable verifier repository; all of them vendor the same conformance vectors this repo is the canonical source of.

| Language | Package / repo | Install |
|---|---|---|
| JS / TS | [`@atlasauth/pca`](https://www.npmjs.com/package/@atlasauth/pca), [`@atlasauth/pca-agent`](https://www.npmjs.com/package/@atlasauth/pca-agent), [`@atlasauth/backend`](https://www.npmjs.com/package/@atlasauth/backend) | `npm install @atlasauth/pca @atlasauth/pca-agent @atlasauth/backend` |
| Go | [Atlas-Authorization/pca-go](https://github.com/Atlas-Authorization/pca-go) | `go get github.com/Atlas-Authorization/pca-go` |
| Python | [Atlas-Authorization/pca-python](https://github.com/Atlas-Authorization/pca-python) | clone / vendor (PyPI pending) |
| Rust | [Atlas-Authorization/pca-rust](https://github.com/Atlas-Authorization/pca-rust) | clone / vendor (crates.io pending) |
| Java | [Atlas-Authorization/pca-java](https://github.com/Atlas-Authorization/pca-java) | clone / vendor (Maven pending) |
| PHP | [Atlas-Authorization/pca-php](https://github.com/Atlas-Authorization/pca-php) | clone / vendor (Packagist pending) |
| Ruby | [Atlas-Authorization/pca-ruby](https://github.com/Atlas-Authorization/pca-ruby) | clone / vendor (RubyGems pending) |
| .NET | [Atlas-Authorization/pca-dotnet](https://github.com/Atlas-Authorization/pca-dotnet) | clone / vendor (NuGet pending) |

This repository is the **hub**: the spec, the normative conformance suite, the docs and a runnable reference copy of every verifier under [`verifiers/`](verifiers). The per-language repos above are the install targets.

## Repository contents

| Path | What it is |
|---|---|
| [`docs/`](docs/README.md) | Concepts, guides, reference, security and adoption docs (mirrors <https://atlasauth.net/pca>) |
| [`docs/diagrams/`](docs/diagrams) | The six framework diagrams, as SVG and Mermaid |
| [`conformance/`](conformance/README.md) | Golden vectors and fixed test keys: the normative rules every implementation must match |
| [`verifiers/`](verifiers) | Reference verifiers in Go, Python, Rust, Java, PHP, Ruby and .NET, each passing every vector |
| [`playground/`](playground) | Interactive in-browser demo of the loop |
| [`sdks.md`](sdks.md) | Developer map: JS packages, per-language repos, playground, conformance |
| [`llms.txt`](llms.txt) | AI-readable index of this repo and the live docs |

## Quick start

```
npm install @atlasauth/pca @atlasauth/pca-agent   # core + agent client
npm install @atlasauth/backend                    # resource-server verifier: verifyPCActn / requirePCA
```

Then follow the [agent quickstart](docs/guides/agent-quickstart.md) and the [resource-server quickstart](docs/guides/resource-server-quickstart.md), or run a verifier against the vectors:

```
cd verifiers/go-pca && go test ./...
```

## License

[MIT](LICENSE)
