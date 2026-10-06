# Proof-Carrying Authority (PCA)

**An execution-authentication framework for autonomous agents.**

> **Status: Preview.** PCA is in development. The hosted `/v1/pca/*` endpoints are gated and off by default. The libraries, reference verifiers and conformance suite can be used today. See the [trust model](docs/security/trust-model.md) for what is and is not production-hardened.

Live documentation: **<https://atlasauth.net/pca>** · Claude plugin: [Atlas-Authorization/atlas-claude-skills](https://github.com/Atlas-Authorization/atlas-claude-skills)

## The thesis: authN, authZ, authF

- **authN**: who are you?
- **authZ**: what may you do?
- **authF**: is *this specific action* a faithful, uncompromised execution of an authority the principal actually conferred?

For a human, authN and authZ are enough, because the human is the policy engine. An autonomous agent is a stochastic, externally steerable process: what it will do is unknown when authority is granted and can be manipulated while it runs. Knowing which agent is calling and which scopes it holds says nothing about whether the action is what was authorized.

PCA makes authF cheaply verifiable by replacing the bearer token with a **proof-carrying action (PCActn)**. The resource server does not check that the caller holds a secret; it verifies a proof that the action is a node of a pre-committed plan, inside a signed policy, reached through an intact attenuating capability chain, co-signed by as many parties as its risk demands, and affordable within a decaying trust budget. Verification is offline and deterministic.

## The PCA loop

1. **Mint a Root Intent Grant.** The principal signs an envelope (goal commitment, action predicates, caveats, risk policy, agent binding).
2. **Attenuate or delegate.** The agent (or a sub-agent) receives a capability that can only be narrowed.
3. **Commit a plan.** The agent commits the Merkle root of a DAG of intended actions.
4. **Act.** Each action is a signed PCActn carrying an inclusion proof for its plan node, the capability chain, a monotonic counter and a risk claim.
5. **Decide.** The Policy VM evaluates predicates, caveats, the risk functional and the trust budget, then releases the guardian signing share or refuses.
6. **Verify.** The resource server checks every clause, offline.
7. **Outcome.** `allowed` (anchored in a transparency ledger, receipt returned), `denied`, or `step_up` (a principal-device co-signature is needed).
8. **Audit and revoke.** Per-action ledger inclusion proofs; capabilities can be revoked and an instance frozen.

## Feature overview

- Root Intent Grants and attenuating capability chains
- Plan commitment (Merkle DAG) with per-action inclusion proofs
- Policy VM and a risk functional with a decaying trust budget
- Threshold and step-up co-signing (multi-signature, FROST threshold signatures, trustless DKG)
- Transparency ledger, revocation proofs and dead-man beacons
- Attestation, an optimistic fast-path with fraud proofs, and a zero-knowledge compliance seam
- A language-neutral wire format with a normative conformance suite and eight reference verifiers

## Repository contents

| Path | What it is |
|---|---|
| [`docs/`](docs/README.md) | Concepts, guides, reference, security and adoption docs (mirrors <https://atlasauth.net/pca>) |
| [`conformance/`](conformance/README.md) | Golden vectors and fixed test keys: the normative rules every implementation must match |
| [`verifiers/`](verifiers) | Reference verifiers in Go, Python, Rust, Java, PHP, Ruby and .NET, each passing every vector |
| [`playground/`](playground) | Interactive in-browser demo of the loop |
| [`sdks.md`](sdks.md) | Developer map: JS packages, verifiers, playground, conformance |
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
