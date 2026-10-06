---
title: PCA vs OAuth vs WebAuthn
order: 40
---

# PCA vs OAuth vs WebAuthn: when to use which

These three do not compete. They answer different questions, and a complete agentic system uses all three.

- **WebAuthn** answers authN: *is this the person (or device) holding this key?*
- **OAuth 2.0** answers authZ-by-delegation: *what has this user allowed this application to do on their behalf?*
- **PCA** answers authF: *is this specific action a faithful execution of an authority the principal actually conferred?*

## Side by side

| | OAuth 2.0 | WebAuthn | PCA |
|---|---|---|---|
| Question answered | authZ: may this client act within a scope? | authN: is this the key holder, here, now? | authF: is this exact action a faithful, in-policy, uncompromised execution of the principal's intent? |
| The credential | Access token (bearer, or sender-constrained with DPoP/mTLS) plus a refresh token | A signed assertion over a server challenge, from a device-held key | A **proof-carrying action (PCActn)**: capability chain, plan-inclusion proof, counter, risk claim, signature(s) |
| What is conferred | A scope: a coarse, static set of permissions | Nothing. It proves presence, it grants no authority | A signed intent envelope: goal commitment, predicates, caveats and risk policy, narrowed by attenuation at each delegation |
| Flow | One-time consent, then reuse the token until expiry or revocation | Challenge-response per ceremony (login, step-up) | Commit a plan once, then a fresh proof per action, bound to a node of that plan |
| What the verifier checks | Token validity and scope (locally for JWTs, or by introspection) | Signature over the challenge, origin, RP ID, counter | Chain attenuation, plan inclusion, leaf signature, counter, caveats, policy, revocation, threshold at the risk-derived level |
| Stolen credential | Usable by anyone until expiry or revocation (bearer) | Useless without the device and user verification | One proof is bound to one action, plan node and counter. A stolen key is still confined by the plan, envelope and trust budget |
| Replay | Within token lifetime unless sender-constrained | Prevented by server challenge | Prevented by a strictly increasing per-holder counter |
| Least authority | Scope granularity, chosen at consent time | Not applicable | Predicates over verb, resource and params, plus attenuation: a sub-agent can only get less |
| Compromised or steered client | Not addressed. A valid token authorizes whatever the client does | Not addressed | The central threat. Out-of-plan actions have no inclusion proof; high-risk actions need co-signers; trust budget decays |
| Revocation | Revoke or expire tokens; introspection or short TTLs | Remove the credential | Revoke a capability id (descendants die with it), freeze the instance, expiry caveats |
| Auditability | Server logs the verifier chooses to keep | Server logs | A transparency ledger: per-action commits with inclusion proofs the principal can replay |
| Human in the loop | At consent time only | At the ceremony | At consent, and per action when the risk-derived threshold needs a principal-device co-signature |

## Why a token is the wrong shape for an agent

An OAuth token proves *possession*. For a human app that is adequate: the app's behavior is fixed by its code and the user's intent is implied by the UI. An agent's behavior is chosen at run time by a model that untrusted content can steer (prompt injection, the confused deputy). A scope like `files:write` cannot distinguish "save the report" from "overwrite everything", and the token is equally valid for both. PCA moves the question from "does the caller hold a secret?" to "is this action provably inside what was committed and signed?", and it makes that checkable offline by the resource server.

## What PCA does and does not do

- It does not replace identity. The principal's root key still has to come from somewhere trustworthy, which is exactly what WebAuthn is for.
- It does not replace delegated access to a third party's API. If the resource server only understands OAuth, PCA can sit in front as a policy and audit layer, but the downstream call still uses that API's tokens.
- It does not claim to detect a malicious plan by itself: it bounds what a plan can do (predicates, risk policy, thresholds, budget) and makes every action attributable and auditable. In this release, features that depend on hardware (hardware attestation, SNARK compliance proofs) are optional seams that report `not-enforced` until you supply a verifier.

## When to use which, and how they compose

| Situation | Use |
|---|---|
| Sign a person in; protect the root of authority | WebAuthn (passkeys) |
| Let a human grant a third-party app access to their data | OAuth 2.0 / OIDC |
| Let an autonomous agent act on a resource, with bounded and auditable authority | PCA |

They stack:

1. **WebAuthn establishes the human.** The principal authenticates with a passkey. The principal's PCA root key signs the Root Intent Grant, and the same principal later provides the device co-signature when a high-risk action steps up. Note that in this release the principal share is a raw Ed25519 signature over `thresholdMessage(pcactn)`; binding it to a passkey ceremony is an integration the console or device layer provides ([Trust model](./security/trust-model.md)).
2. **OAuth connects human to app.** The user signs in to the application hosting the agent, and OAuth/OIDC handles any third-party API access that the app uses on their behalf.
3. **PCA governs agent to resource.** The agent presents a PCActn per action, and the resource server verifies it (`verifyPCActn` / `requirePCA`) and anchors it in the ledger.

## Adopting PCA incrementally

PCA degrades gracefully, so each rung is independently adoptable and a resource server can start small.

| Rung | What you turn on | What you get |
|---|---|---|
| 0 | OAuth 2.1 with PKCE and proof of possession (already shipped). A PCActn with only a scope and a PoP signature *is* an OAuth PoP request. | Bearer-free baseline; OAuth-only clients keep working. |
| 1 | `verifyPCActn` core checks (chain, plan inclusion, leaf signature, counter), Policy VM, risk functional, ledger | Plan-bound actions, per-action attributability |
| 2 | Threshold verification, revocation proofs, kill switch | Human-in-the-loop by cryptography; targeted and global revocation |
| 3 | Attestation (software mode now), optimistic fast-path | Workload identity; low-latency reversible actions |
| 4 | Hardware attestation and SNARK compliance (seams) | Intent privacy, weights-level binding as they become available |

OIDC and OAuth clients that do not understand PCA still work against the Rung 0 surface; PCA-aware verifiers get authF. A resource server can start with only the core checks and add threshold, revocation, attestation and ZK hooks as they become available, checking `verdict.checks` to see exactly which clauses were `pass`, `fail` or `not-enforced`.

See also: [overview](./README.md), [agent quickstart](./guides/agent-quickstart.md), [resource-server quickstart](./guides/resource-server-quickstart.md), [threat model](./security/threat-model.md), and the full documentation at https://atlasauth.net/pca.
