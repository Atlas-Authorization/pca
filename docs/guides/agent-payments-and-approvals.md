---
title: Agent payments, risk-priced approvals and wallet permissions
order: 24
---

# Agent payments, risk-priced approvals and wallet permissions

> **Status: reference (CI pending).** These are verification and policy building blocks, not a payment service. No money moves here, and nothing on this page calls a card network or a chain. See [maturity tiers](../maturity.md).

This page covers three additions around agent spending: binding a card-network agent token to a grant, deciding when to ask a person, and mapping a grant to an ERC-7715 wallet permission.

## 1. Network agent tokens

A **network agent token** is a credential issued by a card network or a processor to one agent, carrying its own limits. PCA does not issue it. PCA does three things around it.

1. **Binds it to a grant.** The agent signs a statement over the token reference, the grant digest, the provider name and a nonce chosen by the issuer. Anyone can check it against the grant and the agent's key. A binding for another grant, another key or another nonce fails.
2. **Keeps the number out.** The token reference is an opaque handle. A reference that contains a run of 13 to 19 digits that passes the Luhn check is refused, both from you and from a provider reply.
3. **Joins the settlement to the proof.** A charge is started with the helper that builds the signed action proof and derives the metadata from its digest. The network request carries the grant digest, the action digest and the token reference. A settlement record joins the ledger entry only if all three come back exactly. A settlement without the action digest does not join.

The limits sent to the network are a copy of the limits PCA enforces, never wider. The network is a second enforcement point. If the grant is revoked, suspend the token; a failed suspend is an error, not a success.

### Providers

| Provider | Status |
| --- | --- |
| Generic provider interface (issue, suspend, controls) | Reference, tested with a mock |
| Visa Intelligent Commerce mapping | Generic mapping, **mock-tested only** |
| Mastercard Agent Pay mapping | Generic mapping, **mock-tested only** |

Visa and Mastercard publish overviews of their agent programs, but the endpoint-level references are available to partners. The two mappings above therefore use placeholder field names and make no network calls. To go live you need partner access with each network, then replace the transport and field names with the documented ones.

## 2. Ask a person only when it is worth it

The rule is one comparison, with explicit inputs:

> ask a person when **(upper bound of the probability the action is bad) × (loss if it is bad)** is greater than **the cost of interrupting the person**.

* The **interruption cost**, the **hard ceiling** on loss and the **tightening step** are set by the principal and signed. Nothing about them is guessed from behaviour.
* The loss comes from the action's schema and the probability upper bound from your own calibrated source. Both are inputs you provide.
* Everything is integer arithmetic (probabilities in parts per million, money in minor units), so every verifier gets the same answer. Any missing, malformed or unsigned input means **ask**.

### What may change over time

A per-principal **multiplier** scales the probability up. It starts at one and can only go up. It rises when the principal, with a signed answer, denies an action that the current pricing would have approved on its own. Approvals, forged answers, replayed answers and answers about unknown actions change nothing. No sequence of answers can make the system ask less; the test suite checks this with randomised sequences.

Asking less is possible only through a **signed raise** from the principal, within a maximum set in the signed configuration.

## 3. ERC-7715 wallet permissions

[ERC-7715](https://eips.ethereum.org/EIPS/eip-7715) (a draft) lets an app ask a wallet for a permission for a session account. `wallet_requestExecutionPermissions` carries the request; the wallet answers with the permission it actually granted, a context handle and a delegation manager.

The adapter maps a grant to a request and checks the answer:

* The cap becomes an allowance (the example permission shape in the draft is `native-token-allowance` with an `allowance` field; an ERC-20 variant is a PCA profile and must be confirmed against your wallet). The end of the grant becomes the `expiry` rule.
* Money is converted with an exact integer ratio **you** give (token base units per minor unit). There is no price feed and no fractions.
* The answer is accepted only if it is no wider than the request and the grant: allowance not larger, same token, chain and recipient, expiry present and not later, only known rule types, and a delegation manager on your list. The draft lets a wallet adjust a permission up or down; PCA accepts only a reduction.
* A context handle that already belongs to another grant is refused.

PCA does not redeem the permission on chain and has no chain client.

## Verifying in your language

The binding check, the pricing decision and the permission check are implemented in the TypeScript reference and in the Python, Go, Rust, Ruby, PHP, Java, Kotlin, .NET and Swift verifiers, all replaying one shared vector file.
