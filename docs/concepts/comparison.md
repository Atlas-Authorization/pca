---
title: Why PCA: a comparison
order: 9
---

# Why PCA: a comparison with OAuth, RAR, capability tokens and UCAN

An AI agent that holds a credential can be steered by what it reads, can leak what it holds, and can hand work to other agents. This page compares how five ways of authorizing an agent hold up against seven concrete attacks. Every result on it comes from a small runnable suite (see [Run it yourself](#run-it-yourself)) that implements each attack against each approach and prints which approaches stop it and why. The matrix below is that suite's output, unedited.

The comparison tries to be fair. Each approach is configured the way its specification intends and used well: audience-bound, short-lived, with the tightest constraints its format can state. Where another approach can express a limit, the suite uses it. Where PCA does not stop an attack, the page says so.

## The five approaches

| Approach | What the agent presents | How the suite uses it | Specifications |
|---|---|---|---|
| OAuth scopes | A bearer access token with a `scope` string | A signed JWT access token with `aud`, `exp` and the least scope (`payments:write`). A sub-agent gets a token by token exchange, which can only drop scopes. | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) §3.3, [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) |
| OAuth RAR | A bearer access token with `authorization_details` | One `payment_initiation` object per approved payment when the payments are known up front (the shape of the RFC 9396 §2 example); otherwise an API-defined type with a payee allowlist, a per-payment ceiling and, when wanted, a cumulative ceiling that the server tracks per token. A sub-agent gets a new, narrower token from the authorization server. | [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) |
| Macaroons / Biscuit | A bearer token with attenuating caveats | An HMAC-chained macaroon whose first-party caveats state the audience, payee allowlist, per-payment ceiling, the exact approved payments, and a cumulative ceiling checked against a spend total the server supplies. When a second system must vouch for each payment, the macaroon also carries a third-party caveat addressed to that system, which the agent discharges with a macaroon from that system. A sub-agent's token is attenuated offline by appending caveats. Biscuit gives the same outcome in every scenario here: it is also a bearer token with offline attenuation, its Datalog checks run against facts the authorizer supplies, with integer arithmetic, and third-party blocks play the role of third-party caveats. | [Macaroons (NDSS 2014)](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/), [Biscuit specification](https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md) |
| UCAN | A signed invocation, carrying a chain of signed delegations | Delegations with a `pol` over the invocation's `args` (payee, amount, exact payments). The invocation is signed by the invoker, which must be the audience of the last delegation, and carries a random `nonce`; the executor refuses a nonce it has already seen. When a second system must vouch for each payment, the chain runs from the principal through that system, whose delegation lists the payments it holds on file. A sub-agent gets a further delegation, signed offline. | [UCAN Delegation 1.0](https://github.com/ucan-wg/delegation), [UCAN Invocation 1.0](https://github.com/ucan-wg/invocation) |
| PCA | A proof-carrying action (PCActn) per request | A Root Intent Grant with predicates (payee allowlist, per-payment ceiling) and a trust budget denominated in dollars (the cumulative ceiling). When the payments are known up front, the principal authorizes the agent's committed plan; otherwise the server accepts any plan the agent commits and relies on the grant alone. Each action is signed by the agent's key and carries the capability chain, the plan-inclusion proof, a digest of its parameters, the audience and a strictly increasing counter. The server runs `requirePCA` (default-deny). A sub-agent gets an attenuated capability, signed offline. When a second system must vouch for each payment, the server also applies the Intent Layer extension's per-parameter provenance (see A2). | [Credential model](./credential-model.md), [Plan commitment](./plan-commitment.md), [Policy and risk](./policy-and-risk.md) |

The scenario is the same everywhere: a principal lets an agent pay vendor invoices at one resource server. Before each attack, the suite sends a legitimate request in the same setup and requires it to be allowed, so an approach can never score "Stopped" by refusing everything.

## Results

"Stopped" means the resource server refused the attack request. "Not stopped" means it allowed it.

<!-- matrix:start -->
| Attack | OAuth scopes | OAuth RAR | Macaroons / Biscuit | UCAN | PCA |
|---|---|---|---|---|---|
| A1. Confused deputy: injected, in-scope, unintended payment | **Not stopped** | Stopped | Stopped | Stopped | Stopped |
| A2. Poisoned approval: the injected payment is in what the principal approved | **Not stopped** | **Not stopped** | Stopped | Stopped | Stopped |
| A3. Stolen credential used by someone else for a different payment | **Not stopped** | **Not stopped** | **Not stopped** | Stopped | Stopped |
| A4. Captured request replayed verbatim | **Not stopped** | **Not stopped** | **Not stopped** | Stopped | Stopped |
| A5. Over-broad delegation to a sub-agent | **Not stopped** | Stopped | Stopped | Stopped | Stopped |
| A6. Payee and amount swapped after approval | **Not stopped** | Stopped | Stopped | Stopped | Stopped |
| A7. Delegated agent exceeds a cumulative spending limit across calls | **Not stopped** | Stopped | Stopped | **Not stopped** | Stopped |
<!-- matrix:end -->

Read it carefully. PCA is not the only approach that stops most of these. RAR and attenuable tokens stop every attack that their constraints can describe; UCAN additionally stops theft and replay because its invocations are signed and unique. What PCA adds is that one credential and one verifier cover all seven, without bolting on a second mechanism for possession, replay or spend. For A2 that takes an extension beyond PCA Core and a separate system that vouches for the values; macaroons, Biscuit and UCAN stop A2 with their own primitives under the same assumption.

## The attacks

### A1. Confused deputy: injected, in-scope, unintended payment

The principal approves two invoices: $120 to acme-hosting and $80 to paper-co. While working, the agent reads an injected message ("paper-co sent a revised invoice") and pays $250 to paper-co: an approved vendor, under the $500 per-payment ceiling, but not a payment anyone approved.

- **OAuth scopes: not stopped.** The token says `payments:write`. A scope cannot name a payee or an amount, so every payment is in scope.
- **RAR, macaroons, UCAN: stopped.** Each can list the two approved payments (two `authorization_details` objects, a caveat, a `pol` clause), and $250 to paper-co matches none of them.
- **PCA: stopped.** The agent committed a plan of the two payments and the principal authorized its root. The injected payment is not a node of that plan (`plan_root_authorized` fails), even though the grant's predicates would allow it.

What stops this attack, in every column, is binding the authority to the specific approved actions before the agent reads untrusted input. RAR, macaroons and UCAN can do that when the work is known at approval time; PCA makes it the normal flow (commit a plan, then act) and refuses unapproved plans by default.

### A2. Poisoned approval

The injection happens earlier, while the agent drafts the work. It proposes $120 to acme-hosting and $180 (not $80) to paper-co, and the principal approves that list without noticing. The company's accounts-payable system holds the real invoices ($120 and $80), and the principal's authority requires every payment's payee and amount to be vouched for by that system, independently of the approval.

No authorization scheme can tell a poisoned approval from a real one by looking at the approval alone. What stops this attack is a second, independent source of truth that each payment must agree with. The scenario assumes one exists, and gives every approach the same one.

- **OAuth scopes: not stopped.** A scope cannot name payees, amounts or a second system.
- **RAR: not stopped.** The token carries what the principal consented to, and the principal approved this payment. RFC 9396 has no member through which a second system vouches for the values at request time. An authorization server that checked its own copy of the invoices before issuing the token would catch it, but that is the server's own logic, outside RAR.
- **Macaroons / Biscuit: stopped.** The macaroon carries a third-party caveat addressed to the accounts-payable system. To use it, the agent needs a discharge macaroon from that system, bound to its own, and the discharge's caveat lists the invoices on file; $180 to paper-co is not one of them. Biscuit expresses the same requirement with a third-party block.
- **UCAN: stopped.** The delegation runs from the principal through the accounts-payable system to the agent. That system's delegation allows only the invoices it holds, and every policy along a chain applies.
- **PCA: stopped, using an extension.** This uses per-parameter provenance from the Intent Layer v2 extension, not PCA Core, and needs `@atlasauth/pca` 0.4.2 or later:
  - The accounts-payable system signs a label receipt for each invoice. The receipt binds a digest of each field's value (payee, amount) to the agent's session.
  - The agent's action declares, for each parameter, where its value came from. Its declaration is signed into the action.
  - The verifier, not the agent, classifies each source. A value that cites a receipt counts as vouched for (`tool` level) only if it hashes to the digest in that receipt. A value that cites the injected mail is `web`, and anything else is `agent`.
  - The principal's grant requires the payee and amount to be at least `tool` level.
  - The steered agent cites the paper-co receipt, the most it can do to look vouched for. The payee matches it, but $180 does not hash to the receipt's $80, so the amount is `agent` and no grant predicate permits the action. The plan check passes, because the principal approved the plan: provenance is what refuses it.

Provenance is opt-in. A resource server turns it on by passing the Intent Layer context (the session root, the signed action schema and a provenance policy pinning the receipt signer) to `authorize`, the library's authorization pipeline (`requirePCA` and the full verifier `verifyPCActn` accept the same context). The suite uses `authorize`, which also binds the decision to the payment the server executes and requires the replay store and revocation source. The coarser action-level taint gate is not used here: it classifies the sources an action declares without binding them to parameter values, so it cannot tell a $180 value from an $80 one.

What is left:

- **A principal who knowingly approves the attacker's payee and amount, or a source of truth that is itself poisoned.** If the accounts-payable system holds a fraudulent invoice, every approach in the matrix pays it.
- **Values with no trusted source.** Provenance can only refuse or escalate them; it cannot vouch for them.

The approval itself remains the first defense: show the principal what each action does in plain terms, keep per-action ceilings and a cumulative budget tight so a poisoned plan is bounded, and require a co-signature for high-risk actions ([Threshold and step-up](./threshold-and-step-up.md)).

### A3. Stolen credential used by someone else

The agent may pay acme-hosting or paper-co, up to $150 each. An attacker copies the agent's credential (from a log, a crash dump or a compromised tool) but not its private key, and pays $150 to paper-co.

- **OAuth scopes, RAR: not stopped.** Bearer tokens: possession is authority. Sender-constraining the token with DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) or mutual TLS ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)) would stop this.
- **Macaroons / Biscuit: not stopped.** Both are specified as bearer tokens.
- **UCAN: stopped.** The invocation must be signed by the delegation's audience; the thief cannot produce that signature.
- **PCA: stopped.** Each action must be signed by the key the capability chain was issued to (`leaf_signature` fails).

### A4. Captured request replayed verbatim

An attacker records the agent's legitimate $120 request on the wire and sends it again, byte for byte.

- **OAuth scopes, RAR, macaroons: not stopped.** The token is meant to be presented again until it expires; nothing in the request is single-use. A DPoP proof whose `jti` the server tracks would stop this for OAuth and RAR.
- **UCAN: stopped**, because this executor refuses a `nonce` it has seen. The specification requires the nonce so that invocations are unique and requires `exp` to bound replay; tracking seen nonces is the executor's job.
- **PCA: stopped.** The counter must strictly increase per holder (`replay` fails); `requirePCA` keeps it in its state store.

### A5. Over-broad delegation to a sub-agent

The agent may pay acme-hosting or paper-co up to $500 each. It hands a sub-agent the narrower job "pay paper-co, at most $100". The sub-agent pays $200 to paper-co, which the parent could have done.

- **OAuth scopes: not stopped.** Token exchange can only drop scopes, and payee and amount are not scopes, so the sub-agent's token is as broad as the parent's.
- **RAR: stopped**, with a round trip: the authorization server issues the sub-agent a token with narrower `authorization_details`.
- **Macaroons / Biscuit, UCAN, PCA: stopped**, offline: the agent appends a caveat, signs a narrower delegation, or delegates an attenuated capability. Removing the narrowing breaks the HMAC chain or signature in all three.

### A6. Payee and amount swapped after approval

The principal approves $120 to acme-hosting and $80 to paper-co. Between the agent and the server (a compromised tool wrapper or proxy), the $80 payment is rewritten to $480 to mallory.

- **OAuth scopes: not stopped.** Nothing binds the payee or amount.
- **RAR, macaroons: stopped.** The rewritten request matches no approved detail or caveat (the macaroon fails first on its payee allowlist).
- **UCAN: stopped.** The executor acts on the signed invocation `args`, which the proxy cannot change.
- **PCA: stopped.** The PCActn commits to a digest of the parameters, and the plaintext no longer hashes to it (`params_digest` fails).

### A7. Delegated agent exceeds a cumulative spending limit

The agent may pay acme-hosting or paper-co, at most $150 per payment and $300 in total. It pays $140, $140, then tries a third $140: each call is under the per-payment ceiling, the sum is not.

- **OAuth scopes: not stopped.**
- **RAR: stopped**, using an API-defined `maxTotalAmount` field and a running total the server keeps per token. RFC 9396 lets an API define such a field; it says nothing about consumption across requests, so that ledger is the server's own code.
- **Macaroons / Biscuit: stopped**, using a caveat `spent + amount <= 300` evaluated against a spend total the server supplies as a fact. Again, the server keeps the ledger.
- **UCAN: not stopped.** A UCAN policy is evaluated over one invocation's `args`, so a running total cannot be stated in the delegation; the executor would need its own out-of-band limit.
- **PCA: stopped.** The ceiling is the grant's trust budget, signed by the principal, and `requirePCA` debits it in its state store on every allowed action. Note what "stopped" means here: an exhausted budget does not forbid the payment outright. The verdict reports `trust budget depleted: human recharge required` and raises the required threshold, so the payment can still go through with the principal's co-signature.

## What the matrix does not show

- **Each other approach can be extended.** Add DPoP to OAuth or RAR and A3 and A4 change; add a spend ledger to a UCAN executor and A7 changes. Doing so assembles, from separate mechanisms, much of what a PCActn carries in one object. The claim here is not that these defenses are impossible elsewhere.
- **State is not free in any column.** Replay protection and cumulative limits need per-holder state at the resource server, in PCA as much as anywhere. `requirePCA` refuses requests when that state is not configured rather than silently skipping the checks.
- **PCA runs in three configurations in this suite.** A1 and A6 use a principal-authorized plan. A2 adds per-parameter provenance from the Intent Layer v2 extension on top of that plan. A3, A4, A5 and A7 use the weaker grant-only mode, where the server accepts any plan the agent commits; PCA still stops those attacks with the grant, the signature, the counter and the budget.
- **Several PCA features are not exercised**: risk-derived step-up thresholds, the transparency ledger and receipts, revocation, liveness beacons and attestation. See [Threat model](../security/threat-model.md).
- **Cost.** PCA signs every action and verifies a chain, an inclusion proof and a policy on every request. A scoped token is cheaper to issue and check.

## How PCA works with what you already run

PCA is the proof layer for agent actions. It is designed to sit inside existing OAuth and agent-protocol deployments rather than replace them.

| You run | How PCA fits | Package |
|---|---|---|
| OAuth 2.1 / MCP authorization | The MCP authorization spec builds on OAuth 2.1, Protected Resource Metadata ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) and resource indicators ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)). A PCA resource server publishes the same metadata and answers with the same 401 challenge, so generic MCP and OAuth clients can discover it; the PCActn's signed audience is the binding. | [`@atlasauth/pca-oauth`](https://www.npmjs.com/package/@atlasauth/pca-oauth) |
| MCP tools | Wrap a tool handler so every call builds a PCActn before it runs. | [`@atlasauth/pca-mcp`](https://www.npmjs.com/package/@atlasauth/pca-mcp) |
| Token exchange / Transaction Tokens | Project a PCA capability chain into RFC 8693 nested `act` claims inside a Transaction Token, so existing infrastructure can read who invoked whom. The token is an interop envelope; the PCActn stays the credential. | [`@atlasauth/pca-txn-tokens`](https://www.npmjs.com/package/@atlasauth/pca-txn-tokens) |
| DPoP or mTLS | Tie a PCActn to the holder key with an RFC 9449 DPoP proof or an RFC 8705 certificate binding. | [`@atlasauth/pca-dpop`](https://www.npmjs.com/package/@atlasauth/pca-dpop) |
| RAR | There is no dedicated bridge. The constraints an authorization server shows at consent as `authorization_details` (payees, amounts, ceilings) map directly onto a grant's predicates and budget, so one consent screen can drive both; the principal's key then signs the grant. | |
| AP2 (Agent Payments Protocol) | Issue and verify AP2 mandates as SD-JWT credentials, with the PCA grant or action proof carried inside the mandate. | [`@atlasauth/pca-ap2`](https://www.npmjs.com/package/@atlasauth/pca-ap2) |
| GNAP | Map a GNAP grant request and continuation onto an attenuated PCA capability and step-up. | [`@atlasauth/pca-gnap`](https://www.npmjs.com/package/@atlasauth/pca-gnap) |

## When not to use PCA

- **A person, not an agent, drives the client.** A fixed-code app acting on a user's clicks is what OAuth was built for. PCA's per-action proofs add cost without a matching threat.
- **The access is low value or read-only.** A short-lived, audience-bound, least-scope token is enough when misuse costs little.
- **The API you call only accepts OAuth.** PCA can govern and audit the agent in front of that API, but the downstream call still uses the API's own token. See [PCA vs OAuth vs WebAuthn](../migration.md).
- **Your limits fit a policy you already run.** If per-request constraints are all you need and you already operate UCAN or Biscuit, the matrix shows they cover most of the same ground.
- **You cannot keep per-holder state at the resource server.** Without a replay and budget store, `requirePCA` denies by default; that store is part of the deployment.
- **You expect authorization to catch a bad plan the principal approved without an independent source of truth.** Nothing can (A2). PCA, macaroons, Biscuit and UCAN can hold each action to a second system's records; without one, invest in the approval step.

Before relying on PCA as the only control over high-value actions, read the [Trust model](../security/trust-model.md).

## Run it yourself

```sh
npm create pca-app@latest my-attacks -- --template attacks
cd my-attacks
npm install
npm start                # every attack, every approach, with the server's reason, then the matrix
npm run matrix           # just the matrix, as Markdown
npm run json             # machine-readable results
```

It needs Node.js 20 or later and no accounts or network services. The A2 scenario uses the Intent Layer extension (`@atlasauth/pca/ext/intent`, in `@atlasauth/pca` 0.5 and later). Each approach is a short file you can read and change. If you think an approach is modeled unfairly, change its configuration and rerun.

## References

- OAuth 2.0: [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749); bearer token usage: [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750); JWT access tokens: [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068); resource indicators: [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)
- Rich Authorization Requests: [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396)
- Token Exchange: [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693); Transaction Tokens: [draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)
- DPoP: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449); OAuth mutual TLS: [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705); Protected Resource Metadata: [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)
- Macaroons: Birgisson et al., [Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/), NDSS 2014
- Biscuit: [specification](https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md)
- UCAN: [Delegation 1.0](https://github.com/ucan-wg/delegation), [Invocation 1.0](https://github.com/ucan-wg/invocation)
- Model Context Protocol: [Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- Agent Payments Protocol: [AP2](https://ap2-protocol.org/)
