---
title: The operational plane
order: 12
---

# The operational plane: freshness, listing, bundles, decision logs and grant management

> **Status: production (pending CI).** The grant-management, lease, blueprint, break-glass and receipt parts are in `@atlasauth/pca-grants`, which carries a fail-closed table and is in the mutation set. The TypeScript reference and all nine native verifiers (Go, Python, Rust, Java, Kotlin, .NET, PHP, Ruby, Swift) implement the artifacts below against shared vectors. See [maturity tiers](../maturity.md).

These pieces sit around the verifier and make a deployment operable. They live in `@atlasauth/pca-grants`, with the protocol bridges in `@atlasauth/pca-authzen`, `@atlasauth/pca-signals` and `@atlasauth/pca-gnap`.

## Consistency tokens: a revoke is ordered before the next decision

Every write (a grant change, a revoke, a budget commit, a policy change) can return a signed `fresh_at` token: the highest revocation epoch, ledger size, budget version and policy revision the issuer had when it wrote. The caller puts the newest token it holds into its next PCActn as the signed `fresh_at` member (`buildPCActn({ freshAt })`), so it cannot be stripped or swapped after signing. A verifier whose own state is behind the token answers **escalate with `stale_state`** (refresh and retry), never allow. A token for another scope, a forged one, one from the future, one past an optional age limit, or one at the same policy revision with a different digest is a deny. Folding tokens takes the field-wise maximum, so an old token never lowers a fresher one.

This closes three cases: the principal revokes an agent while a PCActn is in flight to a server with a cached epoch; a restriction is applied after content was shared; two servers hold different budget versions. A caller that never presents its token still gets the verifier's own bound (the signed revocation epoch), not the exact one.

## Listing what an agent may touch

`listAuthorized` returns the objects of a type that the grant's capability permits AND, when you configure a relation source (OpenFGA, SpiceDB, Atlas FGA or your own tuples), that the relationship allows. The relationship can only narrow. Pages are bound by a signed cursor to the subject, type, filter, policy and limit. Each page is charged to a read accumulator for what was scanned, not only what was returned, so scraping through a filter drains the budget. Each page returns a signed receipt over the policy digest, the consistency token, the filter and the exact objects, so the resource server can prove what an agent was shown.

AuthZEN Search (`authzenSearchHandler`) exposes the same thing on the standard endpoints: `/access/v1/search/subject`, `/resource` and `/action`. Resource search is `listAuthorized`; action search is "what may I do here".

## Signed policy bundles and decision logs

A policy bundle pins the grant digests, the action schema, the constitution, the templates and the flow rules under one revision number. It is accepted only with at least k valid signatures from distinct pinned keys; a lower revision, a same-revision different content, a revision that does not chain from the accepted one and a verifier older than the bundle's `min_verifier_version` are refused.

Each decision becomes a record that cites the bundle revision and digest, is hash-chained to the previous record and committed to a Merkle log whose head is signed. A receiver of the stream (`nextBatch`, `verifyBatch`) detects a gap, a replay, a reordering, an edit and a truncation. An auditor verifies offline that a given denial happened under revision R. Fields are masked by data class before they enter the log. `semanticDiff` re-runs the decision function over recorded traffic under two revisions and lists exactly what changed, widenings first.

## Grant management

One resource for a principal's grants, advertised in the discovery document under `grant_management`:

| Call | Meaning |
|---|---|
| list, inspect | Filter by principal, agent and status; inspect shows the chain digest, usage, remaining budget and pending needs. |
| amend `narrow` | A signed attenuation by the holder or the principal. Revises the grant in place. |
| amend `merge` / `replace` | If the result is not provably narrower, it needs the principal's signature over the current revision and a satisfied step-up, and creates a NEW grant id with `supersedes`. Nothing widens in place. |
| revoke | Scope `grant`, `agent` or `subtree`, by the principal's signature (bound to the scope) or a host-authenticated admin. |
| needs | The agent files typed needs; the principal approves a delta, and may only lower the amounts of needs marked `adjustable`. |

The hosted API serves all of it. A registered root capability stays immutable, so management works on a principal-signed **authority statement** (verbs, resource patterns, ceilings, expiry) that admission enforces on top of the grant's envelope:

1. `PUT /v1/pca/grants/{grant_ref}/authority`: the principal signs the initial statement (revision 0). Once.
2. `POST /v1/pca/grants/{grant_ref}/amend`: a narrowing is signed by the holder or the principal and revises the statement in place; a signature names the revision, so it cannot be replayed on the next one.
3. A widening needs the principal's signature, a **step-up** (`POST /v1/pca/grants/{grant_ref}/step-up` issues a single-use challenge, the principal signs its nonce on its own device, `.../step-up/{id}/approve`) and `new_grant_ref`: a registered grant of the same principal and agent that carries the wider authority. The old grant is superseded and revoked in the same transaction.
4. Needs: `POST .../needs` (signed by the holder), `POST /v1/pca/needs/{id}/approve` (principal signature, lowered amounts only, step-up, successor) or `/deny`.
5. `GET /v1/pca/grants/{grant_ref}` shows the statement, `DELETE` revokes.

Hosted admission enforces verbs, resources, expiry and **limits**. The limit keys are a closed grammar, and a statement with any other key is refused when it is written: `max.<param>` (a per-action ceiling on a numeric action parameter), `sum.<param>` (a lifetime total of that parameter), `count` (a lifetime number of actions) and `rate.<seconds>` (actions per fixed window). The parameter plaintext (`context.params`, bound to the signed action) is required for `max.*` and `sum.*`. The counters are charged atomically inside the admission transaction, so concurrent actions cannot overshoot and a refused action costs nothing. The operator key can submit a change but never replaces a signature.

## Stream health and interaction

`StreamHealth` tracks an event stream with verification round trips (single-use, expiring states). A receiver claims "no pushed revocation was missed in the last N seconds" only if the stream is enabled and a verification completed inside that window; otherwise it falls back to the signed epoch bound. `riskLevelChangeSET` and `assuranceLevelChangeSET` emit the CAEP events from your risk and discharge changes. `InteractionServer` in `@atlasauth/pca-gnap` implements the GNAP interaction modes (redirect, app, user code, user code with URI; finish by redirect or push) with the interaction hash and single-use references.

## Managing event streams

`ssfManagementHandler` in `@atlasauth/pca-signals` implements the SSF stream management API (create, read, update with PATCH, replace with PUT, delete, status, add and remove subject, verification) and `transmitterMetadata` the discovery document. A stream belongs to one receiver; anyone else gets 404. The hosted API serves it at `/v1/ssf/configuration`, `/status`, `/add_subject`, `/remove_subject` and `/verification` (operator key; the stream belongs to the key that created it), persists the streams, and serves RFC 8936 poll delivery at `/v1/ssf/streams/{id}/poll`. Push delivery posts to the receiver's https endpoint behind the webhook SSRF guard; a SET that could not be pushed stays available to poll.

## What is not here yet

The relation-source adapters for specific products are yours to write; `listAuthorized` takes the capability as a predicate and will be connected to the residual-filter engine when that lands; the SSF management handler is also served hosted (below).
