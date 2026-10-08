---
title: API reference
order: 20
---

# API reference

> Preview. Every public `/v1/pca/*` route returns `404 Not found` unless the instance has `auth_config.pca.enabled = true`. The gate does not reveal that PCA exists.

This page is the normative reference for the hosted `/v1/pca/*` surface (public and admin routes) and the dashboard console routes. For the model behind them, see the [README](../README.md).

## Conventions

**Instance resolution.** Public and admin `/v1/pca/*` routes act on one instance. Public routes resolve it from the `Host` header (the instance's frontend API host, like JWKS). Admin routes take the instance from the secret key.

**Authentication classes.**

| Class | Meaning |
|---|---|
| public | No credential. Self-authenticating: grants are signed by the principal, PCActns by the leaf holder, co-sign shares by the principal key. Rate limited. |
| `sk_` `pca:write` / `pca:read` | A secret key (`Authorization: Bearer sk_...`) holding the scope. Both scopes are in the product scope catalog; a `*` key also works. |
| dashboard | A signed-in console user with access to the account and instance. Some actions need an owner or admin (privileged). |

**Rate limit.** Public routes are limited per instance and client IP to `pca.publicRateLimitPerMin` requests per minute (default 60, allowed range 1 to 10000). Responses carry `RateLimit-Limit` and `RateLimit-Remaining`; over the limit returns `429`. Admin routes are gated but not IP rate-limited.

**Instance settings** (`auth_config.pca`): `enabled` (default `false`), `publicRateLimitPerMin` (default 60), `maxPlanNodes` (default 256, range 1 to 5000).

**Request bodies** reject unknown top-level fields with a `400` naming the field.

**Errors** use the Atlas envelope `{ errors: [{ code, message, param?, meta? }] }`. PCActn authentication failures on `/actions` use `401` with a `WWW-Authenticate` challenge:

```
PCA realm="atlas", error="<missing_pcactn|invalid_pcactn|unknown_grant>", hint="send PCA-Action: <base64url PCActn> or JSON body {pcactn}"
```

**Presenting a PCActn.** Either the header `PCA-Action: <base64url(PCActn JSON)>` or a JSON body `{ "pcactn": <object or string> }`.

## Route summary

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /v1/pca/grants` | public | Register a signed Root Intent Grant |
| `POST /v1/pca/plans` | public | Commit a plan DAG under a grant |
| `POST /v1/pca/actions` | public | Verify a PCActn, anchor it, return a receipt |
| `GET /v1/pca/stepups/:id` | public | Poll a step-up |
| `POST /v1/pca/stepups/:id/cosign` | public (principal-signed) | Submit the principal-device share |
| `POST /v1/pca/stepups/:id/deny` | `sk_` `pca:write` | Deny a pending step-up |
| `GET /v1/pca/claims/:id` | public | Poll an optimistic claim |
| `POST /v1/pca/claims/:id/challenge` | public | Trigger re-adjudication of an open claim |
| `GET /v1/pca/ledger` | public | Ledger head |
| `GET /v1/pca/ledger/entries` | public; `sk_` `pca:read` adds openings | Ledger entries |
| `GET /v1/pca/ledger/:index/proof` | public | Inclusion proof |
| `POST /v1/pca/revocations` | `sk_` `pca:write` | Revoke a capability id |
| `POST /v1/pca/freeze` | `sk_` `pca:write` | Engage the kill switch |
| `DELETE /v1/pca/freeze` | `sk_` `pca:write` | Clear the kill switch |
| `GET /v1/pca/attestors` | `sk_` `pca:read` | List trusted software-attestor keys |
| `PUT /v1/pca/attestors` | `sk_` `pca:write` | Replace trusted attestor keys |
| `GET /v1/dashboard/accounts/:accountId/instances/:instanceId/pca/stepups` | dashboard | List step-ups |
| `POST /v1/dashboard/accounts/:accountId/instances/:instanceId/pca/stepups/:id/deny` | dashboard (owner/admin) | Deny a step-up |

## Grants

### `POST /v1/pca/grants`

Register a Root Intent Grant. Public and self-authenticating: the body is the principal's signed root capability.

Request: `{ "grant": <Capability> }` (the object returned by `mintGrant`).

The grant must verify as a single-hop chain (`verifyChain([grant], grant.issuer)`) and carry a valid envelope; otherwise `400`.

Response: `201` on create, `200` if already registered.

```json
{ "object": "pca_grant", "grant_ref": "<grant.id>", "status": "active" }
```

`status` is `active` or `revoked`.

## Plans

### `POST /v1/pca/plans`

Commit a plan under an active grant. Request:

```json
{ "grant_ref": "<grant.id>", "nodes": [ { "id": "n1", "verb": "read", "resource": "doc:1" } ] }
```

`nodes` must have 1 to `maxPlanNodes` entries, each with string `id`, `verb` and `resource` (optional `params_digest`, `reversibility_class`, `pre`, `post`); node ids must be unique. `404` for an unknown grant, `403` if the grant is not active, `400` for an invalid plan.

Response `201`: `{ "object": "pca_plan", "plan_root": "<merkle root>", "grant_ref": "<grant.id>" }`. In this release a committed plan is auto-authorized.

## Actions

### `POST /v1/pca/actions`

Verify a PCActn, apply the threshold and step-up logic, and anchor an allowed action in the grant's ledger.

Request (body, or the `PCA-Action` header for the PCActn alone):

| Field | Type | Meaning |
|---|---|---|
| `pcactn` | object or string | The signed PCActn |
| `params` | object | Plaintext params for predicates. Must hash to `action.params_digest` |
| `subject`, `env` | object | Inputs for predicate `where` clauses |
| `attestation` | object | An `AttestationDocument` ([attestation](../concepts/attestation.md)) |
| `optimistic` | object | A `BondedClaim` ([optimistic](../concepts/optimistic-and-zk.md)); ignored for irreversible actions |

Adjudication order: grant active, not frozen, committed plan for `plan.root`, replay counter strictly increasing per leaf holder, revocation non-membership for every capability in the chain, optional attestation; then a probe verification derives the required `t`; the server adds its guardian share for `t >= 2`; the final verification enforces the threshold. On allow, the counter and trust budget are advanced atomically (a concurrent submission of the same counter loses and is refused as a replay) and the action is appended to the ledger.

Responses:

| Status | Body | When |
|---|---|---|
| `200` | `{ "allow": true, "verdict": {...}, "receipt": {...} }` | Allowed and anchored |
| `200` | `{ "allow": true, "optimistic": true, "claim_id", "challenge_window_ms", "verdict", "receipt" }` | Allowed with an optimistic claim at `t <= 2` |
| `202` | `{ "allow": false, "step_up_required": true, "stepup_id", "required_t", "verdict" }` | `t = 3`: held pending the principal-device share |
| `401` | `{ "allow": false, "verdict" }` + `WWW-Authenticate: PCA ...` | Missing or undecodable PCActn, unknown grant, or a failed `version`, `cap_chain`, `leaf_signature`, `malformed` or `grant_ref` check |
| `403` | `{ "allow": false, "verdict" }` | Denied: out of plan, policy, revoked, replayed counter, frozen, grant revoked |
| `400` | Atlas error | Malformed `attestation` or `optimistic`, or a rejected claim |

`verdict` is the `PcaVerdict`: `{ allow, r, requiredThreshold: { t, proof, optimisticAllowed }, checks, reasons, budget? }`. `checks` maps clause names (for example `version`, `cap_chain`, `plan_inclusion`, `leaf_signature`, `counter`, `grant_ref`, `params_digest`, `delegated_caveats`, `policy`, `threshold`, `budget`, `revocation`, `attestation`) to `pass`, `fail` or `not-enforced`.

`receipt`:

```json
{ "grant_ref": "...", "index": 0, "commit": "...", "root": "...", "size": 1, "inclusion_proof": { "index": 0, "size": 1, "path": [] } }
```

Verify it offline with `verifyLedgerInclusion(root, inclusion_proof, commit)`.

The agent's `risk_claim` is untrusted: the server starts from a baseline and the claim can only raise risk ([Policy and risk](../concepts/policy-and-risk.md#how-the-hosted-surface-derives-risk)).

## Step-ups

A step-up is an action held for the principal-device share. It expires 15 minutes after creation.

### `GET /v1/pca/stepups/:id`

```json
{ "object": "pca_stepup", "stepup_id": "...", "grant_ref": "...", "action_digest": "...",
  "required_t": 3, "status": "pending", "shares": ["guardian"], "created_at": "...", "expires_at": "..." }
```

`status` is `pending`, `approved`, `denied` or `expired`. `receipt` is present once approved. `shares` lists the roles already collected (the agent share is the PCActn's own signature and is not listed).

### `POST /v1/pca/stepups/:id/cosign`

Public, self-authenticating. Request:

```json
{ "role": "principal", "publicKey": "<grant principal key>", "sig": "<Ed25519 over thresholdMessage(pcactn), base64url>" }
```

Only `role: "principal"` is accepted, and `publicKey` must equal the grant's principal key (`403` otherwise); the signature must verify (`400`). `409` if the step-up is no longer pending.

- `202` `{ ...stepup view, "step_up_required": true }` if still short of `required_t`.
- `200` `{ ...stepup view, "allow": true, "verdict", "receipt" }` when the threshold is met: the action is re-verified in full, the trust budget is recharged (a human touch), the action is anchored, and the step-up becomes `approved`.
- If the held action no longer passes (revoked, frozen, replayed counter, policy), the step-up ends `denied` and the denial response is returned.

### `POST /v1/pca/stepups/:id/deny`

Auth: `sk_` `pca:write`. Body `{ "reason"?: string }` (truncated to 500 characters). Returns the step-up view with `status: "denied"`. `409` if not pending. Audited as `pca.stepup.denied`.

## Optimistic claims

### `GET /v1/pca/claims/:id`

```json
{ "object": "pca_optimistic_claim", "claim_id": "...", "grant_ref": "...", "pcactn_digest": "...",
  "bond_ref": "...", "claimed_r": 0.1, "reversibility_class": "reversible", "status": "open",
  "challenge_window_ms": 60000, "challenge_window_closes_at": "...", "opened_at": "...",
  "slash_bond_ref"?: "...", "receipt"?: {...} }
```

`status` is `open`, `expired` (window closed unchallenged) or `slashed`.

### `POST /v1/pca/claims/:id/challenge`

Public. Body `{ "reason"?: string }` (audit metadata only). The challenger supplies **no** policy inputs. The server re-runs the Policy VM from the context the agent recorded when opening the claim, against the current grant, revocation set and time, and slashes only if that re-evaluation contradicts the claim or a capability in the chain has since been revoked. Success returns the claim view with `fraudulent: true` and `reason`; `409` if the claim is not open or no fraud is established. Audited as `pca.claim.slashed`.

## Ledger

All three take `grant_ref` as a query parameter (`400` if missing, `404` if unknown).

### `GET /v1/pca/ledger?grant_ref=`

`{ "object": "pca_ledger_head", "grant_ref": "...", "size": 12, "root": "..." }`

### `GET /v1/pca/ledger/entries?grant_ref=`

```json
{ "object": "list", "grant_ref": "...", "data": [
  { "object": "pca_ledger_entry", "index": 0, "commit": "...", "shredded": false, "created_at": "..." } ] }
```

Anonymous callers see commits only. With a secret key holding `pca:read` for the same instance, each entry also includes `opening` (`{ salt, pcactn }`) unless it was shredded (`shredded: true`).

### `GET /v1/pca/ledger/:index/proof?grant_ref=`

`{ "object": "pca_inclusion_proof", "grant_ref": "...", "index": 0, "commit": "...", "root": "...", "inclusion_proof": { "index", "size", "path": [{ "side", "hash" }] } }`. `404` if there is no such entry.

## Revocation and kill switch

### `POST /v1/pca/revocations`

Auth: `sk_` `pca:write`. Body `{ "grant_ref": "...", "cap_id": "..." }`. Revokes a capability id under a grant; every descendant in any chain that includes it dies with it. Revoking the grant's own id (`cap_id == grant_ref`) also marks the grant `revoked`. `201` when newly revoked, `200` if already. Audited as `pca.capability.revoked`.

```json
{ "object": "pca_revocation", "grant_ref": "...", "cap_id": "...", "revoked": true }
```

### `POST /v1/pca/freeze` and `DELETE /v1/pca/freeze`

Auth: `sk_` `pca:write`. `POST` body `{ "reason"?: string }`. While frozen, **every** PCActn for the instance is denied. Both return `{ "object": "pca_freeze", "frozen": true | false }` and are audited (`pca.frozen`, `pca.unfrozen`).

## Attestors

### `GET /v1/pca/attestors`

Auth: `sk_` `pca:read`. `{ "object": "pca_attestors", "trusted_attestor_keys": ["<b64u key>", ...] }`.

### `PUT /v1/pca/attestors`

Auth: `sk_` `pca:write`. Body `{ "trusted_attestor_keys": [...] }`: up to 50 base64url Ed25519 public keys (32 to 128 characters of `[A-Za-z0-9_-]`). Replaces the list; returns the saved list. Audited as `pca.attestors.updated`. Attestation is enforced for an action only when this list is non-empty and the action presents an attestation.

## Dashboard routes

Base: `/v1/dashboard/accounts/:accountId/instances/:instanceId/pca/stepups`. The console lists pending step-ups with the exact bytes the principal device must sign; the UI signs them with the principal key and calls the public `POST /v1/pca/stepups/:id/cosign`.

### `GET .../pca/stepups?status=`

`status` is optional: `pending`, `approved`, `denied` or `expired` (`400` otherwise).

```json
{ "stepups": [ { "id": "...", "grant_ref": "...", "action": { "verb": "...", "resource": "..." },
  "required_t": 3, "threshold_message": "<base64url bytes to sign>",
  "created_at": "...", "expires_at": "...", "status": "pending" } ] }
```

### `POST .../pca/stepups/:id/deny`

Owner or admin. Body `{ "reason"?: string }` (500 characters max). Returns the step-up in the same shape with `status: "denied"`; `404` unknown, `409` if not pending. Audited as `dashboard.pca.stepup.denied`.

Next: [Wire formats](./wire-formats.md).
