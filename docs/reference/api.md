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

**Rate limit.** Public routes are limited per instance and client IP to `pca.publicRateLimitPerMin` requests per minute (default 60, allowed range 1 to 10000). The limit is hierarchical: each request is also charged to its network (IPv4 /24, IPv6 /48; `quotas.publicPerNetworkPerMin`, default 8 times the per-source limit) and to one global pre-authentication bucket for the instance (`quotas.publicPreAuthGlobalPerMin`, default 64 times). A source that is already limited is refused before it charges the aggregates. So a spray over any number of addresses gets at most the network allowance per network and the global allowance in total. While the global bucket is exhausted, new public requests on the instance are refused for the rest of the minute; authenticated per-grant budgets are separate. Responses carry `RateLimit-Limit` and `RateLimit-Remaining` (the smallest headroom of the three); over any level returns `429`. Admin routes are gated but not IP rate-limited. The client IP is the TCP socket address unless `TRUSTED_PROXY_COUNT` is set (the number of reverse proxies in front of the API; the client is then the Nth entry from the end of the trusted header's chain, never a client-supplied one). Exactly one forwarding header is trusted, `TRUSTED_PROXY_HEADER`: `x-forwarded-for` (default), `forwarded` (RFC 7239 `for=` chain, same rule) or `x-real-ip` (one value the edge-most trusted proxy overwrites). The other headers are ignored. If the chain is shorter than `TRUSTED_PROXY_COUNT` (the request did not come through every trusted proxy), or the picked entry is not an IP address, the socket address is used and the fallback is logged. Addresses are canonicalised: a `:port` is stripped, IPv4-mapped IPv6 becomes IPv4, IPv6 is compared in RFC 5952 form, and every per-source bucket keys an IPv6 client on its `/64`. The audit `ip` is the canonical address.

**Pre-authentication cost (R6-API-01, R6-API-04).** An unauthenticated request cannot make the server verify signatures for it. `POST /v1/pca/actions` and `/actions/dry-run` run, in order: size caps; structural parse and shape caps; `aud` (must be this instance id), `iat` and `exp` (R5-API-03; refused `401` with `checks.audience` or `checks.validity` = `fail`); `grant_ref` equal to `cap_chain[0].id`; the suite allowlist and the `holder_pq` commitment of every hop and the leaf; the stored-grant lookup and root equality by content hash (`capHash`); the strict v2 wire form; then the per-source post-quantum budget; and only then signatures (the leaf first, then the chain under the stored grant). None of the steps before the root match verifies a signature or touches a shared bucket. On a 65 KB 8-hop hybrid chain the anonymous path costs under 1% of a full verification (measured over HTTP against Postgres: 0.7 ms incremental against an 88 ms full verify; it was 108 ms against 142 ms, 76%, before). Bytes that do match a stored root (a replay) are still unauthenticated at the signature step, so their post-quantum work is charged first to `quotas.pqVerifyUnitsPerSourcePerMin` (default 128 units per minute, one per PQ hop or leaf, `429` when exhausted) and their Ed25519 work is bounded by the public per-source limit. The same budget applies before any PQ verification on the other unauthenticated verifying routes: principal beacons (`POST /v1/pca/beacons` without `Authorization`, after the issuer check), witness cosignatures (`POST /v1/pca/ledger/witness`, after the trusted-key check) and mesh proofs (`POST /v1/pca/mesh/proofs/verify`, one unit per PQ chain hop). A hybrid signature's Ed25519 half is always checked first; a failure stops before the PQ half.

**Shared caches (R5-API-05/06, R6-API-05).** Compiled regex programs live in one bounded least-recently-used cache keyed by the SHA-256 of the pattern. Each source may own at most 64 of its 512 entries (a new pattern from a source at its share replaces that source's own oldest entry), total compiled size is capped, and nothing on a request path clears the cache. The in-process rate-limit store (tests, single node, and the Redis fallback) evicts in O(1) and never evicts a live bucket that is at or over its limit. When it is full of such buckets, new keys share one overflow bucket instead of evicting anyone. A spray of fresh keys therefore cannot reset a client that is being limited.

**Instance settings** (`auth_config.pca`): `enabled` (default `false`), `publicRateLimitPerMin` (default 60), `maxPlanNodes` (default 256, range 1 to 5000).

**Request bodies** reject unknown top-level fields with a `400` naming the field.

**Errors** use the Atlas envelope `{ errors: [{ code, message, param?, meta? }] }`. PCActn authentication failures on `/actions` use `401` with a `WWW-Authenticate` challenge:

```
PCA realm="atlas", error="<missing_pcactn|invalid_pcactn|unknown_grant>", hint="send PCA-Action: <base64url PCActn> or JSON body {pcactn}"
```

**Presenting a PCActn.** Either the header `PCA-Action: <base64url(PCActn JSON)>` or a JSON body `{ "pcactn": <object or string> }`.

## Post-quantum key pins

A pure-post-quantum or hybrid artifact names its signer by an Ed25519 key and carries its own PQ public key. The server never verifies under that embedded key: a PQ liveness beacon (`POST /v1/pca/beacons`, principal path) or witness cosignature (`POST /v1/pca/ledger/witness`, which now also accepts `alg`, `pq_pk`, `pq_sig`) is accepted only under the PQ key pinned for the signer. The same holds for intent session roots (`POST /v1/pca/intent/sessions`) and session grants (`POST /v1/pca/intent/sessions/:sid/grants`): a pure-PQ or hybrid root or grant is accepted only when its signer's PQ key is pinned here; the key listed in the root's own `principals[].pq_pk` is never trusted. Ed25519 behaviour is unchanged and needs no pin.

| Method and path | Purpose |
|---|---|
| `POST /v1/pca/pq-pins` | Register `{ binding }` from `signPqBinding(edSecret, edPublic, pqPublicKey, epoch, instanceId)` (signed on the client; `epoch` is a positive integer you raise on every rotation, `aud` is this instance's id). The identity must be an enrolled active principal or a trusted witness key (`403` otherwise); a binding the identity did not sign for this instance, with a PQ key that is not a well-formed key of a registered suite, or with a non-positive epoch is `400`; a different key for an already-pinned identity, or an epoch at or below the last one seen for the identity (including a deleted pin's tombstone), is `409` with the minimum acceptable epoch. |
| `GET /v1/pca/pq-pins?identity=` | Read the binding back (`identity`, `pq_pk`, `epoch`, `aud`, `sig`; re-verified on every read; `404` for a deleted pin). |
| `DELETE /v1/pca/pq-pins/:identity` | Operator rotation step (secret key, `pca:write`, audited). Leaves a tombstone holding the last epoch, so the removed binding and every older one can never be registered again; the identity re-pins by signing a binding with a higher epoch. Artifacts from that identity are refused until it is pinned again. |

Design notes and limits (R4-14):

- A pin is registered by an Ed25519-signed binding and is first-writer-wins per identity. It protects an identity that has ALREADY pinned against a later forger who can break only the PQ side or who holds only an artifact; it adds nothing against an adversary who can break Ed25519 itself, because that adversary can sign the first binding for an identity that has not pinned yet, and, after an operator `DELETE`, a higher-epoch binding. Pin every identity you rely on before you need it, and treat `DELETE` as a trust reset for that identity.
- The epoch is a monotone integer chosen by the identity key holder (maximum `2^53 - 1`). A holder that signs a binding at the maximum epoch makes the identity unrotatable (no larger epoch exists); recovery is a new identity key. This is a self-inflicted denial of service for that identity only, and is deliberate: the alternative (an operator-resettable epoch) would let an operator replay an old binding.
- A deleted pin leaves a tombstone holding the last epoch, so re-registration needs a strictly higher one.

Storage is the `pca_pq_pins` table (migration `0147_pca_pq_pins.sql`). Production migrations are hand-applied: run the file with `psql` before deploying the API build; the old build ignores the table.

## Payments and mesh checks, and a breaking change

The hosted surface exposes only the pure, secret-free checks for payments and the capability mesh:

| Method and path | Purpose |
|---|---|
| `POST /v1/pca/payment-mandates/authorize` | Decide a charge against a payment mandate whose grant is registered with the instance (auto, step-up or deny); an auto charge debits the mandate's server-held cumulative budget. Body: `mandate`, `charge`, `idempotency_key` (a retry replays the recorded decision; a reused key for another charge is `409`). The body's budget, clock and charge history are ignored. |
| `POST /v1/pca/mesh/proofs/verify` | Verify a MeshProof against a pinned trust set. The body's `trust` carries `humanPrincipal`, `witnesses` and `threshold`; the verifier clock is always the server clock, and a `trust.now` in the request is rejected with `400`; the domain allowlist and root domain come from the instance's `auth_config.pca.mesh` (`{ allowedDomains[], rootDomain }`) and are rejected with `400` if sent in the request. `409` when the instance has not configured them. Freshness bounds (R3-04): `auth_config.pca.mesh` may also set `maxHeadAgeMs`, `maxClockSkewMs`, `maxActionAgeMs`, `maxChainLength` (server ceilings; library defaults 5 min, 60 s, none, 64) and pin `humanPrincipal`, `witnesses`, `threshold`. A request may only TIGHTEN a bound (a looser value is `400`, not clamped), may omit or repeat a pinned anchor but not contradict it (`threshold` may only be raised), and any unrecognised `trust` field is `400`. An anchor the server does not pin is refused with `400` (R4-15) unless the operator sets `auth_config.pca.mesh.allowCallerAnchors: true` (library-calculator mode, where the verdict is only as trustworthy as the caller's own configuration). The response carries `trust_anchors`: `server_pinned` or `caller_supplied`. |
| `POST /v1/pca/mesh/ledger/consistency` | Check an RFC 9162 append-only consistency proof. For a size-0 old tree, `old_root` must be the empty-tree root MTH({}) = base64url(SHA-256 of the empty string), which `GET /v1/pca/ledger` publishes for an empty log, and `proof.path` must be empty. `''` is not the empty-tree root and is refused (`consistent: false`). |

> **Breaking change.** The routes `POST /v1/pca/payment-mandates`, `POST /v1/pca/payment-mandates/pcactn`, `POST /v1/pca/mesh/proofs` and `POST /v1/pca/mesh/witness` have been removed. They accepted a signing secret key (`principal_secret`, `signer_secret`, `leaf_secret`, `witness_secret`) in the request body, which any TLS-terminating proxy, APM body capture or crash dump could observe; and a witness that hands its key to a third party is not an independent witness. They now return `404`. Sending a `*_secret` field to a remaining route returns `400` (unknown field). Do the signing on the client with `@atlasauth/pca-payments` and `@atlasauth/pca`, and use the hosted routes only to decide, verify or check consistency.

```ts
import { generateKeyPair, encodeKey, mesh } from '@atlasauth/pca';
import { buildPaymentMandate, authorizeCharge, chargeToPCActn } from '@atlasauth/pca-payments';

const principal = generateKeyPair();
const agent = generateKeyPair();

// Build and sign locally; secrets never leave your process.
const mandate = buildPaymentMandate({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agent.publicKey),
  merchants: ['m1'],
  currency: 'USD',
  perTransactionCap: 100,
  autoApproveThreshold: 50,
  cumulativeCap: 1000,
});
const charge = { merchant: 'm1', amount: 10 };
// The decision is bound to the grant you verified or stored (here: the one you just built); the hosted route looks the
// mandate's grant up in the instance's registered grants and refuses terms/policy that differ from it.
authorizeCharge(mandate, charge, mandate.grant).outcome; // 'auto' (same decision as POST /v1/pca/payment-mandates/authorize)

// Sign the charge as the agent, then submit the PCActn to POST /v1/pca/actions.
const { pcactn } = chargeToPCActn(mandate, charge, { signerSecret: agent.secretKey, aud: '<instance id>', counter: 1 });

// Mesh: assemble locally (leaf key stays with you); verify locally or via POST /v1/pca/mesh/proofs/verify.
// const proof = mesh.assembleMeshProof({ chain, hops, action, leafSecret });
// mesh.verifyMeshProof(proof, trust);
// Witnesses run their own `new mesh.MeshWitness(secret)` in their own process.
```

## Signature suite policy (`pca.allowedSuites`)

The hosted verifier accepts only the signature suites on the instance's **effective suite list**. SECURE DEFAULT (BREAKING, R4-11): when `auth_config.pca.allowedSuites` is unset the list is `ed25519` plus every hybrid suite that includes Ed25519 (`hybrid-ed25519-ml-dsa-65`, `hybrid-nested-ed25519-ml-dsa-65`, `hybrid-ed25519-slh-dsa-sha2-128f`, `hybrid-ed25519-ml-dsa-87`, `hybrid-ed25519-slh-dsa-sha2-256s`, `hybrid-ed25519-less-cat1`). Pure post-quantum suites (`ml-dsa-65`, `ml-dsa-87`, `slh-dsa-sha2-128f`, `slh-dsa-sha2-256s`, `fn-dsa-512`, `fn-dsa-1024`, `less-cat1`) are refused until the operator lists them. A listed pure-PQ or hybrid suite must still satisfy the `holder_pq` binding (the signer's `pq_pk` is the one its parent committed to) and, for a root, the issuer's PQ pin.

- **Where it applies.** PCActn leaf and every delegation hop on `POST /v1/pca/actions` (both the pre-database probe and the full verifier), the step-up cosign and reattest re-verification, grant roots on `POST /v1/pca/grants`, every hop of a mesh chain on `POST /v1/pca/mesh/proofs/verify` (refused in the verdict with `chain: signature suite '...' is not allowed on this instance`), and the `alg` of a principal beacon on `POST /v1/pca/beacons` (`400`).
- **Denials.** On `/actions` a disallowed suite is `401` `invalid_pcactn` (check `leaf_signature` or `cap_chain`) naming the suite. On `/grants` it is `400`.
- **Validation.** `PUT` of the instance config rejects a `pca.allowedSuites` that is not a non-empty array (at most 16, no duplicates) of known suite ids with `400` and param `pca.allowedSuites`. If an invalid list is ever found stored, every route above fails closed with `500` `INTERNAL`; it is never read as "unset" or silently narrowed. This includes a stored value that is not a list at all (a bare string such as `"ml-dsa-65"`, `null`, a number, an object) and a list with a non-string, empty or over-long entry (R5-API-07).
- **Discovery.** `GET /v1/pca/suites` returns `{ "object": "pca_suites", "allowed_suites": [...], "source": "default" | "configured" }`.
- **Migration.** Operators whose agents sign with a pure-PQ suite must set `allowedSuites` explicitly, for example `["ed25519", "hybrid-ed25519-ml-dsa-65", "ml-dsa-65"]`.

## Route summary

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /v1/pca/grants` | public | Register a signed Root Intent Grant |
| `POST /v1/pca/plans` | public | Commit a plan DAG under a grant |
| `POST /v1/pca/actions` | public | Verify a PCActn, anchor it, return a receipt |
| `GET /v1/pca/suites` | public | Effective signature-suite list (`pca.allowedSuites` or the secure default) |
| `GET /v1/pca/stepups/:id` | public | Poll a step-up |
| `POST /v1/pca/stepups/:id/cosign` | public (principal-signed) | Submit the principal-device share |
| `POST /v1/pca/stepups/:id/reattest` | public (attestation-verified) | Complete a held attested step-up with a fresh attestation |
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

Request also carries `holder_pop` (the holder key's proof of possession).

Quotas are tiered (R4-06). A grant whose issuer is an enrolled, active principal is `verified` and counts against `quotas.maxActiveGrants` (whole instance, verified grants only) and `quotas.maxActiveGrantsPerPrincipal` (per issuer key, default 1,000). An unverified self-registration (any key, no enrolment) is a separate, small tier: `quotas.maxUnverifiedGrants` (default 200) and `quotas.maxUnverifiedGrantsPerKey` (default 5), both counted over the last 24 hours, plus `quotas.unverifiedRegistrationsPerMin` (default 6 per client IP). Unverified input therefore can never consume the capacity of verified principals. The count and the insert are one transaction under an advisory lock, so concurrent registrations cannot overshoot a cap. A `429` names the quota that was hit.

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
- `202` `{ ...stepup view, "result": "reattestation_required", "reason", "reattestation": { nonce, epoch, grant_ref, holder, action_digest, issued_at, expires_at } }` when the quorum is met but the action's attestation is no longer fresh. The step-up stays `pending` with its cosignatures; complete it with `POST /v1/pca/stepups/:id/reattest`.

### `POST /v1/pca/stepups/:id/reattest`

Public, self-authenticating (the attestation must verify). Request `{ "attestation"?: {...}, "action_digest"?: "..." }`. Without `attestation` it returns the outstanding fresh-nonce challenge (`202`, same shape as above; an unexpired one is reused). With `attestation` and `action_digest` (the step-up's) it admits the held action exactly once: `200` `{ ...stepup view, "allow": true, "verdict", "receipt" }`. `409` `{ "result": "reattestation_rejected", "reason" }` with `reason` one of `action_digest_mismatch`, `no_outstanding_challenge`, `attestation_nonce_mismatch`, `attestation_nonce_expired` (a fresh challenge is returned alongside); `403` `reattestation_rejected` when the evidence does not verify (step-up stays pending); `409` also when the quorum is not met, the requirement no longer applies, or the step-up is not pending. See [Anti-replay](./anti-replay.md).

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

Auth: `sk_` `pca:write`. A `context_attestation` signed by one of these keys covers `(instance_id, grant_ref, action digest, counter, subject, env, issued_at)` under the domain tag `atlas-pca/context/v2` (R4-08; v1 attestations no longer verify). Body `{ "trusted_attestor_keys": [...] }`: up to 50 base64url Ed25519 public keys (32 to 128 characters of `[A-Za-z0-9_-]`). Replaces the list; returns the saved list. Audited as `pca.attestors.updated`. Attestation is enforced for an action only when this list is non-empty and the action presents an attestation.

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
