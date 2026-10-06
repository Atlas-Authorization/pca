---
title: Resource-server quickstart
order: 11
---

# Resource-server quickstart: verify PCA

> Preview. Hosted routes are off by default; verifying in your own service has no such gate.

Two options. Run the verifier yourself with `@atlasauth/backend`, or use the `/v1/pca/*` endpoints an Atlas-hosted resource server exposes.

## Option 1: verify in your own service

Both functions are exported from `@atlasauth/backend`. Verification is deterministic and offline; any internal error becomes a fail-closed deny (it never throws).

### `verifyPCActn(pcactn, opts)`

```ts
import { verifyPCActn } from '@atlasauth/backend';

// verifyPCActn(pcactn: PCActn | string, opts: VerifyPCActnOptions): Promise<PcaVerdict>
const verdict = await verifyPCActn(pcactn, {
  grant,                       // the Root Intent Grant (Capability) you resolved from pcactn.grant_ref
  hooks,                       // optional VerifyHooks, see below
  now: Date.now(),             // optional
  context: {                   // optional PcaContext
    params,                    // plaintext; MUST hash to action.params_digest; needed by predicates
    subject, env,              // inputs for predicate `where` clauses
    plan,                      // your copy of the committed plan; its Merkle root must equal plan.root
    risk,                      // Partial<RiskInputs> you can vouch for; missing inputs fail closed
    budget,                    // current TrustBudget for the leaf holder
    recentActionTimes,         // for rate-limit caveats
  },
});
// PcaVerdict: { allow, r, requiredThreshold: { t, proof, optimisticAllowed }, checks, reasons, budget? }
```

`checks` maps each clause (`version`, `cap_chain`, `plan_inclusion`, `leaf_signature`, `counter`, `grant_ref`, `params_digest`, `delegated_caveats`, `policy`, `threshold`, `budget`, ...) to `'pass' | 'fail' | 'not-enforced'`. `allow` is true only if nothing failed and the policy VM released the guardian share. If you passed `context.budget`, persist the returned `verdict.budget` on allow.

### `requirePCA(opts)`

A framework-agnostic guard, the PCA analogue of `requireAuth()`:

```ts
import { requirePCA, memoryPcaStore } from '@atlasauth/backend';

const guard = requirePCA({
  resolveGrant: async (grantRef) => grantsById.get(grantRef) ?? null,   // null = unknown grant
  hooks,
  budgetStore: memoryPcaStore(),         // implement PcaStateStore over Redis/DB in production
  context: (req, pcactn) => ({ params: req.body?.params }),
});

// guard(req: { headers, body? }) => Promise<PcaGuardResult>
const res = await guard(req);
if (!res.ok) {
  // res.status is 401 (authentication-class failure) or 403 (policy denial)
  // 401 carries res.wwwAuthenticate; res.verdict explains why
  return reply.code(res.status).header('www-authenticate', res.wwwAuthenticate ?? '').send(res.verdict);
}
// res.ok: res.verdict and the decoded res.pcactn
```

- Extraction (`defaultExtract`): header `PCA-Action: <base64url PCActn JSON>`, else JSON body `{ pcactn }`. Override with `extract`.
- Replay: with `budgetStore`, the counter must strictly increase per `grant.id:leafHolder`, and the budget is loaded and saved there. Without a store, counters are reported `not-enforced`. Use a shared store in any multi-node deployment.
- 401 (`WWW-Authenticate: PCA realm="pca", error=...`) covers missing/undecodable PCActn, unknown grant, and failed `version`, `cap_chain`, `leaf_signature`, `malformed` or `grant_ref` checks. Policy and threshold denials are 403.

### Injectable hooks (`VerifyHooks`)

A hook returns `{ enforced: false }` (reported `not-enforced`) or `{ enforced: true, ok, reason? }`. Anything you do not supply is not enforced, except that an action needing `t > 1` is denied unless a threshold verifier is enforced.

| Hook | Purpose | Helper in `@atlasauth/pca` |
|---|---|---|
| `threshold` | verify co-signers at the risk-derived `t` | `createThresholdVerifier({ signerSet, t?, requiredT? })` |
| `revocation` | non-membership of every capability id in the chain | `createRevocationChecker({ root, proofFor, ids? })` (fails closed) |
| `attestation` | agent runtime attestation (L0) | bring your own `AttestationVerifier` |
| `zk` | zero-knowledge proof of compliance | bring your own `ZkVerifier` |

```ts
import { createThresholdVerifier, createRevocationChecker } from '@atlasauth/pca';

const hooks = {
  threshold: createThresholdVerifier({
    signerSet: [
      { role: 'agent', publicKey: agentPub },
      { role: 'guardian', publicKey: guardianPub },
      { role: 'principal', publicKey: principalPub },
    ],
  }),
  revocation: createRevocationChecker({ root: () => trustedRevocationRoot, proofFor: (id) => proofs.get(id) }),
};
```

`signerSet` must register the agent role's key as the leaf holder. If you do not recompute risk yourself, pass an explicit `requiredT` rather than relying on the default, which reads the agent's own `risk_claim.r`. For golden test vectors to validate your own verifier, see [Verify in your language](./verify-in-your-language.md).

## Option 2: Atlas-hosted `/v1/pca/*`

### The gate

Everything is behind `auth_config.pca.enabled` (default `false`). When off, every public route returns `404 Not found` and does not reveal PCA exists. Related settings: `auth_config.pca.publicRateLimitPerMin` (default 60, per instance and IP, 429 when exceeded, `RateLimit-Limit`/`RateLimit-Remaining` headers) and `auth_config.pca.maxPlanNodes` (default 256).

### Authentication

Public routes resolve the instance from the `Host` header (like JWKS) and are self-authenticating: grants are signed by the principal, PCActns by the leaf holder, co-sign shares by the principal key. Admin routes (`revocations`, `freeze`, `stepups/:id/deny`, `attestors`; the last takes `pca:read` for `GET`) need a secret key: `Authorization: Bearer sk_...` with the `pca:write` scope (`pca:read` for ledger openings and listing trusted attestors). Both scopes are in the product scope catalog, so a scoped `sk_` key works (a `*` key does too).

### Endpoints

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /v1/pca/grants` | public | Register a signed Root Intent Grant. 201 on create, 200 if already registered. |
| `POST /v1/pca/plans` | public | Commit a plan DAG under a grant. 201. |
| `POST /v1/pca/actions` | public | Verify a PCActn, anchor it in the ledger, return a receipt. |
| `GET /v1/pca/stepups/:id` | public | Poll a step-up. |
| `POST /v1/pca/stepups/:id/cosign` | public (principal-signed) | Principal-device share. |
| `POST /v1/pca/stepups/:id/deny` | `sk_` `pca:write` | Deny a pending step-up. |
| `GET /v1/pca/ledger?grant_ref=` | public | Ledger head. |
| `GET /v1/pca/ledger/entries?grant_ref=` | public; `sk_` `pca:read` adds openings | Commits (and openings for the operator). |
| `GET /v1/pca/ledger/:index/proof?grant_ref=` | public | Inclusion proof. |
| `GET /v1/pca/claims/:id` | public | Poll an optimistic claim. |
| `POST /v1/pca/claims/:id/challenge` | public | Trigger re-adjudication of an open claim; slashes only if the server's own re-evaluation finds fraud. |
| `POST /v1/pca/revocations` | `sk_` `pca:write` | Revoke a capability id. |
| `POST /v1/pca/freeze`, `DELETE /v1/pca/freeze` | `sk_` `pca:write` | Instance-wide kill switch on/off. |
| `GET /v1/pca/attestors`, `PUT /v1/pca/attestors` | `sk_` `pca:read` / `pca:write` | Trusted software-attestor keys. |

Every route, with request and response shapes, is in the [API reference](../reference/api.md).

### Examples

Register a grant (`grant` is the object from `mintGrant`):

```http
POST /v1/pca/grants
{ "grant": { ...signed root capability... } }

201 { "object": "pca_grant", "grant_ref": "<grant.id>", "status": "active" }
```

Commit a plan (`nodes` need string `id`, `verb`, `resource`; 1 to `maxPlanNodes` nodes; grant must be active):

```http
POST /v1/pca/plans
{ "grant_ref": "<grant.id>", "nodes": [ { "id": "n1", "verb": "read", "resource": "doc:1" } ] }

201 { "object": "pca_plan", "plan_root": "<merkle root>", "grant_ref": "<grant.id>" }
```

Submit an action (`params`, `subject`, `env` optional, used for predicates; `params` must hash to the PCActn's `params_digest`):

```http
POST /v1/pca/actions
{ "pcactn": { ... }, "params": { "page": 2 } }

200 { "allow": true,  "verdict": { ... }, "receipt": { "index": 0, "commit": "...", "root": "...", "inclusion_proof": [...] } }
202 { "allow": false, "step_up_required": true, "stepup_id": "...", "required_t": 2, "verdict": { ... } }
401 { "allow": false, "verdict": { ... } }      // + WWW-Authenticate: PCA realm="atlas", error="invalid_pcactn"
403 { "allow": false, "verdict": { ... } }      // out of plan, policy, revoked, replayed counter, frozen
```

Poll and approve a step-up:

```http
GET /v1/pca/stepups/:id
200 { "object": "pca_stepup", "stepup_id": "...", "grant_ref": "...", "action_digest": "...",
      "required_t": 2, "status": "pending", "shares": ["agent"], "created_at": "...", "expires_at": "..." }
// status becomes approved | denied | expired; "receipt" appears once approved (pending steps expire after 15 minutes)

POST /v1/pca/stepups/:id/cosign
{ "role": "principal", "publicKey": "<grant principal key>", "sig": "<Ed25519 over thresholdMessage(pcactn), b64u>" }
202 { ...stepup view, "step_up_required": true }      // still short of required_t
200 { ...stepup view, "allow": true, "verdict": {...}, "receipt": {...} }   // threshold met, action re-verified and anchored
```

Only `role: "principal"` is accepted, and `publicKey` must equal the grant's principal key. The action is re-verified in full at approval; if it no longer passes (revoked, frozen, replayed counter) the step-up ends `denied`.

Ledger audit:

```http
GET /v1/pca/ledger?grant_ref=<ref>
200 { "object": "pca_ledger_head", "grant_ref": "...", "size": 12, "root": "..." }

GET /v1/pca/ledger/entries?grant_ref=<ref>
200 { "object": "list", "grant_ref": "...", "data": [ { "object": "pca_ledger_entry", "index": 0, "commit": "...", "shredded": false, "created_at": "..." } ] }

GET /v1/pca/ledger/0/proof?grant_ref=<ref>
200 { "object": "pca_inclusion_proof", "grant_ref": "...", "index": 0, "commit": "...", "root": "...", "inclusion_proof": [...] }
```

Anonymous entries are commits only. With a secret key holding `pca:read`, entries also include `opening` (salt plus the PCActn) unless it was shredded (`shredded: true`).

Revoke and freeze (secret key):

```http
POST /v1/pca/revocations   { "grant_ref": "<ref>", "cap_id": "<capability id>" }
201 { "object": "pca_revocation", "grant_ref": "<ref>", "cap_id": "<id>", "revoked": true }   // 200 if already revoked

POST   /v1/pca/freeze      { "reason": "incident 42" }   ->  200 { "object": "pca_freeze", "frozen": true }
DELETE /v1/pca/freeze                                    ->  200 { "object": "pca_freeze", "frozen": false }
```

Revoking a capability kills every descendant in any chain that includes it. While frozen, every action is denied.

The `@atlasauth/pca-agent` client speaks exactly these routes; point `rsBaseUrl` at the instance's frontend API host.

With an optimistic claim in the request body, an allowed reversible action returns `200 { allow: true, optimistic: true, claim_id, challenge_window_ms, verdict, receipt }` ([optimistic and ZK](../concepts/optimistic-and-zk.md)). Request bodies reject unknown top-level fields with a `400` naming the field.


Next: [Playground](./playground.md). Concepts: [policy and risk](../concepts/policy-and-risk.md), [ledger and revocation](../concepts/ledger-and-revocation.md).
