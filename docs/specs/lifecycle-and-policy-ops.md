# Lifecycle and policy operations (track K8)

Specification text for leases, shadow policy rollout, the strict CEL importer and decision obligations. Contract entries C-500 to C-515, threats T-600 to T-614. Roadmap items 35 to 38.

Hard rule: nothing here lets a heuristic widen authority. A lease can only be shortened by revocation and lengthened only by the authority's signature inside a fixed cap; a shadow policy never decides; a CEL construct that cannot be translated exactly is refused; an obligation nobody can perform turns an allow into a deny.

## 1. Leases

Sources: HashiCorp Vault lease concept (lease id and TTL, renew with an increment measured from now, revoke immediately and block renewal, revoke by prefix, revoking a token revokes its leases), https://developer.hashicorp.com/vault/docs/concepts/lease; Teleport access requests (approvers cannot approve their own request, configurable threshold), https://goteleport.com/docs/identity-governance/access-requests/. Entra PIM and Cloudflare Access were not fetched and are not relied on.

A lease authority signs a record (domain `atlas-pca/lease/v1`, strict canonical JSON):

```
Lease = { v: 1, lease_id, path, grant_ref, holder, requester, approvers[], justification_digest,
          seq, issued_at, renewed_at, expires_at, max_ttl, authority, sig }
```

- Issue: `seq = 1`, `renewed_at = issued_at`. Renewal: `seq + 1`, identical `path`, `grant_ref`, `holder`, `requester`, `max_ttl`, `issued_at` and authority; `expires_at` strictly later; `renewed_at` before the old `expires_at` (an expired lease is not renewed); `expires_at <= issued_at + max_ttl`; a different `justification_digest` (unless the registry sets `freshJustification: false`). The reason text is display-only; only its digest is signed.
- Check: only the newest stored record is live (an older record is `superseded` even inside its window), `renewed_at <= now < min(expires_at, issued_at + max_ttl)`, and no revocation covers it.
- Separation of duties on every issue and renewal: approvers distinct, none is the requester or the holder, none is in the holder's delegation chain (the caller passes the chain keys), all are in `eligibleApprovers` when pinned, at least `minApprovals` (k of n).
- Revocation (domain `atlas-pca/lease-revoke/v1`): by lease id, by path prefix (segment boundary), or by grant. It covers leases with `issued_at <= revoked_at`; a lease issued afterwards under the same prefix is a new lease. A revoked lease cannot be renewed.
- Automatic renewal (`renewLease`) takes a veto callback (learned or behavioural signals can refuse a renewal, never lengthen one) and records one ledger entry per renewal (`history`).
- Storage: sharded. A lease lives in the shard its id hashes to (SHA-256, first four bytes, modulo the shard count, default 16), so an issue, renewal or check reads and writes one small document; a prefix or grant revocation is written to every shard and a lease revocation to its own; the shard count is pinned in the store and a store opened with another count is refused. `LeaseKv` is structurally the durable state of `@atlasauth/pca/durable-state` (crash-safe, tamper-evident, one value per shard under its size limit); `memoryLeaseKv` is the default. With a `maxTtlCeiling`, revocations older than the ceiling are pruned and a longer `max_ttl` is refused (`ttl_ceiling`). `runLeaseStoreConformance` is the conformance kit for any store: spread, atomic update, independence, revocation placement, pinned shard count, restart, pruning. Hosted routes: `POST /pca/leases` (issue or renew, admin), `GET /pca/leases/:id`, `POST /pca/leases/:id/check`, `POST /pca/leases/revoke` (`leaseResourceHandler`, `leaseManagementMetadata`). The server stores only records the authority signed.
- Conformance: `lease-vectors.json` (31 scenarios) in the reference and the nine native verifiers (`verifyLease`, `LeaseRegistry`, `checkLease`, `sodError`, `pathUnder`).

The lease is a signed record beside the grant, not a new caveat type, so no caveat vector changes.

### Break-glass grants

A pre-authorized, sealed, small-budget grant for an emergency, with a mandatory review after the fact (`breakglass.ts`, `break-glass-vectors.json`, nine natives).

```
BreakGlass = { v: 1, id, holder, grant_ref, reason_digest, max_uses (1..16), issued_at, expires_at (<= issued_at + 24 h),
               review_within (1 ms .. 30 d), notify_to, authority, sig }       domain atlas-pca/break-glass/v1
Review     = { v: 1, id, outcome: "justified" | "unjustified", notes_digest, at, reviewer, sig }   domain atlas-pca/break-glass-review/v1
```

- `reason_digest` binds the stated reason into the signed record (the text is display-only), the way a request carries a `reason_digest` for the approver.
- Time-boxed and budgeted: past `expires_at`, past `max_uses`, or after an `unjustified` review the grant is dead (auto-revoked).
- Loud: a use is recorded (numbered, timestamped, bound to the action digest) only when the enforcement point reports that it delivered the notification to `notify_to`.
- Mandatory review: the first use starts the clock `review_within`. With no signed review when it runs out, or after an `unjustified` review, the HOLDER IS FROZEN: no use of any of their break-glass grants and no new one. The reviewer is a pinned key that is neither the holder nor the issuing authority; the first review is final; a late `justified` review lifts an overdue freeze.
- State is sharded by holder over the same key-value contract as leases, so a holder's grants, uses, reviews and freeze status are one atomic document.

## 2. Shadow policy rollout and the CEL importer

Sources: Kubernetes ValidatingAdmissionPolicy (`validationActions` Deny / Warn / Audit; Deny and Warn cannot be combined; `failurePolicy`), https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/; Google IAM Conditions (CEL subset; a deny condition applies when true or when it cannot be evaluated), https://docs.cloud.google.com/iam/docs/conditions-overview. The CEL language definition was taken from the published specification of the language; the grammar subset below is this project's own decision.

Shadow mode:

- An enforced bundle revision may carry `shadow: [candidate bundle digest]` (covered by the bundle signature, at most 16, no duplicates).
- `runShadow(input, enforced, candidates)` returns the enforced decision, computed first and untouched, and each candidate's answer on a copy of the input. A candidate failure is `error`. The decision record carries `shadow: [{digest, decision, diverged}]`. Each divergence is a verifier-signed `ShadowDiff` (domain `atlas-pca/shadow-diff/v1`).
- `promotionGate` passes only with enough observations, zero candidate failures, all diffs verifying for this (candidate, enforced) pair, zero unexplained widenings (a principal-signed `WideningExplanation` per widened action), and, when the analyzer's verdict on the declared surfaces is `wider` or `unknown`, a principal-signed `PromotionApproval`. `promoteShadow` then builds the body of the next revision (candidate content, `prev` = enforced digest, no shadow list); the pinned signers sign it like any bundle revision. Audit never lets a request through because audit never decides.

Strict CEL importer (`@atlasauth/pca-policy-bridge`): `celToCondition(expr, schema)`, `celToPredicate`, `celConditionsToPca` (a `BridgeResult` whose `report.errors` makes `decide` deny everything). The subset, the rejected list and the exactness argument are in the module header; the differential test evaluates the parsed expression with a reference CEL evaluator and the translation with the PCA evaluator over thousands of contexts, including missing and ill-typed values. The result is a PERMIT condition; use a CEL expression as a deny by evaluating it separately and treating `unknown` as deny.

Not in the trusted core: shadow evaluation, the log, the gate and the importer are rollout and analysis tooling beside the verifier. PCA's total predicate DSL stays the only evaluator.

Three more pieces of the same track:

- `bind_params_digest` (VAP `paramRef`): a `template_ref` carries either its `slots` or a `bind_params_digest` (the `hashCanonical` of the slot object), never both. The resolver is given the parameter object (registry `params`), must find one that hashes to the digest and passes the template's slot rules. The grant signature covers the digest, so the parameters cannot be swapped. Shared `policy-link-vectors.json`, nine natives.
- Typed missing context and stored-wins (SpiceDB caveats; roadmap item 36), source: https://authzed.com/docs/spicedb/concepts/caveats (stored values take precedence over request values; CONDITIONAL lists missing fields). `decideWithMissing` returns allow only on true; an undecidable condition becomes `escalate: missing_context <supplier>:<path>,...` (suppliers `principal`, `discharge_issuer`, `rs_observation`) or, when a gap can only be filled by the agent, a deny; a wrongly typed present value is `ill_typed_context`; `bindContext` makes the bound value win and turns a differing request value into `context_shadow`. `missing-context-vectors.json`, nine natives.
- Policy classes (NIST NGAC idea; not fetched): `DecisionRecord.policy_classes` and `decideClasses` name the classes consulted (constitution, regulatory, org, blueprint, user) with revision and digest; the decision is their meet and the record lists `denied_by` / `escalated_by`; no class consulted is a deny. `policy-classes-vectors.json`, nine natives.

## 3. Decision obligations

Source: OASIS XACML 3.0 core specification (OASIS Standard, 22 January 2013), https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html, fetched 2026-10-27, sections 7.2 and 7.18. What the text says and how this track relates to it:

- 7.2.1 base PEP: on Permit, "the PEP SHALL permit access only if it understands and it can and will discharge those obligations"; on Deny the PEP denies "only if it understands, and it can and will discharge" the obligations; NotApplicable and Indeterminate are undefined for the base PEP. 7.2.2 deny-biased PEP: Permit with obligations is permitted only if the PEP understands and can discharge them; every other decision is a denial. 7.2.3 permit-biased PEP is the mirror image.
- 7.18: obligations (mandatory) and advice (optional) are attached per effect (`FulfillOn` / `AppliesTo`: Permit or Deny) and reach the PEP only along evaluation paths whose result equals the final decision; an obligation expression that evaluates to Indeterminate makes the whole rule, policy or policy set Indeterminate.
- Therefore the PCA rule "an allow carrying an obligation the PEP does not support is a deny" is the XACML deny-biased PEP rule, adopted as the only PEP behaviour (there is no permit-biased PEP: a PEP that cannot discharge never permits). PCA differs from XACML on purpose: obligations ride on allow only (an obligation on a deny would never be needed, because a deny already refuses), advice is not modelled, and a malformed obligation list or supported-kind set is a deny (XACML's Indeterminate maps to deny in a deny-biased PEP). The spec text says nothing about how often real PEPs ignore obligations; this document makes no claim about that.

```
Obligation = { kind: "log" | "notify" | "redact" | "watermark" | "require_receipt", params?, due? }
  log {sink?}   notify {to}   redact {fields[]}   watermark {id}   require_receipt {}
```

Closed vocabulary; every parameter validated; unknown kinds, members and parameters are malformed; at most 16, no duplicates. `due` is epoch milliseconds.

- Carriage: `DecisionRecord.obligations` (signed with the record). Policy side: `collectObligations(rules, ctx)` adds the obligations of every rule whose condition is true or cannot be decided; `mergeObligations` is a union deduplicated and sorted by canonical key.
- PEP rule: `pepObligationGate(decision, answered, obligations, supportedKinds)`. An allow (or an escalate with a verified answer) with an unsupported kind, a malformed list or a malformed supported set is a deny; deny and unanswered escalate pass through. A resource server lists its kinds in `/.well-known/pca-configuration` as `obligations_supported`.
- After the action: `obligationOutcome(obligations, fulfilledIndexes, now)` reports the overdue ones as `obligation_unmet` with an `escalate` outcome (freeze or step-up). It never allows retroactively.
- Conformance: `obligations-vectors.json` (validate, merge, gate, outcome) in the reference and the nine natives.

Not in scope: the obligation performers themselves (redaction, watermarking, notification) belong to the enforcement point; this track defines only the vocabulary, the carriage and the rule for what an enforcement point must refuse.
