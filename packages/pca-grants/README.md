# @atlasauth/pca-grants

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

The operational plane of Proof-Carrying Authority: the pieces a deployment needs around the verifier.

| You want | Use |
|---|---|
| A revoke or restriction to be ordered before any later decision (the "new enemy" problem) | `signFreshAt`, `checkFreshAt`, `FreshAtIssuer`, `gateDecision` |
| "Which objects may this agent touch?" without scraping | `listAuthorized`, `verifyListReceipt`, `WindowReadAccumulator` |
| One signed policy revision that every decision cites | `signBundle`, `assembleBundle`, `verifyBundle` |
| An auditable decision log you can stream and prove against | `DecisionLog`, `nextBatch`, `verifyBatch`, `verifyRecordInclusion`, `semanticDiff`, `auditReplay` |
| List, inspect, amend, revoke and incrementally extend a principal's grants | `GrantService`, `grantResourceHandler`, `createGrantClient`, `grantManagementMetadata` |

```sh
npm i @atlasauth/pca-grants
```

```ts
import { FreshAtIssuer, gateDecision } from '@atlasauth/pca-grants';

const issuer = new FreshAtIssuer(secretKey, 'inst_1', { revocation_epoch: 5, ledger_tree_size: 100, budget_version: 7, policy_revision: 3, policy_digest });
const token = issuer.advance({ revocation_epoch: 6 }, Date.now()); // returned by the revoke call
// later, on a request that carries `token`:
const verdict = issuer.check(token, Date.now());
const decision = gateDecision('allow', verdict); // 'allow' | 'escalate' (stale_state) | 'deny'
```

Rules that hold throughout: a stale or unverifiable state is never an allow; a widening is never in place (it needs the principal's signature over the current revision and a step-up, and mints a new grant id); a relationship can only narrow a capability; everything signed is domain-separated strict-canonical JSON under Ed25519 and verifies without throwing.

The consistency token is also a signed PCActn member (`buildPCActn({ freshAt })`, verifier policy `freshAt`). Shared conformance vectors for the native verifiers are `k3-vectors.json` and `fresh-at-vectors.json` in the core package's conformance directory.

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| A consistency token that is forged, for another scope, from the future or too old | denied; a verifier whose counters lag the token escalates (`stale_state`), never allows |
| `listAuthorized` with a forged, malformed or reused page cursor (changed subject, type, filter, policy or limit) | throws `bad_cursor`, nothing is returned |
| A page limit outside 1 to 500 | throws `bad_limit` |
| A read budget that is used up | throws `read_budget_exhausted` |
| A policy bundle that is malformed, below its signature threshold, older than the accepted revision, off the revision chain or needs a newer verifier | refused with a code (`malformed`, `below_threshold`, `rollback`, `broken_chain`, `verifier_too_old`); it does not throw |
| A decision-log batch with a gap, a replay, a reorder, an edit or a bad head signature | `{ ok: false, reason }` |
| An amendment that widens, changes nothing when it should narrow, is unsigned, or is signed by the wrong party | refused (`not_narrower`, `signature_required`, `bad_signature`); a widening also needs the principal and a step-up and makes a new grant |
| A needs approval that raises an amount, changes the target, lowers a non-adjustable need, or lacks the principal's signature | refused; nothing is granted |
| A revocation without the principal's signature or the host's admin authority | refused (`bad_signature`, or `forbidden` for a false admin flag) |
| A malformed authority (bad verbs, resources, ceilings or expiry), or a duplicate grant id | refused (`bad_request`, `conflict`) |
| A widening whose step-up check is missing, says no, or throws | refused (`step_up_required`, or the thrown error); the grant is unchanged |
| An incomparable change (neither wider nor narrower) | treated as wider: needs the principal and a step-up |
| A grant store that fails on write | the error surfaces; nothing is reported as granted |
| An HTTP caller that is not authenticated, or has neither a principal nor admin authority | 401 |
| A principal asking for another principal's grant, amendment, needs or need request | 404, the same answer as for a grant that does not exist |
| A lease that is malformed, unsigned, from an unpinned authority, past its cap, a renewal that does not extend or replays its reason, a fork, or breaks separation of duties | refused with a code (`bad_record`, `unknown_authority`, `over_max_ttl`, `not_extending`, `stale_justification`, `lease_fork`, `sod`); the lease routes map each to a 4xx |
| A lease store that is unreachable | `store_unreachable` (503 on the routes); `checkLease` denies |
| A lease presented after expiry, past its cap, revoked, superseded or unknown | `checkLease` denies with the matching code |
| A blueprint, break-glass or workflow record that is unsigned, from an unpinned operator, stale, forked, expired or out of budget | refused with a code; a registry that cannot be read denies |

## Leases and shadow rollout

- **Leases.** `signLease`, `LeaseRegistry` (`accept`, `revoke`), `checkLease`, `renewLease`, `leaseResourceHandler`. A lease is renewed only to a later expiry and never past `issued_at + max_ttl`; a renewal needs a new justification digest; approvers must be distinct and never the requester, the holder or a key in the holder's chain (`minApprovals` of n); revoke by lease, path prefix or grant blocks renewal. Pass an opened durable state as the registry's store for crash-safe storage.
- **Shadow mode.** A bundle revision may list `shadow` candidates. `runShadow` returns the enforced decision untouched and records what each candidate would have said; divergences are signed (`ShadowLog`); `promotionGate` needs zero unexplained widenings; `promoteShadow` builds the next revision for the bundle signers.

- **Agent blueprints.** `signBlueprint`, `BlueprintRegistry`, `checkBlueprints`, `groupKill`, `admitBlueprintInstance`. An operator-signed blueprint caps every instance made from it (tighten-only); one signed record at a higher epoch disables every instance, including ones the verifier never saw.
- **Break-glass.** `signBreakGlass`, `BreakGlassRegistry`, `signBreakGlassReview`. A signed, time-boxed (at most 24 hours), use-limited (at most 16) emergency window that requires notification and a signed review; an unjustified review freezes the holder.

## Limits

- It is the operational layer around a verifier, not a verifier. Every decision still belongs to the full server verifier with a grant from your own store.
- `MemoryGrantStore`, `MemoryBlueprintStore`, `memoryLeaseKv()`, the in-process read accumulator and the admission registry are for tests and single-process use. `LeaseRegistry`, `BreakGlassRegistry` and `BlueprintRegistry` have no default store (they hold revocations and kill records, which must survive a restart): the constructor throws without one. Production supplies durable, shared versions.
- A revocation or restriction is ordered only for requests that carry a consistency token and verifiers that honour it.
- The step-up verdict and the admin authority are inputs the host evaluates; this package does not authenticate people.
- The decision log proves what was logged, not that everything was logged.
- Needs and amendments are authorised by signatures and the host's step-up verdict; an HTTP caller's identity (`authenticate`) is the host's to get right.
- Lease and break-glass registries are only as durable as the key-value store you give them; the in-memory default is for tests.
- Break-glass access is bounded (window up to 24 hours, at most 16 uses) and must be reviewed; a registry records the review, it does not perform it.
