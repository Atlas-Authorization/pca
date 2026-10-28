# T6: `authorize` for the remaining native SDKs (Go, Rust, Java, Kotlin, .NET, PHP, Ruby, Swift)

Python is done (`sdks/python-pca/atlas_pca/authorize.py`; since B3 (0.5) it is also the default of the guards). Mirror it mechanically. Every
port reuses its own core verifier and its existing 0.4.1 caveat evaluator (`policy_caveats` / `evaluate_caveats`);
only the pieces below are new.

## 1. API shape (names in each language's case)

```
authorize(pcactn, AuthorizeInput{ operation, audience, resolveGrant, stateStore, isRevoked,
                                  now?, plan?: "single-step", context?, intentPolicy?, intentV2?, allowedSuites?,
                                  require?: []string }) -> AuthorizeResult
Operation        { verb: string, resource: string, params: JSON object }      // from the server, never the PCActn
AuthorizeResult  { allow, status (200|401|403), checks: map name -> "pass"|"fail"|"not-enforced",
                   reasons: []string, reason (decisive), operation?: { verb, resource, params_digest, id },
                   missing?: []string }
StateStore       claim(key string, counter uint53) -> ClaimResult{ ok bool, lastCounter? }   // ONE atomic op
MemoryStateStore (mutex), plus one durable reference where the ecosystem has one (SQLite / DB upsert)
isRevoked(pcactn, grant) -> bool     // only `false` passes; error or anything else denies
isAuthorizedFor(result, operation) -> bool
evaluateAgentCaveats(caveats, ctx, actionCtx, toolCall) -> (ok, failedTypes)
evaluateToolSchema(caveat, {tool, args, toolSignatureDigest?}) -> (ok, reason)
readEnvelope(grant), rootCaveats(grant)
```

Middleware: an additive option (`Authorize`/`authorize`) holding `stateStore`, `isRevoked`, `plan` (default
`single-step`), `context`, `require`, plus an operation mapping `(request) -> Operation | null`. 0.5 (B3): authorize mode is the default; no option refuses with `authorize_config`; signature-only is an explicit opt-in.
Native middlewares: Go `RequirePCA`, Java `PcaFilter`, .NET `PcaMiddleware`, PHP `PcaMiddleware`, Ruby Rack, Rust axum.

## 2. Pipeline (exact order; first failing reason is reported, `operation` first in `reason`)

1. Config: `audience` non-empty, `resolveGrant`, `stateStore` with `claim`, `isRevoked`; `plan` only `single-step` or
   absent. Missing -> 403, check `authorize_config`, `missing` = names in that order. Then `operation` (verb,
   resource non-empty strings, params an object) -> else 403 `operation`. Copy the params (canonical round trip).
2. Parse: absent / undecodable -> 401 `wire`. `grant_ref` not a string -> 401 `malformed`. `resolveGrant` error -> 403
   `resolve_grant`; unknown -> 401 `grant_ref`. `context` / `intentV2` callback error -> 403 `context` / `intent_v2`.
3. Core verifier (existing). Wire failure is terminal (401). Then `revocation` (`isRevoked`), then `zk_compliance`
   present -> fail (no verifier).
4. `operation`: signed verb/resource == operation's, else `params_digest(operation.params) == action.params_digest`.
   `grant_ref` == grant.id. `params_digest` (same digest). `plan_root_authorized`: single-step = one node `{id:
   String(plan.node_id), verb, resource, params_digest(op.params), reversibility_class: action's}`, Merkle root with
   default conditions must equal `plan.root`; or `context.plan` + `plan_authorized: true`; neither -> not-enforced.
5. `attestation`: envelope `agent_binding` has any pin (non-empty `model_allowlist` / `weights_allowlist` /
   `system_prompt_allowlist` / `tool_manifest_allowlist`, `min_measurement` present and not "", non-empty
   `operator`, `require_hardware` or `require_measured_weights` true) -> fail. `reversibility` when
   `context.reversibility_class` is given (rank reversible 0, rate_limited/costly 1, irreversible 2, unknown 2;
   declared < server fails; effective = declared if declared > server else server).
6. Action context: `{action: {verb, resource (signed), params: op.params, reversibility_class: effective}, subject?,
   env?}`; tool call `{tool: verb, args: op.params, toolSignatureDigest: pcactn.tool_binding?}`; caveat ctx `{now,
   action, delegation_depth: len(chain)-1, blast_radius?, reversibility_class (effective, else plan node by
   node_id), recent_action_times?}`.
   `delegated_caveats` = agent evaluator over `leaf.caveats[len(grant.caveats):]`.
   `policy` (one regex budget) = no envelope -> fail "grant carries no valid envelope"; else envelope predicates
   (any match, empty list denies), agent evaluator over envelope caveats, then over `rootCaveats(grant)`.
   Agent evaluator: `tool_schema` -> evaluateToolSchema; `predicates` -> any `allow` predicate matches the action
   context; everything else -> the existing stock evaluator (unknown type fails).
7. Required (must be `pass`): `counter, revocation, plan_root_authorized, audience, validity, grant_ref_bound,
   operation, params_digest, policy` + `require`. Any `fail` -> deny (401 if any of `wire, version, audience,
   validity, chain, grant_ref_bound, leaf_signature, malformed, grant_ref` failed, else 403).
8. Only then `claim("<grant.id>:<leaf holder>", counter)`: `ok` -> 200 with `operation.id = hash_canonical(pcactn)`;
   else `counter` fail "N is not greater than last seen M (replay)" (or "was already claimed", or "the replay store
   failed (fail closed)").

`tool_schema` port notes (TS `agent-native.ts`): closed schema keys per type, depth 8, 256 nodes, 64 props, 256 enum
values; string lengths in UTF-16 code units; integers are finite doubles with no fraction; `enum`/`const` use JS
`===` (a bool is never a number, numbers compare as doubles); `schema_digest` and `binding_digest` recomputed; key
presence (not null) decides optional members.

Not in scope for natives (documented in each README): risk score, trust budget, threshold co-sign, epochs, beacons.

## 3. Shared tests (same for every language)

1. `sdks/python-pca/testdata/authorize-fixtures.json` (`pca-authorize-fixtures/1`): 31 cases / 35 steps signed by
   the TS reference, each run against ONE fresh store: assert `{allow, status, sorted failing checks}` == `expect`
   and `{allow, status}` == `ts` (the TS `authorize()` outcome). Run once with the memory store and once with the
   durable store. Regenerate with `tsx packages/pca/scripts/gen-authorize-fixtures.ts` (from the repo root;
   records `ts` when `src/server/authorize.ts` is present).
2. `primitives.caveat_eval` (41 vectors) through the agent evaluator: identical to the stock results.
3. Fail closed: each missing component (exact `missing` list, resolver never called); invalid operations; no plan
   source; `isRevoked` returning null/0/"no"/throwing; store throwing or returning garbage; a denied action never
   reaches the store; callbacks throwing; `require` adds a check; zk proof refused.
4. Store: monotone claim table (5 ok, 5 replay(5), 4 replay(5), 6 ok, other key 0 ok, 0 replay(0)); 16 concurrent
   claims of one counter -> exactly one ok (threads, and processes for the durable store); 8 concurrent `authorize`
   of one proof -> one allow.
5. `tool_schema` unit table (Python `test_tool_schema_rules` / `test_tool_schema_caveat_integrity`: exact reasons).
6. Middleware acceptance, handler spy never called on a denial: $400 under $100 (403, reason `policy: caveat(s) not
   satisfied: max_spend`), $50 proof with a $400 body, proof for X on a route executing Y, replay, revoked, missing
   operation mapping (B3, 0.5: through the DEFAULT options; signature-only is the explicit opt-in).
7. Mutation check: remove each step of section 2 in turn; at least one test must fail (Python: `t6` report lists them).
