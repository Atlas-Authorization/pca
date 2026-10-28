# Protocol and identity front doors (track K6)

Specification text for the four wire additions that let existing protocols and identity products carry PCA. Sources and fetch dates are given per section; anything not fetched is marked. The public explanations are `concepts/positioning.md` and `guides/pca-grant-oauth.md`. Contract entries C-480 to C-491, threats T-580 to T-588.

Hard rule that applies to every item: nothing here lets a heuristic decide authorization. A hint (`pca_need`) never grants; a pointer (`pca_grant`) never authorizes; a ceiling only tightens; every unknown, unparseable or unevaluable input is a deny or an escalation.

## 1. `pca_need`, the argument-aware step-up parameter

Source for the extension point: MCP authorization, "Runtime Insufficient Scope Errors" (2025-11-25, 2026-07-28, draft): a server SHOULD answer 403 with `error="insufficient_scope"`, `scope` and `resource_metadata`, and "the required scopes may be determined dynamically based on the specific request arguments and context". Unknown auth-params are ignored by recipients (RFC 9110 section 11.2; RFC 6750 section 3 leaves error attributes extensible).

Wire. One extra auth-param on the `Bearer` challenge: `pca_need="<base64url(strict canonical JSON)>"`, at most 2048 encoded characters.

```
PcaNeed = { v: 1, kind: "scope" | "grant" | "discharge" | "escalate",
            verb, resource,                       // 1..128 / 1..512 chars
            scopes?: [token...],                  // at most 16, no whitespace: the plain `scope` fallback
            grant_ref?, policy_digest?,
            limits?: { name: number >= 0 },       // residual envelope (advisory), at most 16
            discharges?: [{ issuer, claim }],     // at most 16
            tier?: 2 | 3 }                        // required iff kind = "escalate", forbidden otherwise
```

Rules. Unknown members are refused. A malformed value is a typed failure and the client uses the `scope` parameter as before. A server that cannot build a valid need omits it and returns the unchanged 403. `pcaNeedDigest(need)` (domain `atlas-pca/need/v1`) is the content address an approval flow cites. The client shows every field as untrusted text and never approves on its own. Implementation: `@atlasauth/pca` (`encodePcaNeed`, `decodePcaNeed`, `pcaNeedFromChallenge`), `@atlasauth/pca-mcp-rs` (`admitRequest` adds it to the `insufficient_scope` denial by default; `pcaNeed: false` omits it; a function supplies a richer need), `@atlasauth/pca-oauth` (`wwwAuthenticate({ pcaNeed })`), `@atlasauth/pca-mcp` (`planStepUp`).

Scope-union mapping. MCP 2026-07-28 and draft have the client compute the union of its earlier scopes and the challenge scopes. PCA's narrowing-only rule means a re-authorization replaces a grant with a new principal-approved id (`supersedes`) and never silently merges: the union is what a stock client sends to its authorization server; the PCA flow produces a new grant.

## 2. MCP conformance matrix

Sources (fetched 2026-10-26 from the `modelcontextprotocol/modelcontextprotocol` repository, main at 54b91cdb, `docs/specification/<revision>/basic/authorization`; published at modelcontextprotocol.io/specification/<revision>/basic/authorization): revisions 2025-03-26, 2025-06-18, 2025-11-25, 2026-07-28 and draft. From 2026-07-28 the text is split into `index`, `authorization-server-discovery`, `client-registration` and `security-considerations`; the draft was last changed 2026-09-22 in that directory and must be re-fetched before it is relied on.

Differences that matter to the rows: PRM (RFC 9728) and the `WWW-Authenticate` `resource_metadata` start in 2025-06-18; RFC 8707 audience validation and the "MUST NOT accept or transit any other tokens" sentence start in 2025-06-18; `insufficient_scope` (SHOULD) and the scope in the first 401 (SHOULD) start in 2025-11-25; CIMD is SHOULD and DCR MAY and deprecated from 2025-11-25 (the older comment in the resource-server package that DCR "is gone" in 2026-07-28 was wrong: it is deprecated and retained); the RFC 9207 `iss` table, "all scopes in a single challenge" (SHOULD), the scope-union step and "Servers MUST account for scope hierarchies" start in 2026-07-28. The authoritative table is `MCP_AUTH_RS_ROWS` and `MCP_AUTH_CLIENT_ROWS`; each non-`n/a` cell has a check.

Not covered by a row: client registration (CIMD, DCR) and authorization-server discovery are authorization-server and client-library requirements; `verifyCimd` has its own tests in `@atlasauth/pca-mcp-rs`. The `client_id_metadata_document_supported` flag is defined on authorization-server metadata; the resource-server package also puts it in the protected resource metadata, where it is not a defined field (harmless, unspecified).

## 3. `pca_grant` authorization details (RFC 9396)

RFC 9396 section 2 allows API-defined types; section 2.2 defines the common members `locations`, `actions`, `datatypes`, `identifier`, `privileges`; RFC 9728 section 2 defines `authorization_details_types_supported` on protected resource metadata.

Detail: `{ type: "pca_grant", chain_digest, chain_len, chain_ref?, bundle_revision?, locations? }`.
- `chain_digest = base64url(sha-256(strict-canonical({"d":"atlas-pca/pca-grant-chain/v1","ids":[<capability ids, root first, chain_len of them>]})))`, unpadded, canonical.
- `chain_len` 1..16. `bundle_revision` a non-negative safe integer. `locations` 1..8 https URLs. `chain_ref` an https URL.
- https URL rule, identical in every implementation: starts `https://`, only printable ASCII (0x21 to 0x7e) without `#` or `\`, at most 2048 characters, a non-empty authority up to the first `/` or `?`, no `@` in the authority.
- Refused members: `actions`, `datatypes`, `identifier`, `privileges`; any member not listed is `unknown_member`.
- Array: at most 16 entries; non-object or untyped entry `bad_entry`; entries of other types skipped; one bad `pca_grant` entry refuses the array.

Resource server: allow only if (a) the details parse, (b) a verified per-action PCActn is present, (c) some detail's `chain_digest` equals the digest over the first `chain_len` ids of the presented chain (attenuation appends hops, so a delegated chain matches), (d) the detail's `locations`, when present, include this resource. Otherwise the first failing code: `no_detail`, `proof_required`, `chain_mismatch`, `wrong_location`. The check does not authenticate the token; the caller does.

Authorization servers. Atlas implements RFC 9396 with a per-instance type allowlist and returns the stored details in token responses and introspection; it validates the type, not the shape. Auth0 documents RAR with type-only validation. Read on 2026-10-26: Microsoft Entra ID's authorize-endpoint parameter table (learn.microsoft.com, v2-oauth2-auth-code-flow, updated 2026-06-15) lists no `authorization_details` and its discovery document has no `authorization_details_types_supported`; WorkOS AuthKit's published metadata (workos.com/docs/authkit/mcp) lists none; the Stytch Connected Apps guide and the Descope agentic-identity overview do not mention it (the Descope page was truncated when read). These are absences in public documentation, not tests of the services. Vectors: `pca-grant-vectors.json` (68 cases) in TypeScript, Python, Go, Rust, Ruby, PHP, Java, Kotlin, .NET and Swift.

## 4. A2A binding

Source: A2A protocol specification, `docs/specification.md` and `specification/a2a.proto` at main 98279d62 (2026-10-20), read in full this time: sections 3.1.7, 3.1.11, 3.3.2, 3.5, 4.1 to 4.6, 7, 8.4, 13. The earlier gap note cited a `security` field and AUTH_REQUIRED mapping; the current wire names are `securitySchemes` and `securityRequirements` on the card, `TASK_STATE_AUTH_REQUIRED` and `ROLE_USER` / `ROLE_AGENT`, and a push config `token` field. The existing structural types in `@atlasauth/pca-a2a` predate that (`role: "user" | "agent"`, `kind`); the new functions read the 1.0 state names and also accept the pre-1.0 `auth-required`.

- Extension. Declared in `capabilities.extensions` (A2A 4.4.4, 4.6.1) with the URI `https://atlasauth.net/a2a/ext/pca/v2`, `required` true or false, `params: { aud, suites?, grants? }` (grants are `pca_grant` pointers). A required extension with a client that did not opt in (`A2A-Extensions`) is the A2A `ExtensionSupportRequiredError`. One declaration only; unknown params refused.
- AUTH_REQUIRED (A2A 7.6). The agent sets state `TASK_STATE_AUTH_REQUIRED` and a status message whose metadata carries the encoded need under `<uri>#need`. 7.6.4: the state authorizes nothing and a credential obtained meanwhile must not be assumed to authorize later messages. So the answer is a message carrying a PCActn for exactly the need's verb and resource plus the need's digest; the full verifier decides; a task in any other state never resumes. INPUT_REQUIRED stays a clarification.
- Delegation across hops. Each hop verifies its own PCActn for its own audience; the chain must extend the previous hop's chain; first failure names the hop.
- Push (3.1.7, 13.2). The per-task token is `H({"d":"atlas-pca/a2a-push/v1","task_id","chain":<chain digest>,"salt"})` with a secret salt of at least 16 characters; the receiver recomputes it (constant time) and checks the payload is about that task. An authentic update is a report, not authority for the next workflow step.
- Anti-enumeration (3.3.2, 13.1): `uniformTaskNotFound()` is the one answer for unknown and unauthorized tasks.
- Extended Agent Card (3.1.11, 13.3). `extendedAgentCard(publicCard, { authenticated, hiddenSkills, envelopes })` takes the `whatMayIDo` envelopes computed for the caller's chain and reveals a hidden skill (tagged `pca-verb:<verb>`) only when its verb is autonomous or needs-approval; denied, unmapped and untagged skills are absent, so absence looks the same as non-existence. One policy digest for all envelopes, recorded in the PCA extension `params.policy_digest`; the derived card is unsigned and must be re-signed.
- Signed receipts. A receipt is `{v:1, task_id, state, seq, prev, chain, issued_at, signer, sig}` signed under `atlas-pca/a2a-receipt/v1` + NUL; `prev` is the digest of the previous receipt, `chain` the `pcaChainDigest` of the authorizing chain. `checkReceiptChain` requires sequence from 0, digest links, same task and chain, nothing after a terminal state; `mayTriggerNext` is true only for a verified chain ending in COMPLETED. Carried on status metadata under `<uri>#receipt`.

## 5. Agent blueprints

Prior art: Microsoft Entra Agent ID (blueprint, agent identity, group disable; docs linked from the positioning page). Design: an operator-held blueprint key is the holder of one hop and the issuer of each instance hop, so "instance of blueprint B" is "a chain with a hop issued by B's key"; no new caveat type (an unknown caveat refuses a chain, and a new type would have to go through the caveat-language vectors).

Record (domain `atlas-pca/agent-blueprint/v1` + NUL, strict canonical body, Ed25519 by `operator`): `{ v: 1, id, key, ceiling: [caveat...] (at most 32), max_depth? >= 1, expires_at?, epoch, status: "active" | "disabled", issued_at, operator }`.

Registry: pinned operator keys; a record replaces the stored one only with a strictly higher epoch; same epoch and a different signature is `epoch_fork` (refused); an older epoch `stale_epoch`; a different operator for a known key `operator_changed`; the identical record again is a no-op.

Check, per hop whose issuer is a registered blueprint key: the previous hop must have made the key a holder (`broken_link`), status active (`blueprint_disabled`), not expired (`blueprint_expired`), depth `chain.length - i <= max_depth` (`too_deep`), and the ceiling satisfied (`ceiling_violated`). A non-empty ceiling that cannot be evaluated denies (`ceiling_unevaluable`): the reference needs an action or an evaluator, the native verifiers (Python, Go) always deny a non-empty ceiling. Mode `require` demands at least one blueprint hop. `minEpoch` (the revocation epoch of a `fresh_at` token) makes a lagging registry escalate. A throwing store denies.

Group kill: the operator signs the record `disabled` at epoch + 1; the verifier accepts it, revokes the key as an `issuer` in the revocation registry and advances the verifier's `fresh_at` revocation epoch. Re-enable needs a still higher epoch. Composition with grant management: the host calls its grant service's revoke for the instances it tracks; the blueprint kill does not depend on that list, which is the point for never-seen instances.

Attestation-gated admission. A record may carry `runtime_pins` (1 to 16 pins; each pin names at least one of `runtime_measurement`, `model_id`, `weights_digest`, `operator`). `admitBlueprintInstance` calls an existing `HardwareAttestationVerifier` (SEV-SNP, TDX, Azure MAA, Confidential Space, NVIDIA or the multi-root verifier) and admits only when the result is ok, bound to the expected holder, grant and nonce, measured, and equal to a pin on every field the pin names; everything else denies. `AdmissionRegistry` keeps admissions per instance key and blueprint epoch with an expiry; `checkBlueprints` denies a pinned blueprint without `admitted` (`admission_required`) or with a false answer (`not_admitted`). The native verifiers do not read `runtime_pins`, so they refuse such a record (bad signature over the body they rebuild). Evidence adapters: `eatAdmissionEvidence` (`@atlasauth/pca-attest-eat`: EAT signature, issuer, nonce and age, RATS appraisal at tier `affirming` or better, `cnf.jkt` equal to the RFC 7638 thumbprint of the instance key; identity = the measured identity) and `spiffeAdmissionEvidence` (`@atlasauth/pca-spiffe`: X.509 or JWT SVID verified against the trust bundle and bound to the instance key by `svidToHolder`; identity = `{ spiffe_id }`) feed `admitWithEvidence`; a pin may name `spiffe_id`. Unverifiable evidence is a deny.

- Native verifiers. `a2a-vectors.json` (89 checks) carries typed-need decoding with digests, chain extension, the resume gate, push tokens and checks, and signed receipts with chain scenarios, generated from the reference with hand-written expectations cross-checked. All nine natives replay it. The full per-hop PCActn verification is the ordinary verifier's.

## 6. Scopes derived from the action (MCP and OAuth side)

Reference behaviour (from the second gap analysis, item 31): the scopes a credential may carry come from the reviewed action's upstream declaration, not from the caller and not from the grant alone; an unconfirmed action releases nothing. `ScopeAction { verb, def_digest, confirmed, upstream: { provider, scopes_min } }` is the shape K7's vault (`VaultAction` in `@atlasauth/pca-connect`) uses; this track adds the MCP and OAuth scope side on the same fields. `deriveActionScopes(action, { provider?, granted? })` returns the sorted, deduplicated `scopes_min` or a refusal (`unknown_action`, `unconfirmed`, `provider_mismatch`, `no_scopes`, `bad_scope`, `exceeds_grant`); scope tokens follow RFC 6749 section 3.3. MCP: `admitRequest({ toolActions })` takes a listed tool's required scope from the action and refuses (403 `forbidden`) when none can be derived; the first 401 then carries no fallback scope. OAuth: `oauthScopeForAction(action, { provider, granted, resource })`. `confirmed` is the operator's computation from the signed review (`effective(def, registry, {attestationVerified}).confirmed`); ActionDef itself has no `upstream` member in this tree, so the mapping is pinned by the operator, as in K7.

## 7. Open items and unverified claims

- RAR support at Stytch, WorkOS, Descope and Microsoft Entra ID: no documentation shows it (read 2026-10-26); a live test against each service was not done.
- Entra, AgentCore and Keycard behaviour is as their documentation states, read through search summaries, not the full pages.
- The Rust, Java, Kotlin and Swift `pca_grant` tests were written but not run in this environment (the Swift module compiled; Python, Go, Ruby, PHP and .NET suites were run and pass); CI is their first run.
