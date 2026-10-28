# Supply chain and guard authoring (track K9)

Status: implemented in the TypeScript reference; the provenance gates and the full Sigstore bundle verification are in the nine native verifiers (shared vectors). Security contract C-520 to C-532, threats T-620 to T-629. Every feature here only removes authority: provenance is a discharge a caveat requires, a trace rule is a caveat, a detector receipt feeds `tighten`. None adds a way to widen a grant.

Sources fetched 2026-10-27 (commits are the default-branch heads read that day):

- Sigstore bundle and trust root: sigstore/protobuf-specs 6d0a62a6 (`sigstore_bundle.proto`, `sigstore_rekor.proto`, `sigstore_common.proto`, `trustroot.proto`); client verification order: sigstore/architecture-docs 82f7d950 `client-spec.md` section 4; public-good trust root: sigstore/root-signing f39569f3 `targets/trusted_root.json`.
- DSSE PAE: secure-systems-lab/dsse b531b787 `protocol.md`. in-toto Statement v1: in-toto/attestation 50bf0171 `spec/v1/statement.md`.
- SLSA v1.0 provenance and verification: https://slsa.dev/spec/v1.0/provenance, https://slsa.dev/spec/v1.0/verifying-artifacts ("builder.id ... the sole determiner of the SLSA Build level"; consumers accept only specific signer-builder pairs).
- Fulcio certificate extensions: sigstore/fulcio 62a73e3f `docs/oid-info.md` (`.1.1` to `.1.6` raw UTF-8, `.1.8` onward DER UTF8String).
- RFC 9162 sections 2.1.1 and 2.1.3.2 (Merkle leaf, node and inclusion verification); RFC 6962 section 3.2 (precertificate SCT); transparency-dev/formats e55b160b `log/README.md` (checkpoint); rekor b939d42f `pkg/verify/verify.go` (SET payload: JCS of `{body, integratedTime, logID (hex), logIndex}`).
- GitHub: artifact attestations alone are SLSA v1.0 Build Level 2, reusable workflows can reach Level 3 (github/docs 9568e964 `artifact-attestations.md`); `actions/attest-build-provenance` buildType `https://actions.github.io/buildtypes/workflow/v1` (actions/toolkit 0c3a9c33).
- Invariant guardrails: invariantlabs-ai/invariant 2340fe2d README and invariantlabs-ai/docs d4747872 `mcp-scan/guardrails-reference.md` (`raise "..." if: (a: ToolOutput) -> (b: ToolCall)`, `->` = trace order, `x is tool:name`).
- Lakera Guard `POST /v2/guard`: docs.lakera.ai `api-reference/lakera-api/guard/screen-content` (`flagged`, `breakdown[].detected`; `flagged` is always false in `detect` mode).
- **UNVERIFIED:** Prompt Security's own API documentation could not be reached (re-tried 2026-10-27: prompt.security/docs 404, docs.prompt.security does not resolve). Two open-source integrations read different shapes: LiteLLM (BerriAI/litellm aa33b052) `{result: {prompt: {action, violations[]}}}`, NVIDIA NeMo Guardrails (`library/prompt_security/actions.py`) `{result: {action}}` (`block`, `modify`, default `log`). The adapter accepts both and is clean only when no present action is block or modify and no violation is listed. Rekor v2 entry formats and key ids were not checked; such bundles are refused.

## 1. Build provenance as a discharge

### 1.1 Discharge class `artifact`

`needs_discharge.issuer_class` and a `DischargePin.class` may now be `artifact` (caveat-language section 1). Class pinning is unchanged: an `artifact` pin discharges only a caveat that says `artifact`, and a `workload`, `org`, `human` or `model` pin never can. The class is in every native's list; the K1 corpus has artifact-class `discharge_verify` and `caveat_shape` entries.

`provenanceCaveat({issuer, min_level, source_repo?, builder_ids?, oidc_issuer?, require_runtime = true, bind = "action", ttl_ms = 300000})` builds:

```
{type:"needs_discharge", id:"provenance", issuer, issuer_class:"artifact", bind, ttl_ms,
 require:[{claim:"slsa_level",op:"gte",value:min_level}, {claim:"source_repo",op:"eq",...}?, {claim:"builder_id",op:"in",...}?,
          {claim:"oidc_issuer",op:"eq",...}?, {claim:"runtime_bound",op:"eq",value:true}?]}
```

### 1.2 Verification (`@atlasauth/pca-attest-eat` `verifySigstoreBundleCore` / `verifySigstoreBundle`, offline)

Input: a bundle (media types `application/vnd.dev.sigstore.bundle+json;version=0.2`, `;version=0.3`, `application/vnd.dev.sigstore.bundle.v0.3+json`) and `parseTrustedRoot(trusted_root.json)` (transparency logs: ECDSA P-256 Rekor v1 with id SHA-256(SPKI), Ed25519 Rekor v2 with id = C2SP note key hash SHA-256(host || 0x0A || 0x01 || key), host of `baseUrl`; CT logs ECDSA or RSA; Fulcio CAs; timestamp authorities). Order (client spec section 4), each failure a distinct code:

1. Shape: keyless only, a DSSE envelope with exactly one signature and payload type `application/vnd.in-toto+json` (`not_keyless`, `envelope`).
2. Exactly one entry from a pinned log; kinds Rekor v1 `dsse` 0.0.1, Rekor v1 `intoto` 0.0.2, Rekor v2 `hashedrekord` 0.0.2 (which must come from an Ed25519 log) (`tlog_count`, `tlog_kind`, `tlog_key`).
3. Time: every RFC 3161 timestamp must verify (CMS SignedData, TSTInfo `messageImprint` = hash of the raw signature bytes, signed attributes `contentType` and `messageDigest`, signature over the DER SET of signed attributes by the leaf of a pinned TSA chain valid at `genTime`, TSA `validFor`, timeStamping EKU) (`tsa`); a Rekor v1 SET must verify when present (`tlog_set`); at least one verified time (`no_verified_time`); the log key valid at each.
4. Inclusion: RFC 9162 over the canonicalized body; checkpoint signed by the log key with the same size and root and a non-empty origin; Rekor v2: the signature line named by the log host, Ed25519; witness co-signatures ignored (`tlog_inclusion`, `tlog_checkpoint`).
5. Certificate path leaf -> pinned CA at EVERY verified time (hybrid model, client spec 4.3), CA flags, leaf not a CA, code-signing EKU; an SCT from a pinned CT log when the root lists CT logs (`cert_chain`, `cert_time`, `cert_eku`, `sct`).
6. The entry body names this envelope: `dsse` payload hash, signature, certificate; `intoto` payload hash, double-base64 signature, base64 PEM key; `hashedrekord` digest = Hash(PAE), `signature.content`, `verifier.x509Certificate` (Rekor v2 spec 6.1.4, persisted-body variant) (`tlog_body`).
7. DSSE signature over `PAE(payloadType, payload)` under the leaf key (`signature`).
8. Identity: one SAN (URI or email); issuer `.1.8` or legacy `.1.1` (both present must agree); source `.1.12`, `.1.13`, `.1.14` (`identity`).
9. Statement v1 with sha256/sha512 subjects (`statement`); `verifySigstoreBundle` then reads the SLSA v1 predicate (`predicate`).

`verifySigstoreBundleCore` returns `{identity, oidc_issuer, source_*, predicate_type, subjects, signed_time (earliest verified time, s), rekor_log_index, rekor: v1|v2, timestamps: {tsa, set}}`; `verifySigstoreBundle` returns `BuildProvenanceFacts` with `integrated_time` = `signed_time`. Shared vectors `packages/pca/conformance/sigstore-vectors.json` (generator `packages/pca-attest-eat/scripts/gen-sigstore-vectors.ts`): the DSSE cases of sigstore-conformance acb38c9e (Rekor v1 and v2, TSA, expired certificate, SET outside validity, log-entry mismatch, missing proof), the npm provenance bundle, and mutations (witness-only checkpoint, reordered signature lines, empty origin, flipped log signature, no timestamp, flipped TSA signature, unpinned TSA, TSA pin ended, unpinned log, broken proof, TSA-only and SET-only v1). Natives must reproduce `ok` and the whole core.

### 1.3 The gate (`@atlasauth/pca` `provenanceGate`, all natives)

`provenanceGate({facts, policy, runtime?, now})`, `now` in unix seconds. Policy (closed): `roots[1..32] {oidc_issuer, identity | identity_prefix (>= 10 chars), builder_id, level 1..3}`, `min_level 1..3`, `source_repo?`, `source_ref? | source_ref_prefix?`, `build_types?[1..16]`, `max_age_s?`, `require_runtime?`. Order and codes: `malformed_policy`, `malformed_facts`, `malformed_runtime`, `predicate_type`, `future`, `stale`, `no_root`, `level`, `source_mismatch` (the provenance's own resolved source disagrees with the certificate: commit, or `git+<repo>[@...]`), `source_repo`, `source_ref`, `build_type`, `runtime_mismatch` / `runtime_required` / `subject_ambiguous`, `claim_too_long`. The level is the highest among matching signer-builder roots; nothing in the provenance can raise it. On success the claims are `subject_alg, subject_digest, slsa_level, builder_id, build_type, oidc_issuer, identity, source_repo?, source_ref?, source_digest?, rekor_log_index, runtime_bound`.

Vectors: `packages/pca/conformance/provenance-vectors.json` (generator `scripts/gen-provenance-vectors.mjs`): `merkle_inclusion` (a real Rekor proof and its mutations, plus small trees built by the recursive RFC 9162 definitions), `gate`, `model_path`. Replayed in TypeScript and all nine natives. Note recorded in a vector: the same proof at `size + 1` can verify when the path shape is unchanged; the signed checkpoint binds the size.

### 1.4 Joined to runtime attestation

`runtimeDigestFromEat(verdict, {slot = "image", alg})` reads the running image digest from an EAT the verifier already accepted (`verifyFreshAttestedEAT`: signature, nonce, channel, appraisal): exactly one `measurements` entry with that label, lowercase hex. `issueArtifactDischarge({bundle, roots, policy, runtime, request, now, issuerSecret})` runs 1.2, then 1.3 with that digest, and signs the K1 discharge the request asked for. A runtime of `null` (an EAT that yielded nothing) is `no_runtime`, never "no runtime required". With `require_runtime`, `runtime_bound: true` in the claims means: this exact binary, built from this source by a pinned builder, is the one that runs the action.

### 1.5 Action packs

The signed pack wire is unchanged (natives verify packs with closed members). A pack's build provenance is a Sigstore bundle whose subject is the pack file; the publisher pins the identity that builds it in `pca.config.json`: `provenance: {oidc_issuer, identity | identity_prefix, builder_id}`. `pca actions lint` reports `LP-001` (warning, fails under `--strict`) for a `beta` or `stable` pack without that pin. LP-001, LT-000 and LT-001 are outside `LINT_RULES`, so `lintRulesDigest` is unchanged.

## 2. Trace rules

```
never <B> after <A> within <duration>
selector := atom ("," atom)*      atom := tool:<verb> | trait:<trait id> | resource:<prefix> (A only) | any
duration := <n>(ms|s|m|h|d), at most 30 d
```

`compileTraceRules(rules, verbTable)` lowers each rule to K1 `derive` caveats: per A item (verb, or resource prefix) and per chunk of at most 8 B verbs,

```
defs: seen = count{verb | resource_prefix, window_ms}, verb = action.verb, is_b = or(eq(verb, b1), ...)
check: not(and(gt(seen, 0), is_b))
```

so the check is false (refused) iff an A happened in `(now - w, now]` and this action is a B; a missing history or verb is unknown, and unknown refuses. The result also lists the edges `{rule, from, to, within_ms}` and a digest `hashCanonical({d:"atlas-pca/trace-rules/v1", caveats})`. Errors (never skipped): unknown tool, a selector that matches nothing, a resource selector on the B side, a window over 30 days, more than 64 caveats, a malformed or repeated id. The K1 corpus carries trace-shaped `k1_eval` entries, so every native enforces a compiled rule with its existing derive evaluator. Trait selectors expand over the union of the effective and hint trait closures (an unconfirmed action has every trait), so a rule catches unreviewed actions too.

**Invariant subset.** `parseInvariantRule(id, text, {horizon, dropUnsupported?})` accepts `raise "<msg>" if:`, one flow `(x: ToolCall|ToolOutput) -> (y: ToolCall)` and `x is tool:<name>` lines (a binding with no tool line matches any tool). `horizon` is required: Invariant's `->` spans the whole trace and the PCA check spans the verifier's history window. Any other condition (a detector call, an argument pattern, a chain of three, a `Message`) is an error; with `dropUnsupported` it is removed from the raise condition (a weaker condition fires more often, so the rule refuses more) and listed in `dropped`. Two different tools for one binding is `unsatisfiable`.

**Lethal trifecta lint.** `lethalTrifecta(table, edges, {untrusted?, untrusted_traits?})`: private reads (`pii_access`, `financial_data_read`, `credential_access`, `regulated_data`), untrusted-content reads (listed verbs, listed traits, and read-only actions with `network_egress`), sends (`external_communication`, `network_egress`, `data_export`, `public_exposure`, not read-only). A send is cut off when every untrusted read, or every private read, has an edge to it. `pca actions lint` reports `LT-001` per open send (classified from declared and implied traits) and `LT-000` for a configured rule (`trace: {rules: ["<id>: never ..."], untrusted?}`) that does not compile.

## 3. Detector receipts

Wire (domain `atlas-pca/detector-receipt/v1\0`, W-B artifact signing rules):

```
{v:1, kind:"pca-detector-receipt", detector, version, input_digest, verdict:"suspicious"|"no_finding",
 categories[0..8, sorted, distinct; empty on no_finding], iat, session?, calibration_ref?, sig}
```

`input_digest = hashCanonical({d:"atlas-pca/detector-input/v1", content})`. Policy: `{detectors[0..16]: {id (not "invalid"), keys[1..8], on_suspicious: escalate|deny, categories?, max_age_ms 1..86400000}}`.

`detectorSignal({receipts, policy, input_digests, session?, now})` returns `{signal, env: {detect: {<id>: flagged, invalid: n}}, flagged, rejected}`:

- a valid `suspicious` receipt (declared detector, pinned key, content of this action, matching session if bound, not future, not older than `max_age_ms`) with an acting category lowers the signal to `on_suspicious`;
- a valid `no_finding` changes nothing: it is exactly no receipt;
- an invalid receipt lowers the signal to `escalate` and counts in `env.detect.invalid`; a malformed policy is `deny`.

There is deliberately no "detector required" option: requiring a clean scan would let a `no_finding` (or a bypassed detector) buy back authority. `env.detect.*` joins the model-derived roots of rule 21 (TypeScript and all natives), so a grant's `where` that reads it is refused; only `tighten[]` may. Properties (fast-check, `detector-receipt.test.ts`): for every base decision and receipt set, `tighten(base, signal) <= base`; adding valid `no_finding` receipts leaves signal, env, flags and every `tighten[]` outcome unchanged.

Adapters (`@atlasauth/pca-dataflow`): `lakeraReceipt`, `promptSecurityReceipt`, `genericReceipt`. Only a well-formed clean answer maps to `no_finding`; malformed or ambiguous answers become `suspicious` with category `detector_error`.

## 4. Gateway profile and an external PDP (item 39)

No new primitive. The public guide "PCA in front of an MCP server" describes the one-URL-change gateway (`pca-gateway` + `pca-mcp-rs`) and how an external PDP's allow enters only as a discharge (class `org`) or an oracle fact: a `needs_discharge` caveat can require it, nothing can substitute it for the PCActn.

## 5. Declined and not done

- No rule engine, Datalog or solver in the core: trace rules compile to the existing bounded `derive`.
- No detector verdict can widen; no "required detector".
- Not implemented (refused): `messageSignature` bundles, public-key bundles, v0.1 bundles, OtherName SANs, SLSA v0.2 provenance, Rekor v2 `dsse` entries (Rekor v2 defines only hashedrekord). Rekor v1 `envelopeHash` is not recomputed (the payload hash, signature and certificate are); Rekor v2 uses the persisted-body variant of spec 6.1.4 rather than recomputing the leaf.
