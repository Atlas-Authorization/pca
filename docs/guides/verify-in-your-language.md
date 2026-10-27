---
title: Verify in your language
order: 13
---

# Verify in your language

PCA is a protocol, not a library. Any language that can do SHA-256, Ed25519 and canonical JSON can verify a PCActn. The **conformance suite** in `packages/pca/conformance` gives independent implementations golden vectors to self-certify against, the way OIDC has conformance tests.

## Start with the Core profile

Implement [PCA Core](../core.md) first. The suite ships `core-profile.json`, which names the subset of the corpus a Core-only verifier (Ed25519, no extensions) must pass: 276 PCActn vectors (40 allow, 236 deny), every `canonical`, `json_parse`, `b64u`, `merkle` and `pca_header` entry, 37 `caveat_eval` entries, 48 `malformed` entries and 16 `depth` entries. Filter `vectors.json` by the names it lists. Once your verifier passes it, add the sections for the extensions you implement.

## What the suite covers

Files:

| File | Contents |
|---|---|
| `keys.json` | Fixed test keys `{ principal, agent, subagent, rogue: { seed, public } }`, base64url without padding. `seed = sha256("atlas-pca-conformance/<label>")` is the Ed25519 private seed. Extra chain keys are `sha256("atlas-pca-conformance/hop<i>")`. |
| `vectors.json` | The shared corpus: `{ format: 2, ver: 2, sig_domain, cap_domain, share_domain, check_order, limits, primitives, vectors, agent_leaf_binding }`. 676 PCActn vectors (129 positive, 547 negative) plus the primitive sections below. Every language verifier runs it. |
| `core-profile.json` | The Core profile: the names selected from `vectors.json` (see above). |
| `vectors-adversarial.json.gz` | The full adversarial parser-differential set: 4,358 PCActn vectors and 1,178 primitives (425 `json_parse`, 718 `b64u`, 35 `canonical`), same schema. `vectors.json` carries a representative sample of it. |
| `policy-vectors.json` | Policy-layer decisions: 413 vectors, each a grant, its delegation chain and a context, with the expected decision as reason codes. See [Claim conformance per layer](#claim-conformance-per-layer). |
| `intent-state-vectors.json` | Intent Layer v2 state: 3,045 function-level cases for accumulators, monitors, session-history windows and pre-states, sequencer key sets and reservation receipts. Run in the TypeScript, Go, Rust and Python verifiers. |
| `stateful-vectors.json` | Stateful-layer sequences: 20 sequences (64 steps), each run in order against one fresh replay and budget store. |
| `layers.json` | The layer of every section, file and vector, and the counts per layer. |
| `SUITES.md` | Which signature suites each language verifier implements, and the library behind each. |

Assert minimum counts in your runner, not exact sizes: the corpus grows over time.

### `primitives`

| Section | Entries | What a runner checks |
|---|---|---|
| `canonical` | 23 | `{ value, expect, hash }`: the strict canonical JSON text and `base64url(sha256(canonical))`. |
| `json_parse` | 125 | `{ input, accept, canonical? }`: the strict JSON profile; `accept: false` must be rejected. |
| `b64u` | 81 | `{ input, valid, len? }`: strict base64url, `len` = required decoded length. |
| `merkle`, `params_digest_empty` | 3, 1 | Roots and inclusion proofs; `hashCanonical({})`. |
| `pca_header` | 27 | `{ input, valid, text? }`: the `PCA-Action` header decoder (strict unpadded base64url of UTF-8). |
| `caveat_eval` | 41 | Root and delegated caveat evaluation for the baseline caveat types: `{ allow, failed }`. |
| `malformed` | 84 | Inputs that must come back as a clean deny, never an exception. |
| `depth` | 29 | Nesting limits at 31 / 32 / 33 and 100,000 levels on every untrusted entry point. |
| `threshold_share`, `threshold_set`, `signer_set_hash` | 56, 65, 8 | Threshold shares and signer sets (extension). |
| `chain_pin`, `pq_artifact` | 31, 20 | Post-quantum root pins and signatures on the other signed surfaces (extension). |
| `intent_*` | 391 in 9 sections | Intent Layer rules (extension). |

### `vectors[]`

`{ name, class, description, grant, plan_nodes, context: { now, aud, ... }, pcactn | pcactn_json, expect: { allow, checks }, requires? }`

- Verify with `verify(pcactn, grant, now = context.now, audience = context.aud)`, passing any other `context` member (suite policy, intent policy) to your verifier as well.
- `pcactn_json` is raw text that must go through the strict JSON profile first. A parse failure is a `wire` failure, and the verdict is then exactly `{ allow: false, checks: { wire: false } }`.
- `expect.checks` are booleans. When `wire` is false it is the only entry. Otherwise all of `wire, version, audience, validity, chain, grant_ref_bound, plan_inclusion, leaf_signature, counter` are present, in that order (`chain` is the check other APIs call `cap_chain`), plus `intent` and the Intent Layer checks when the vector exercises them. `allow` is true only if every check passes.
- `requires` names a signature suite. A verifier that does not implement it must refuse the vector (fail closed, reason `unsupported_suite`) and count it, rather than compare it.

## Rules every implementation must match

These are normative; the byte-level definitions are in [Wire formats](../reference/wire-formats.md).

- **Canonical JSON**: object keys sorted bytewise by their UTF-8 encoding (Unicode code point order, not UTF-16 code units), recursively. No whitespace. Strings escape only `"`, `\` and control characters below U+0020 (`\b \f \n \r \t` short forms, others `\u00xx` lowercase); everything else, including U+007F, U+2028, U+2029 and characters outside the BMP, is raw UTF-8. Numbers are safe integers (at most 2^53 - 1 in absolute value, no `-0`) or plain decimals with no exponent, at most 15 significant digits, no trailing fractional zero and an absolute value of at least 0.000001.
- **Strict JSON profile** for parsing signed bytes: reject comments, trailing commas, a BOM, whitespace other than space / tab / LF / CR, duplicate keys, lone surrogates, raw control characters in strings, unknown escapes, nesting deeper than 32, input over 1 MiB, and any number outside the canonical form. A PCActn document over 524,288 UTF-8 bytes is refused before parsing.
- **base64url**: unpadded, alphabet `A-Za-z0-9-_` only, no whitespace, length mod 4 not 1, and zero unused trailing bits (re-encoding reproduces the string). 32-byte ids, keys and digests; 64-byte Ed25519 signatures.
- **Hash**: base64url, no padding, of SHA-256.
- **Merkle**: leaf `H(0x00 || canon(leaf))`, node `H(0x01 || L || R)`, split at the largest power of two below `n`. Proof step `{ side, hash }` where `side` is where the **sibling** sits; `index` and `size` must determine the path length and every side.
- **Plan leaf**: `{ node_id, verb, resource, params_digest (default hash({})), reversibility_class (default "reversible"), conditions (default hash({pre:null,post:null})) }`.
- **Signed message** for the leaf signature: `"atlas-pca/actn/v2\0" || sha256(canonical(pcactn without sig, pq_sig and threshold))`. `ver` must be 2.
- **Freshness**: `aud` equals your audience; `exp > iat`, `exp - iat <= 3,600,000`, `iat <= now + 60,000`, `now <= exp` (epoch milliseconds).
- **Capability hop**: `id = body_digest = hash({issuer, holder, caveats, parent|null})`; signature over `"atlas-pca/cap/v1\0" || raw(body_digest)` by the parent's holder (root: by the issuer), under strict RFC 8032 Ed25519 (non-canonical S, non-canonical points and small-order or mixed-order keys and R are rejected). `parent` = hash of the full parent capability. The child's caveats must have the parent's caveats as an exact prefix. `chain[0]` must equal the grant, the chain has at most 16 hops, and `grant_ref` must equal `chain[0].id`.

## Reference verifiers

Each runs the shared corpus. A verifier that does not implement one of the registered signature suites refuses those vectors (`unsupported_suite`) and counts them instead of comparing them; `SUITES.md` in the conformance suite lists which suites each one covers.

| Language | Location | Run (from the repo) | Entry point |
|---|---|---|---|
| TypeScript | `packages/pca` | `pnpm --filter @atlasauth/pca test` | `verifyPCActnCore` |
| Go | `sdks/go-pca` | `cd sdks/go-pca && go test ./...` | `VerifyPCActnCore(pcactn, grant, now, audience)` |
| Python | `sdks/python-pca` | `cd sdks/python-pca && python3 -m unittest test_conformance` | `verify_pcactn_core(p, grant, now, audience)` |
| Rust | `sdks/rust-pca` | `cd sdks/rust-pca && cargo test` | `verify_pcactn_core(&pcactn, &grant, now, audience)` |
| Java | `sdks/java-pca` | run `ConformanceTest` from `sdks/java-pca` (JDK plus BouncyCastle, no JUnit) | `Pca.verifyPcactn(pcactn, grant, now, audience)` |
| Ruby | `sdks/ruby-pca` | `ruby sdks/ruby-pca/conformance.rb` | `AtlasPca` module |
| PHP | `sdks/php-pca` | `php sdks/php-pca/conformance.php` | `Atlas\Pca\Pca` |
| .NET | `sdks/dotnet-pca` | `dotnet run --project sdks/dotnet-pca/Conformance` | `AtlasPca.Pca` |
| Swift | `sdks/swift-pca` | `cd sdks/swift-pca && swift test` | `AtlasPCAVerify` (+ a step-up client) |
| Kotlin | `sdks/kotlin-pca` | `cd sdks/kotlin-pca && ./gradlew test` | `net.atlasauth.pca.verifier` (+ a step-up client) |

Go, Python, Rust and Java are conformance-exact and form the primary set; Ruby, PHP, .NET, Swift and Kotlin are further ports from the same vectors. The Go, Rust and Java verifiers share the same exported primitives: `canonicalize`, `hash_canonical`, `merkle_root`, `verify_inclusion`, `params_digest`, `cap_hash`, `verify_chain`, `threshold_message` and the core verifier. Python needs no dependencies (an optional `cryptography` extra gives native Ed25519; a pure-Python RFC 8032 verifier is the fallback). Ruby needs OpenSSL 3 for raw Ed25519.

## Writing your own verifier

1. Implement the strict JSON profile, canonical JSON, `hash_canonical` and strict base64url; check against `primitives.json_parse`, `canonical` and `b64u`.
2. Implement the Merkle tree and `verify_inclusion`; check against `primitives.merkle`.
3. Implement `verify_chain` (hop signatures, parent links, holder continuity, caveat-prefix attenuation, the 16-hop and caveat limits).
4. Implement `verify_pcactn_core`: the nine checks in the normative order, with a `wire` failure ending verification.
5. Run the [Core profile](#start-with-the-core-profile), comparing `allow` and every listed check, then the `malformed` and `depth` entries it names.
6. Add extensions one at a time, each with its own sections of `vectors.json`.

## Claim conformance per layer

The suite is split into seven layers, and a verifier states which layers it passes, never just "conformant". A layer counts as passed only when every section in it passes, with none skipped.

| Layer | What it checks | Where |
|---|---|---|
| wire | strict JSON, canonical form, base64url, the `PCA-Action` header, PCActn structure | `canonical`, `json_parse`, `b64u`, `pca_header`; PCActn vectors that fail `wire` or `version` |
| proof | signatures and bindings: audience, validity, plan inclusion, leaf signature, counter format, threshold shares, post-quantum suites | accepted PCActn vectors and those that fail one of these checks; `merkle`, `threshold_*`, `pq_artifact`, the suite vector files |
| capability | delegation chains, attenuation, `grant_ref` binding, chain pins, depth, malformed capabilities | `chain_pin`, `malformed`, `depth`; PCActn vectors that fail `chain` or `grant_ref_bound` |
| policy | caveats (root, envelope, delegated), envelope predicates, `predicates` and `tool_schema` caveats, unknown types, missing context | `caveat_eval`, the Intent Layer sections, `policy-vectors.json` |
| stateful | replay, counter order, revocation partway through a sequence, trust-budget depletion | `stateful-vectors.json` |
| extension | the optimistic path (claims, challenge window, fraud proofs at the wire level, settlement records) and the transparency ledger (Merkle inclusion and consistency, signed tree heads, witness cosignatures, checkpoint chains) | `optimistic-vectors.json`, `ledger-vectors.json`; Ed25519 only, Go, Python and Rust today |
| integration | HTTP middleware and framework adapters | no shared vectors yet |

A PCActn vector belongs to the layer of the first check it fails, in the normative order; a vector that verifies belongs to proof.

Each policy vector expects two results from the same input. `caveats` is `evaluate_caveats(policy_caveats(grant, chain), context)`, the caveat check every reference verifier already implements. `decision` is the whole decision: `allow` and the ordered reasons, each one of `envelope_missing`, `predicates_unsatisfied`, `chain_malformed`, `envelope_caveats_unsatisfied`, `root_caveats_unsatisfied`, `delegated_caveats_unsatisfied`, plus the unsatisfied caveat types in each group. A stateful step expects `allow` and the sorted names of the checks that failed. Neither carries reason text.

Today the TypeScript reference passes every layer that has shared vectors. The nine native verifiers pass wire, proof and capability. Their policy-vector results are reported per language but do not yet fail the build, and none of them runs the stateful sequences yet, so none of them can claim the policy or stateful layer.

The core verifier returns `allow` only if no check failed. It does not by itself prove the action was signed off at the right risk level: caveat evaluation, policy, threshold, revocation and replay state are the resource server's layer on top ([Resource-server quickstart](./resource-server-quickstart.md)).

Next: [API reference](../reference/api.md).
