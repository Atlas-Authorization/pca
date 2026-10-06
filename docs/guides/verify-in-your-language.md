---
title: Verify in your language
order: 13
---

# Verify in your language

PCA is a protocol, not a library. Any language that can do SHA-256, Ed25519 and canonical JSON can verify a PCActn. The **conformance suite** in [`conformance/`](../../conformance) gives independent implementations golden vectors to self-certify against, the way OIDC has conformance tests.

## What the suite covers

The suite validates the **core** verification that depends only on bytes: capability chain, Merkle plan inclusion, Ed25519 leaf signature and counter. Policy, risk, threshold, revocation, attestation and the ledger are layered on top of these and are not part of the portable core vectors.

Files:

| File | Contents |
|---|---|
| `keys.json` | Fixed test keys `{ principal, agent, subagent, rogue: { seed, public } }`, base64url without padding. `seed = sha256("atlas-pca-conformance/<label>")` is the Ed25519 private seed. |
| `vectors.json` | `{ format, sig_domain, cap_domain, primitives, vectors }` |

### `primitives`

- `canonical[]`: `{ value, expect, hash }`: the canonical JSON string and `base64url(sha256(canonical))`.
- `merkle[]`: `{ leaves, root, proofs[] }`: roots and inclusion proofs per leaf.
- `params_digest_empty`: `hashCanonical({})`.

### `vectors[]`

Each is `{ name, description, grant, plan_nodes, pcactn, expect: { allow, checks: { chain, plan_inclusion, leaf_signature, counter } } }`. A verifier calls `verify(pcactn, grant)` and must produce the same `allow` and the same pass/fail for each of the four checks.

There are 21 vectors, covering:

| Group | Examples |
|---|---|
| Valid actions | Each leaf of a 5-node plan (different Merkle paths); a 2-hop delegated chain |
| Plan integrity | Out-of-plan action; tampered params (with and without re-signing); tampered Merkle proof; swapped `conditions_digest` |
| Signature and counter | Signed by the wrong key; counter changed after signing; negative counter; leaf signed by the parent holder instead of the sub-agent |
| Chain attenuation | Dropped, reordered or edited parent caveat; hop signed by the wrong key; hops swapped; root that is not the grant |

## Rules every implementation must match

These are normative; the byte-level definitions are in [Wire formats](../reference/wire-formats.md).

- **Canonical JSON**: object keys sorted by UTF-16 code units, recursively; no whitespace; JavaScript `JSON.stringify` string escaping (only `"`, `\` and control characters escaped; `\b \f \n \r \t` short forms; other controls `\u00xx` lowercase; non-ASCII emitted raw). Vectors use integers only.
- **Hash**: base64url, no padding, of SHA-256.
- **Merkle**: leaf `H(0x00 || canon(leaf))`, node `H(0x01 || L || R)`, split at the largest power of two below `n`. Proof step `{ side, hash }` where `side` is where the **sibling** sits.
- **Plan leaf**: `{ node_id, verb, resource, params_digest (default hash({})), reversibility_class (default "reversible"), conditions (default hash({pre:null,post:null})) }`.
- **Signed message** for the leaf signature: `"atlas-pca/actn/v1\0" || sha256(canonical(pcactn minus sig, threshold))`.
- **Capability hop**: `id = body_digest = hash({issuer, holder, caveats, parent|null})`; signature over `"atlas-pca/cap/v1\0" || raw(body_digest)` by the parent's holder (root: by the issuer); `parent` = hash of the full parent capability; the child's caveats must have the parent's caveats as an exact prefix; `chain[0]` must equal the grant and the root issuer must equal the grant issuer.

## Reference verifiers

Each passes every vector. They are intentionally small and take the grant and PCActn as parsed JSON.

| Language | Location | Run (from the repo) | Entry point |
|---|---|---|---|
| TypeScript | `/pca` (npm) | `npm test` in the package source | `verifyPCActnCore` |
| Go | `verifiers/go-pca` | `cd verifiers/go-pca && go test ./...` | `VerifyPCActnCore(pcactn, grant)` |
| Python | `verifiers/python-pca` | `cd verifiers/python-pca && python3 -m unittest test_conformance` | `verify_pcactn_core(p, grant)` |
| Rust | `verifiers/rust-pca` | `cd verifiers/rust-pca && cargo test` | `verify_pcactn_core(&pcactn, &grant)` |
| Java | `verifiers/java-pca` | run `ConformanceTest` from `verifiers/java-pca` (JDK only, no JUnit) | `Pca.verifyPcactnCore(pcactn, grant)` |
| Ruby | `verifiers/ruby-pca` | `ruby verifiers/ruby-pca/conformance.rb` | `AtlasPca` module |
| PHP | `verifiers/php-pca` | `php verifiers/php-pca/conformance.php` | `Atlas\Pca\Pca` |
| .NET | `verifiers/dotnet-pca` | `dotnet run --project verifiers/dotnet-pca/Conformance` | `AtlasPca.Pca` |

Go, Python, Rust and Java are conformance-exact and form the primary set; Ruby, PHP and .NET are further ports from the same vectors. The Go, Rust and Java verifiers share the same exported primitives: `canonicalize`, `hash_canonical`, `merkle_root`, `verify_inclusion`, `params_digest`, `cap_hash`, `verify_chain`, `threshold_message` and the core verifier. Python needs no dependencies (an optional `cryptography` extra gives native Ed25519; a pure-Python RFC 8032 verifier is the fallback). Ruby needs OpenSSL 3 for raw Ed25519.

## Writing your own verifier

1. Implement canonical JSON and `hash_canonical`; check against `primitives.canonical`.
2. Implement the Merkle tree and `verify_inclusion`; check against `primitives.merkle`.
3. Implement `verify_chain` (hop signatures, parent links, caveat-prefix attenuation).
4. Implement `verify_pcactn_core`: chain root equals grant, plan inclusion from the PCActn's own action fields, leaf signature under the leaf holder, counter well-formed.
5. Run every entry in `vectors.json` and compare `allow` and each of the four checks.

The core verifier returns `allow` only if no check failed. It does not by itself prove the action was signed off at the right risk level: policy, threshold, revocation and replay-state are the resource server's layer on top ([Resource-server quickstart](./resource-server-quickstart.md)).

Next: [API reference](../reference/api.md).
