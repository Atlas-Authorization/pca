---
title: Wire formats
order: 21
---

# Wire formats

This page defines the bytes an independent implementation must reproduce. It is normative for the core objects. The reference is `@atlasauth/pca`; the portable subset is checked by the [conformance suite](../guides/verify-in-your-language.md). Higher-level checks (policy, threshold, revocation) build on these primitives.

PCA objects are JSON. There is no CBOR/COSE form in this release; a PCActn travels as canonical JSON.

## Primitives

### Canonical JSON (`canonicalize`)

Deterministic serialization of a JSON value:

- `null`, `true`, `false` as literals.
- **Strings**: JavaScript `JSON.stringify` escaping. Only `"` and `\` and control characters are escaped; `\b \f \n \r \t` use short forms; other controls use lowercase `\u00xx`; non-ASCII is emitted raw (UTF-8).
- **Numbers**: `JSON.stringify` of a finite number; `-0` is emitted as `0`. Non-finite numbers are rejected. Conformance vectors use integers only; avoid floats in cross-language objects.
- **Arrays**: `[` elements joined by `,` `]`, in order.
- **Objects**: keys sorted byte-wise over their UTF-8 encoding, i.e. by Unicode code point (recursively), each as `"key":value`, joined by `,`, no whitespace.
- Rejected (no stable encoding): `undefined`, functions, symbols, bigint, non-plain objects, cycles.

### Predicate string order

The `lt`/`lte`/`gt`/`gte` predicate operators order strings by the byte-wise order of their UTF-8 encoding (Unicode code point order), the same order used for object keys above. No normalisation, case folding or locale applies, and a string containing a lone surrogate is unordered (the condition is false). Shared vectors: `packages/pca-conformance/predicate-string-order.json`.

### Hash

`hashCanonical(v) = base64url_nopad( SHA-256( UTF-8( canonicalize(v) ) ) )`. All digests, ids and roots are base64url **without padding**. Keys and signatures are Ed25519 (32-byte public key, 64-byte signature) encoded the same way.

### Domain-separated signed messages

Every signature covers a message that begins with a fixed ASCII domain string ending in a NUL byte (`\0`), so a signature for one purpose can never be replayed for another.

| Domain | Used for |
|---|---|
| `atlas-pca/cap/v1\0` | Capability hop signature |
| `atlas-pca/actn/v1\0` | PCActn signature and every threshold share |
| `atlas-pca/goal/v1\0` | Goal commitment (placed inside the hashed object, see below) |
| `atlas-pca/attest/v1\0` | Attestation document |
| `atlas-pca/optimistic/v1\0` | Bonded optimistic claim |
| `atlas-pca/zk-compliance/v1\0` | Attested-VM compliance statement |
| `atlas-pca/beacon/v1\0` | Freshness beacon |
| `atlas-pca/ledger-head/v1\0` | Witnessed ledger head |
| `pca-revset/v1\0` | Revocation-set root binding (hashed, not signed) |

For attestation, optimistic, zk-compliance and beacons the message is `domain || canonical(body)` where `body` is the object without `sig` (for a beacon, the fields `v, scope, epoch, not_after, guardian`). For a ledger head it is `domain || canonical({ principal, size, root })`.

## Merkle tree

RFC 6962 shape with domain separation.

```
leaf  = SHA-256( 0x00 || canonicalBytes(leaf) )
node  = SHA-256( 0x01 || left || right )
split(n) = largest power of two strictly less than n     # k; left = first k leaves, right = the rest
root(1 leaf) = that leaf hash
```

A proof is `{ index, size, path: [{ side, hash }] }` from leaf to root. `side` is where the **sibling** sits (`"L"` or `"R"`); `hash` is the sibling's base64url hash. Verification folds from the leaf hash: sibling on `L` gives `node(sibling, h)`, on `R` gives `node(h, sibling)`. The result, base64url-encoded, must equal the expected root. Empty leaf sets are an error for plans.

## Capability

```json
{
  "id": "<body_digest>",
  "issuer": "<b64u key>",
  "holder": "<b64u key>",
  "caveats": [ { "type": "...", "...": "..." } ],
  "parent": "<capHash of parent>",       // absent on the root
  "body_digest": "<hashCanonical(body)>",
  "sig": "<b64u Ed25519>"
}
```

- `body = { issuer, holder, caveats, parent }` where `parent` is `null` on the root (so the field is always present in the hashed body).
- `body_digest = id = hashCanonical(body)`.
- `sig = Ed25519.sign( signer, "atlas-pca/cap/v1\0" || rawBytes(body_digest) )` where `rawBytes` is the 32 decoded bytes of the digest, **not** its base64url text. The signer is the issuer: the principal for the root, the parent's holder for a child.
- `capHash(cap) = hashCanonical(cap)` over the **whole** capability object including `sig`; a child's `parent` equals this.
- Chain rules: `chain[0].parent` absent; `chain[0].issuer` equals the grant issuer and `chain[0]` equals the grant; for `i >= 1`: `chain[i].parent == capHash(chain[i-1])`, `chain[i].issuer == chain[i-1].holder`, signed by that key, and `chain[i-1].caveats` is an exact prefix of `chain[i].caveats` (compared element-wise by `hashCanonical`).

### Root Intent Grant

A root capability whose caveats begin with:

```json
{ "type": "envelope", "goal_commit": "...", "predicates": [...], "caveats": [...],
  "agent_binding": {...}, "risk_policy": {...} }
```

`goal_commit = hashCanonical({ d: "atlas-pca/goal/v1\0", goal, salt })`. The envelope is the **first** `envelope` caveat.

## Plan leaf

```json
{ "node_id": "...", "verb": "...", "resource": "...",
  "params_digest": "<default hashCanonical({})>",
  "reversibility_class": "<default \"reversible\">",
  "conditions": "<hashCanonical({ pre: pre ?? null, post: post ?? null })>" }
```

- `params_digest = hashCanonical(params ?? {})`.
- A node's omitted `params_digest`, `reversibility_class` and conditions default as shown, identically on node and action.
- The plan root is the Merkle root of the leaves in node order. A verifier **recomputes the leaf from the PCActn's own action fields** plus `plan.node_id` and `plan.conditions_digest` (default `hashCanonical({pre:null,post:null})`) and checks it against `plan.root` with `plan.inclusion_proof`.

## PCActn

```
PCActn {
  ver: 1,
  action:      { verb, resource, params_digest, reversibility_class },
  grant_ref:   <grant id>,               // MUST equal cap_chain[0].id (the root capability's id)
  cap_chain:   [ Capability, ... ],      // root -> leaf; root equals the grant
  plan:        { root, inclusion_proof, node_id, conditions_digest? },
  attestation: { quote_digest, epoch, model_id, measurement, operator },
  provenance:  { causal_hash, taint_level, trusted_refs[] },
  freshness:   { beacon_ref, epoch, accumulator_witness },
  counter:     <non-negative integer>,
  risk_claim:  { r, inputs },
  sig:         <b64u Ed25519 by the leaf holder>,
  threshold?:  { shares: [ { role, publicKey, sig } ] },
  zk_compliance?: <opaque>,
  bond_ref?:   <string>
}
```

Notes:

- `attestation`, `provenance` and `freshness` default to empty stub values (`model_id` and `operator` `"unattested"`, zero epochs, empty strings) when no attestation is in use; the corresponding checks report `not-enforced`. They are still covered by the signature.
- `grant_ref` is bound: the verifier requires it to equal `cap_chain[0].id`. Replay state (nonces, counters, budgets) is keyed on it, so an unbound value would let a holder pick a fresh namespace for every action. Honest emitters (`buildPCActn`) already set it to the grant id.
- `risk_claim` is the agent's claim and is advisory: a verifier recomputes risk.
- `ver` must equal `PCACTN_VERSION` (1).
- Transport: canonical JSON (`encodePCActn`), or base64url of it in the `PCA-Action` header.

### Signed message

```
thresholdMessage(p) = "atlas-pca/actn/v1\0" || SHA-256( canonicalBytes( p without `sig` and without `threshold` ) )
```

The leaf `sig` and every threshold share sign exactly these bytes. `threshold` is excluded so shares can be added after the message is fixed. For a PCActn with no `threshold` field this equals the previous single-signature definition. The core verifier checks `Ed25519.verify(leafHolder, thresholdMessage(p), p.sig)`, where `leafHolder` is the **last** capability's `holder`.

### Core checks

`verifyPCActnCore` evaluates, in order: `version`; `cap_chain` (root equals grant by `capHash`, then chain rules); `grant_ref_bound` (the signed `grant_ref` must be a non-empty string byte-equal to `cap_chain[0].id`, the root capability's id; compared exactly, fails closed on an empty chain); `plan_inclusion`; `leaf_signature`; `counter` (a non-negative integer; strict monotonicity versus stored state is the resource server's job). `plan_root_authorized`, `taint_gate`, `attestation`, `threshold`, `revocation`, `zk_compliance` and `bond` report `not-enforced` unless a hook or the layer above supplies them. `allow` is true iff no check is `fail`.

## Signature suites

A PCActn, a capability hop and the other signed objects may carry an optional `alg` naming the signature suite. Absent `alg` means `ed25519` and the bytes are identical to the base format. A non-default suite adds `pq_pk` (the post-quantum public key, bound into the signed body so it cannot be swapped) and, for hybrids, `pq_sig`. In a hybrid, `sig` is the 64-byte Ed25519 signature and `pq_sig` the post-quantum one, both over the same message, and both must verify. An unknown `alg`, a missing or mis-sized component, or an unavailable backend is a failure, never a downgrade.

| `alg` | Family | `pq_pk` | signature |
|---|---|---|---|
| `ed25519` (default) | classical | absent | 64 B |
| `ml-dsa-65`, `hybrid-ed25519-ml-dsa-65`, `hybrid-nested-ed25519-ml-dsa-65` | lattice (FIPS 204) | 1,952 B | 3,309 B |
| `ml-dsa-87`, `hybrid-ed25519-ml-dsa-87` | lattice, category 5 | 2,592 B | 4,627 B |
| `slh-dsa-sha2-128f`, `hybrid-ed25519-slh-dsa-sha2-128f` | hash-based (FIPS 205) | 32 B | 17,088 B |
| `slh-dsa-sha2-256s`, `hybrid-ed25519-slh-dsa-sha2-256s` | hash-based, category 5 | 64 B | 29,792 B |
| `fn-dsa-512`, `fn-dsa-1024` | lattice (Falcon, FIPS 206 draft) | 897 B, 1,793 B | 666 B, 1,280 B |
| `less-cat1`, `hybrid-ed25519-less-cat1` | code-based (LESS, NIST candidate) | 97,484 B | 1,153 to 1,329 B in 16-byte steps |

The LESS signature is variable length (its last byte is the number of opened seed-tree leaves), so its length is checked as a range on a 16-byte grid rather than as one exact size. LESS is a NIST additional-signature Round 2 candidate, not a standard, and the suites are implemented by the TypeScript reference only: the other verifiers reject them as an unknown `alg`. They are not part of the conformance vectors.

## Threshold signature (multi-signature form)

`{ shares: [ { role: "agent" | "guardian" | "principal", publicKey: <b64u>, sig: <b64u> } ] }`, each `sig` over `thresholdMessage(p)`. Valid iff the count of **distinct roles** with a share signed by a key registered for that role is at least `t`. The agent share is implied by the PCActn's `sig` under the leaf holder key.

With FROST, the PCActn's `sig` is a single 64-byte Ed25519 signature `R || z` verifying under the group public key, and the leaf holder is that group key. Ciphersuite: `FROST(Ed25519, SHA-512)`, context string `FROST-ED25519-SHA512-v1` (RFC 9591).

## Ledger

```
commit = hashCanonical({ salt, pcactn_digest })      # pcactn_digest = hashCanonical(full PCActn incl. sig)
leaf   = SHA-256( 0x00 || canonicalBytes(commit) )   # commit as a canonical JSON string, i.e. quoted
root   = RFC 6962 Merkle tree hash of leaves; empty log = SHA-256("") base64url
```

Opening = `{ salt, pcactn }`. Consistency proofs follow RFC 9162 section 2.1.4.2. A witnessed head is `{ principal, size, root, witness, sig }` signed over `"atlas-pca/ledger-head/v1\0" || canonical({ principal, size, root })`.

## Revocation set

Leaves are revoked ids sorted ascending by UTF-8 byte order (Unicode code point order, as for canonical JSON keys), in the same Merkle tree. Published root:

```
tree  = merkleRoot(ids)            # empty set: base64url(SHA-256(""))
root  = base64url( SHA-256( "pca-revset/v1\0" || canonicalBytes({ size, tree }) ) )
```

Non-membership proof: `{ size, lo?, hi? }` where `lo`/`hi` are `{ id, proof }` leaf proofs of the adjacent neighbours around the absent id. Each leaf proof's path length and sides must match the expected shape for its `index` in a tree of `size`, which binds position to the root.

## Other signed objects

| Object | Fields signed (canonical JSON, minus `sig`) |
|---|---|
| Beacon | `{ v: 1, scope, epoch, not_after, guardian }` |
| Attestation document | `{ model_id, weights_digest, runtime_measurement, operator, nonce, issued_at, expires_at, attestor, mode }` |
| Bonded claim | `{ pcactn_digest, bond_ref, claimed_r, reversibility_class, issued_at, challenge_window_ms }` |
| Compliance statement | `{ v: 1, mode: "attested-vm", action_commit, policy_commit, plan_commit, released: true, r, issued_at, expires_at, prover }` |

Commitments used by the compliance statement: `action_commit = hashCanonical(pcactn.action)`, `policy_commit = grant.id`, `plan_commit = pcactn.plan.root`.

Next: [Glossary](./glossary.md).
