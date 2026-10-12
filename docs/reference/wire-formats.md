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
- **Numbers**: `JSON.stringify` of a finite number (the shortest round-trip decimal). In signed bytes only two forms exist: a safe integer (absolute value at most 2^53 - 1), or a plain decimal with no exponent, no trailing fractional zero, at most 15 significant digits and an absolute value of at least 0.000001. `-0`, non-finite numbers and anything else are rejected, so every implementation produces the same text.
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
| `atlas-pca/actn/v2\0` | PCActn leaf signature (wire version 2) |
| `atlas-pca/share/<role>\0` | Threshold share for `agent`, `guardian` or `principal` (see below) |
| `atlas-pca/signerset/v1\0` | Signer-set hash (hashed, not signed) |
| `\0atlas-pca/share-suite/v1\0` | Suffix binding a non-Ed25519 share to its suite |
| `atlas-pca/holder-pq/v1\0` | Holder commitment to a post-quantum key (`holder_pq`, hashed) |
| `atlas-pca/goal/v1\0` | Goal commitment (placed inside the hashed object, see below) |
| `atlas-pca/attest/v1\0` | Attestation document |
| `atlas-pca/optimistic/v1\0` | Bonded optimistic claim |
| `atlas-pca/zk-compliance/v1\0` | Attested-VM compliance statement |
| `atlas-pca/beacon/v1\0` | Freshness beacon |
| `atlas-pca/ledger-head/v1\0` | Witnessed ledger head |
| `atlas-pca/pq-binding/v2\0` | PQ key pin binding: Ed25519 signature over `domain || ed \0 pq \0 epoch \0 aud` (`aud` = instance id, `epoch` a positive integer that only increases; v1 bindings without epoch/aud are not accepted) |
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
  "holder_pq": "<b64u 32 bytes>",        // optional: commitment to the holder's post-quantum key
  "alg": "<suite>",                      // optional, absent = ed25519
  "pq_pk": "<b64u>",                     // per suite (signed)
  "pq_sig": "<b64u>",                    // per suite (hybrid only)
  "body_digest": "<hashCanonical(body)>",
  "sig": "<b64u, length per suite>"
}
```

The member set is closed to exactly these eleven names; any other member fails `wire` inside a PCActn.

- `body = { issuer, holder, caveats, parent }` where `parent` is `null` on the root (so the field is always present in the hashed body), plus `holder_pq` when present, plus `alg` and `pq_pk` for a non-Ed25519 suite. An explicit `"alg": "ed25519"` is not part of the hop body (it is still inside the signed PCActn body).
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

### Caveat evaluation

Core verification treats caveats as opaque: it only checks that each hop keeps its parent's caveats as an exact prefix (and that `budget_alloc` limits never grow). Whether an action satisfies the caveats is decided by the policy layer (`verifyPCActn`, `requirePCA`, `decide`), which evaluates, conjunctively:

1. the envelope's own `predicates` and `caveats`;
2. every caveat on the root grant except that first `envelope` caveat (since 0.4.1; before, root caveats outside the envelope were signed but never evaluated);
3. every caveat the delegation hops appended (`leaf.caveats` beyond the grant's).

A caveat type the evaluator does not implement is unsatisfied, wherever it sits. The built-in types are `expires`, `not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc`, `max_spend`, `predicates` and `tool_schema`. `max_spend {usd}` (0.4.1) holds when the action's parameters carry an `amount` that is a number from 0 to `usd` inclusive and, if a `currency` is given, it is exactly `"usd"` or `"USD"`; a missing or non-numeric amount does not satisfy it. The `caveat_eval` conformance vectors pin items 2 and 3 for the baseline types.

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
  ver: 2,
  action:      { verb, resource, params_digest, reversibility_class },
  grant_ref:   <grant id>,               // MUST equal cap_chain[0].id (the root capability's id)
  cap_chain:   [ Capability, ... ],      // root -> leaf; root equals the grant
  plan:        { root, inclusion_proof, node_id, conditions_digest? },
  attestation: { quote_digest, epoch, model_id, measurement, operator },
  provenance:  { causal_hash, taint_level, trusted_refs[] },
  freshness:   { beacon_ref, epoch, accumulator_witness },
  counter:     <non-negative integer>,
  risk_claim:  { r, inputs },
  aud:         <string, 1..256 UTF-8 bytes>,
  iat:         <ms since epoch>,
  exp:         <ms since epoch>,
  sig:         <b64u, length per suite, by the leaf holder>,
  nonce?, caution?, rationale_commitment?, progress_step?, prohibition_evidence?, tool_binding?,
  alg?, pq_pk?,                          // signed suite fields
  pq_sig?,                               // unsigned (hybrid leaf)
  threshold?:  { shares: [ { role, publicKey, sig, alg?, pq_sig?, pq_pk? } ] },   // unsigned
  zk_compliance?: <opaque>,
  bond_ref?:   <opaque>
}
```

The top-level member set is closed, and so are `action`, `plan`, `plan.inclusion_proof`, its path steps and the hops: an unknown member fails `wire`. The evidence slots (`attestation`, `provenance`, `freshness`, `risk_claim`) accept extra members, which are signed like the rest. A whole PCActn document is at most 524,288 bytes, checked before parsing; a chain has at most 16 hops and at most 256 caveats per hop and 1,024 per chain.

Notes:

- `attestation`, `provenance` and `freshness` default to empty stub values (`model_id` and `operator` `"unattested"`, zero epochs, empty strings) when no attestation is in use; the corresponding checks report `not-enforced`. They are still covered by the signature.
- `grant_ref` is bound: the verifier requires it to equal `cap_chain[0].id`. Replay state (nonces, counters, budgets) is keyed on it, so an unbound value would let a holder pick a fresh namespace for every action. Honest emitters (`buildPCActn`) already set it to the grant id.
- `risk_claim` is the agent's claim and is advisory: a verifier recomputes risk.
- `ver` must equal `PCACTN_VERSION` (2).
- `aud` must equal the verifier's own audience id; `exp > iat`, `exp - iat <= 3,600,000`, `iat <= now + 60,000` and `now <= exp` (milliseconds).
- Transport: canonical JSON (`encodePCActn`), a JSON body `{ "pcactn": ... }`, or the `PCA-Action` header. The header value is the **strict unpadded base64url** of the UTF-8 PCActn text, exactly the profile's base64url rule: no `=` padding, no `+` or `/`, no whitespace, zero unused trailing bits, and the bytes must be valid UTF-8. Since 0.4.1 any other spelling is refused (401) instead of being decoded leniently.

### Signed message

```
thresholdMessage(p) = "atlas-pca/actn/v2\0" || SHA-256( canonicalBytes( p without `sig`, `pq_sig` and `threshold` ) )
```

The leaf `sig` (and `pq_sig` for a hybrid leaf) signs exactly these 50 bytes; threshold shares sign a role-bound message derived from them (below). `sig`, `pq_sig` and `threshold` are excluded so signatures and shares can be added after the message is fixed; `alg` and `pq_pk` are inside, so the suite and the post-quantum key cannot be swapped. The core verifier checks the leaf signature under the leaf suite with the **last** capability's `holder` as the Ed25519 key; a post-quantum leaf key must match the leaf hop's `holder_pq` commitment.

### Core checks

`verifyPCActnCore` evaluates, in order: `wire` (the structural and lexical rules above; a failure is terminal and nothing else is evaluated); `version`; `audience`; `validity`; `cap_chain` (root equals grant by `capHash`, then chain rules); `grant_ref_bound` (the signed `grant_ref` must be a non-empty string byte-equal to `cap_chain[0].id`, the root capability's id; compared exactly, fails closed on an empty chain); `plan_inclusion`; `leaf_signature`; `counter` (a non-negative integer; strict monotonicity versus stored state is the resource server's job). `plan_root_authorized`, `taint_gate`, `attestation`, `threshold`, `revocation`, `zk_compliance` and `bond` report `not-enforced` unless a hook or the layer above supplies them. `allow` is true iff no check is `fail`.

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

FN-DSA is a pure suite (no hybrid is defined). It is usable on capability hops (`mintRoot`/`delegate` with `suite: { alg, fnDsa512 | fnDsa1024 }`, key material plus a 32-byte `signSeed`), as a PCActn leaf and as a quorum-share suite, under the same rules as ML-DSA: `pq_pk` is body-bound, the signer's PQ key must be the one its parent committed to in `holder_pq` (unbound keys are rejected unless `allowUnboundPq`), and `allowedSuites` applies. It needs the `@atlasauth/pca-fndsa-wasm` backend; without it every FN-DSA verification fails closed.

**Hosted-API suite policy.** The hosted API does not accept every registered suite. By default (instance config `pca.allowedSuites` unset) it accepts `ed25519` and the hybrids that include Ed25519 (every `hybrid-*` row above) and refuses the pure post-quantum suites (`ml-dsa-*`, `slh-dsa-*`, `fn-dsa-*`, `less-cat1`) on leaves, hops and grant roots; an operator opts a pure suite in by listing it. The binding rules do not change: an allowed pure-PQ or hybrid signer's `pq_pk` must equal the parent's `holder_pq` commitment. The effective list is readable at `GET /v1/pca/suites`; see the API reference. Library verifiers (`allowedSuites` / `allowed_suites`) have no such default: absent means every registered suite.


### Suites on the guardian-signed surfaces

Revocation epochs, liveness beacons, tree heads, witness cosignatures, legacy witnessed heads, bond settlements, safety certificates, state attestations, judge verdicts, software attestations and quorum shares all accept every suite in the table above through one signer-options type, `SignerSuiteOpts` (`{ alg, mlDsa | mlDsa87 | slhDsa | slhDsa256s | fnDsa512 | fnDsa1024 | lessCat1 }`; FN-DSA and LESS key material also carry a 32-byte `signSeed`). The wire format is the one described above and does not change per surface: a non-default suite adds `alg` and `pq_pk` to the signed body (so neither can be swapped or stripped) and `sig`, plus `pq_sig` for a hybrid, outside it. The default `ed25519` bytes are unchanged. The verifier takes the PQ key from its own pin for the named identity (`pqPins`, built with `signPqBinding` / `pqPinFor`), never from the artifact: an artifact whose `pq_pk` is not the pin, or any non-ed25519 artifact with no pin, is refused unless the verifier sets `allowUnboundPq`. A quorum share's key is the `pq_pk` registered for its role in the signer set, which may be any suite's key.

The LESS signature is variable length (its last byte is the number of opened seed-tree leaves), so its length is checked as a range on a 16-byte grid rather than as one exact size. LESS is a NIST additional-signature Round 2 candidate, not a standard, and the suites are implemented by the TypeScript reference only: the other verifiers reject them as an unknown `alg`. They are not part of the conformance vectors.

## Threshold signature (multi-signature form)

`{ shares: [ { role: "agent" | "guardian" | "principal", publicKey, sig, alg?, pq_sig?, pq_pk? } ] }`. Each share signs a message bound to its role, the action, the signer set, the threshold and its suite:

```
signerSetHash = SHA-256( "atlas-pca/signerset/v1\0" || canonicalBytes( rows ) )
                # rows = [{ publicKey, role, pq_pk? }] for each signer-set entry (pq_pk only when it is a string),
                # sorted by (UTF-8 role, UTF-8 publicKey)
share_msg     = "atlas-pca/share/<role>\0" || SHA-256( thresholdMessage(p) ) || signerSetHash || byte(t)
                || ( "\0atlas-pca/share-suite/v1\0" || alg   for a non-Ed25519 share )
```

`publicKey` is the role's registered Ed25519 key. For a post-quantum or hybrid share the post-quantum key is always the `pq_pk` the signer set registers for the role; a share's own `pq_pk`, if present, is only an echo and must equal it. A role that registers a `pq_pk` needs a post-quantum or hybrid share. Valid iff `t` is 1, 2 or 3, the signer set is well formed (known roles, one key per role, one role per key) and the count of **distinct keys** with a verifying share is at least `t`. The `agent` role's explicit share uses the same construction; in addition the PCActn's own leaf `sig` counts as the agent's share when the leaf holder is the registered agent key.

On the wire each share's `sig` and `pq_sig` are validated per suite like the leaf's (since 0.4.1): `alg` absent means `ed25519` with a 64-byte `sig`; a pure suite carries its own signature length in `sig` (3,309 bytes for `ml-dsa-65`, 4,627 for `ml-dsa-87`, 17,088 / 29,792 for the SLH-DSA sets, 666 / 1,280 for FN-DSA, 1,153 to 1,329 for LESS) and no `pq_sig`; a hybrid carries a 64-byte `sig` plus the post-quantum `pq_sig`. An unknown or non-string `alg`, a wrong length or a missing or stray `pq_sig` fails `wire`. Before 0.4.1 every share `sig` had to be 64 bytes, so a pure post-quantum share could not be carried in a PCActn.

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
