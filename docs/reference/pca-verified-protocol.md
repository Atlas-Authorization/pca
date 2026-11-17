---
title: PCA Verified: driver protocol, profiles and statements
order: 7
---

# PCA Verified: driver protocol, profiles and statements

PCA Verified lets anyone who builds a PCA verifier or producer prove, to a third party and without asking us, that it
conforms. You wrap your implementation in a small **driver**; the runner (`@atlasauth/pca-verified`) feeds the driver the
shared, hash-pinned **corpus** and checks every answer; a **profile** says which parts of the corpus a claim covers; a passing
profile yields a signed **statement** that anyone can verify, turn into a **badge**, and list in a transparency-logged
**registry**. This page is the normative description of all five. Version of this document: **protocol 1**.

## 1. The driver protocol (version 1)

A driver is any program. The runner starts it as

```text
<command> <in.jsonl> <out.jsonl>
```

(or with `{in}` / `{out}` placeholders inside the command, or with `--io stdio`: JSON lines on standard input, JSON lines on
standard output). It must:

1. Read `<in.jsonl>`: one JSON object per line, UTF-8, each with a string `id` and a `kind`.
2. For every line, write exactly one JSON object per line to `<out.jsonl>`, carrying the same `id`. Order does not matter.
3. Exit. The exit status is not part of the verdict, but a driver that dies before answering a line is judged for that line.

A driver is run on batches of lines (200 at a time, producer lines 8 at a time). The runner enforces a time budget per line
(15 s by default). A line that makes the driver hang, crash or never answer is isolated, scored a **fault**, and the run
continues. A line the driver is not asked about must not appear in the output; an id answered twice, an id nobody asked for, or a
line that is not a JSON object with a string `id` is a **protocol violation**, and no profile can pass a run that has one.

The expected answer is never sent to the driver.

### Line kinds

Every input line has `id`, `kind`, and (for most kinds) `raw`, `grant`, `now`, `aud`.

| `kind` | You receive | You answer |
|---|---|---|
| `suites` | nothing else | `{"id", "suites": ["ed25519", ...]}`: the signature suites your build implements, from the registered list. Must include `ed25519`, no duplicates, no unregistered names. |
| `verify` | `raw`: the PCActn as JSON text. `grant`: the verifier's own grant as JSON text. `now`: epoch ms. `aud`: your audience. Optional: `allowed_suites`, `intent_policy`, `intent_policy_json`, `intent_v2`. | `{"id", "allow": bool, "checks": {"wire": bool, "version": bool, "audience": bool, "validity": bool, "chain": bool, "grant_ref_bound": bool, "plan_inclusion": bool, "leaf_signature": bool, "counter_format": bool, "intent"?: bool}}`. A PCActn that fails the strict wire parse is `{"allow": false, "checks": {"wire": false}}`. If the PCActn needs a suite you do not implement, answer `allow: false` and add `"unsupported_suite": "<reason containing unsupported_suite>"`. |
| `canon` | `raw`: any JSON text | `{"id", "canon": "<strict canonical form>", "hash": "<digest>"}`, or `{"id", "error": "parse"}` when the strict profile refuses it. |
| `chain` | `raw`: JSON text `{chain, expected_root_issuer?, pq_pins?, trusted_root?, allowed_suites?}` | `{"id", "allow": bool, "checks": {"chain": bool}}` (plus `unsupported_suite` as above). |
| `policy` | `raw`: JSON text `{grant, chain, context}` | `{"id", "allow": bool, "failed": ["<caveat type>", ...]}`; optionally `"decision": {allow, reasons, failed}` for the whole policy decision. |
| `produce` | `raw`: JSON text `{op, args, keys, pq_keys?}`, one producer case | `{"id", "out": <the artifact>}`, or `{"id", "error": "<message>"}` when the producer refuses. An operation you do not implement: `{"id", "error": "unsupported_op: <op>"}`; a suite you do not sign: an error containing `unsupported_suite`. |
| `stateful` | `raw`: JSON text `{setup, steps}` run against one fresh store | `{"id", "steps": [ {"allow": bool, "failed": [check...]} \| null, ... ]}`, one entry per step, `null` for a `revoke` step. |

A kind your driver does not implement should be answered `{"id", "error": "unsupported"}`. The runner scores that
**unsupported**, never passed, and the profile that needs it cannot be claimed.

### How an answer is judged

* `verify`: `allow` must equal the expectation, the **first failed check** must be the same, and every check named in the
  expectation must have the expected value. Extra checks you report are ignored.
* `canon`: a document the strict profile accepts must come back with exactly the canonical form; a document it rejects must not
  come back with a canonical form (an `error` answer is the refusal).
* A vector that carries a suite you did not declare in your `suites` answer must be **refused** (`allow: false`, with the
  `unsupported_suite` tag, or the same early refusal the reference gives). Accepting it, or failing it for a different reason,
  is a failure. A vector whose suites you did declare is verified in full, and refusing it with `unsupported_suite` is a failure.
* `produce`: the output must equal the reference output exactly (the post-quantum cases use the deterministic signing variants
  so this is reproducible). A case the reference refuses must be refused.
* `policy`: the caveat projection `{allow, failed}` must match; a `decision`, when you give one, must match too.
* Outcomes: **pass**, **refused** (a correct refusal of an undeclared suite; counts as a pass), **unsupported**, **fail**,
  **fault** (hang, crash, no answer).

## 2. Layers and profiles

The corpus is split into layers: **wire** (strict JSON, canonical form, PCActn structure and version), **proof**
(audience, validity, plan inclusion, leaf signature, counter format, post-quantum artifacts), **capability** (delegation chains,
`grant_ref` binding, chain pins, depth), **policy** (caveat evaluation), **suites** (the manifest), **producer** (signing
and artifact construction) and **stateful** (sequences against one store).

You claim a **profile**, never a vague "conformant". A profile is claimed only when **every** item in it passes, nothing is
skipped, and the run has no protocol violation.

| Profile | Layers | What it says |
|---|---|---|
| `core-verifier` | wire, proof, capability, policy, suites | The implementation verifies PCActns correctly: strict wire format, signatures and bindings, delegation chains, policy caveats, and an honest suite manifest. |
| `producer` | producer | The implementation signs and builds PCA artifacts byte for byte as the reference does. |
| `pq` | wire, proof, capability, policy (the post-quantum subset) | The implementation declares at least `ml-dsa-65` and `hybrid-ed25519-ml-dsa-65` and verifies every vector that uses only suites it declares; any suite it does not declare is refused. |
| `stateful` | stateful | Replay, counter ordering, revocation mid-sequence and trust-budget depletion behave as the reference does. |

`pca-verified corpus` prints the corpus manifest: the exact item count per layer and per profile.

## 3. The corpus

The corpus is versioned (`corpus_version`) and pinned by the SHA-256 of its exact content. The runner ships the corpus and
checks that hash before every run; `--corpus` and `--corpus-manifest` select another corpus, and the manifest's hash is then
the pin. From corpus version 1.1.0 it also carries the generated adversarial and mutation vectors and the regression vectors, each with the reference verdict computed when the corpus was built (a vector the reference rejects is judged as rejected even when a driver raises instead of answering). A statement names the corpus version and hash it was made against; a verifier accepts only corpora it trusts.

## 4. The report

`report.json` is deterministic: it holds no timestamps and no durations, so the same implementation over the same corpus
yields the same bytes. It lists the implementation, the runner and corpus versions, the declared suites, every item with its
outcome, and for each profile the totals, the per-layer totals and a **results digest**: the SHA-256 of the corpus hash, the
profile and every `(item id, outcome)` pair in corpus order. The profile figures are derived from the items, so a report that
was edited by hand no longer adds up, and `pca-verified verify --report` says so.

## 5. The conformance statement

For each profile that passes in full, the runner can sign a **statement**: a COSE Signed Statement (the same format as the
SCITT statements in `@atlasauth/pca-scitt`) whose payload binds:

* the implementation `name`, `version` and optional `vendor`;
* the runner name and version, the protocol version;
* the corpus `version` and `sha256`;
* the `profile`, the result `pass`, the totals, the per-layer totals, and the results digest;
* the suites the implementation declared;
* the signer's public key (so the key cannot be swapped) and the time of issue.

The file is JSON: `{ format, statement, public_key, payload }`. `statement` is the COSE message and is the attestation;
`payload` is a convenience copy that is checked against it.

`pca-verified verify statement.json` checks, and refuses on any failure: the signature; that the readable payload equals the
signed one; that the key in the payload is the signing key; that the corpus hash is a corpus the verifier trusts and its version
matches; that the totals cover **the whole profile** (a partial run cannot be passed off as a full one); that the declared
suites meet the profile's requirement; and, if you pass `--report`, that the report follows from the corpus and has exactly this
digest. `--trust-key` pins the signer: without it the output says the signer is not pinned, because anyone can sign a statement
for any name. A statement proves **which implementation, which version, which corpus, which result**, signed by **this key**; who
that key belongs to is for you to decide, for example by publishing it with your release.

### Trust tiers

A statement is always **self-attested**: it is signed by a key, and a verifier learns which implementation, version, corpus and
result that key vouches for. The stronger tier is **CI-attested**: the runner ran inside GitHub Actions, and the workflow then made
a Sigstore build-provenance attestation (SLSA provenance, signed with the workflow's OIDC identity and logged in Rekor) over the
exact bytes of the statement (`<profile>.statement.cose`, which the runner writes next to the JSON file).

```text
pca-verified verify out/core-verifier.statement.json --attestation bundle.json \
  --ci-repo my-org/my-verifier --ci-workflow verified.yml --require-tier ci-attested
```

`verify` checks the bundle offline against a pinned Sigstore root (the public-good root ships in the package; `--sigstore-root`
overrides it): the signature, Fulcio certificate chain, Rekor inclusion and timestamp; that GitHub Actions issued the signing
identity; that the identity is a workflow of `--ci-repo` (exactly `--ci-workflow` when given, and on `--ci-ref` when given); and that
the SHA-256 of the statement bytes is one of the attested subjects. Only then does it report `tier: ci-attested`, with the workflow
identity and ref. A bundle that does not verify **fails the statement**; it is never a silent downgrade to self-attested.
`--require-tier ci-attested` refuses a statement with no attestation. The CI tier binds the result to a repository and a workflow
run; it does not say the repository is the one you expect, so state it with `--ci-repo`. The public-good root covers public
repositories; for a private repository, supply that service's root with `--sigstore-root`.

The registry stores each entry's attestation bundle beside the log entry, `registry verify --ci-repo ...` re-checks it, and the
listing page shows the tier of every entry.

### Badges

`pca-verified badge statement.json --out DIR` writes `badge.svg` and `badge.json`. The JSON is the
[shields.io endpoint](https://shields.io/badges/endpoint-badge) format (`schemaVersion`, `label`, `message`, `color`) so it can be
served as a live badge. A badge is produced **only** from a statement that verifies; there is no way to ask for one otherwise.

## 6. The registry

A registry is an append-only list of statements in a transparency log (an RFC 9162 Merkle log with RFC 9942 COSE receipts, the
same service that `@atlasauth/pca-scitt` provides). Adding a statement checks it first, refuses duplicates, appends it, and
returns a receipt. An export contains every statement, a receipt for each, and the log head.

```text
pca-verified registry init DIR                      # creates the log and its key; prints the registry key to pin
pca-verified registry add DIR statement.json
pca-verified registry export DIR --out registry.json
pca-verified registry verify registry.json --key <registry key> [--previous older.json]
pca-verified registry page registry.json --key <registry key> --out site/
```

`registry verify` checks every receipt against the head under the **pinned** key (the key inside the export proves nothing),
re-verifies every statement, and with `--previous` checks that the older export is an unchanged prefix of this one, so history
cannot be rewritten unnoticed. `registry page` builds a static, script-free HTML listing of verified implementations grouped by
profile and version, with a badge for each, and refuses to build one from a registry that does not verify.

## What a statement does not say

It says the implementation agreed with the reference on this corpus. It is not an audit, it says nothing about timing,
resource limits or the code outside what the corpus exercises, and a new corpus version can contain vectors an older
statement never saw. It does not say that the signer is who they claim to be.
