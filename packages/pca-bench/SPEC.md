# PCA performance corpus and result schema (format `pca-bench-corpus/1`, result `pca-bench-result/1`)

This is the contract every harness (the TypeScript flagship and the nine native SDKs) implements. The harnesses live beside the code they
measure (`packages/pca-bench` for TypeScript, `sdks/<lang>-pca/bench/` for the natives); this directory owns the corpus generator, the
result schema, the converters for tools that do not emit it directly, and the regression gate.

## 1. The corpus

`gen-corpus.mjs` writes the corpus to stdout. It is **generated, never committed**: every secret is derived from a seed label at run time
and no private key is stored. The file holds public data only (grants, signed PCActns, public keys, expected hashes and signatures).

Determinism: Ed25519, ML-DSA-65 signing (FIPS 204 deterministic variant), the canonical form and its hash are all deterministic, and the only
randomness-free inputs are the labels. Two generations are byte-identical; CI checks that on every run. `digest` is the SHA-256 of the
serialised `scenarios` array and travels in every result, so a baseline can tell it was recorded against a different corpus.

Seed derivation (the one rule, shared by every language):

```
seed(label, n) = first n bytes of  sha256(D || label || "/0") || sha256(D || label || "/1") || ...      D = corpus.seed_domain = "pca-bench/v1/"
Ed25519 secret   = seed(label, 32)            ML-DSA-65 key = keygen from seed(label, 32) (FIPS 204 xi)
```

Corpus fields: `format`, `version` (1), `seed_domain`, `now`, `aud`, `digest`, `scenarios[]`. Each scenario has `id`, `kind`, `group`, an
optional `pair`, and the data its kind needs. A harness resolves everything by `id`; the ids are stable within a corpus version.

| id | kind | what is measured |
|---|---|---|
| `verify.ed25519.d1/d3/d8` | verify | core verifier over a 1 / 3 / 8-hop chain, every hop and the leaf Ed25519 |
| `verify.hybrid.d1/d3/d8` | verify | the same chains, every delegation hop and the leaf `hybrid-ed25519-ml-dsa-65` (root Ed25519) |
| `verify.hybrid-pqroot.d3` | verify | 3 hops, the root hop also hybrid (the principal's key is post-quantum) |
| `verify.caveats.d3` | verify | 3 hops, 25 caveats per hop (24 opaque + one monotone `budget_alloc`) |
| `deny.hybrid.d8.leaf-sig`, `deny.hybrid.d8.pq-sig`, `deny.ed25519.d8.root-hop-sig`, `deny.ed25519.d8.audience`, `deny.ed25519.d8.expired`, `deny.ed25519.d8.wire` | verify | refusals: bad leaf signature, bad PQ signature, bad first-hop signature, wrong audience, expired, malformed wire |
| `deny.ed25519.d17.hop-limit` | verify | 17 genuinely signed hops: one over the shared cap of 16 |
| `canon.pcactn.ed25519.d3`, `canon.pcactn.hybrid.d8` | canonicalize | canonical form + SHA-256 of a whole PCActn |
| `sign.ed25519.d3`, `sign.hybrid.d3` | sign | produce the leaf signature(s) of a PCActn body; must reproduce `expect.sig` / `expect.pq_sig` |
| `authorize.allow`, `deny.authorize.policy`, `deny.authorize.audience` | authorize | the full resource-server pipeline in single-step mode: a $50 payment under a $100 predicate; a validly signed $400 payment refused by the predicate; a wrong-audience refusal |

Verify scenarios carry `grant`, `pcactn`, `context {now, aud}` and `expect {allow}`; the verifier runs with the plan-root check skipped, as the
conformance runners do (the corpus's plan is not authorized by anything). Canonicalize carries `value` and `expect.canonical_sha256` (base64url).
Sign carries the unsigned `body`, `suite`, `seed_labels` and `expect`. A harness must **check the recorded answer once before it times
anything** (a verdict that differs from `expect`, a hash or signature that differs, is `status: "error"`, never a fast wrong answer).

A deny scenario names the allow scenario it derives from in `pair`.

Authorize scenarios carry `grant`, `pcactn`, `operation {verb, resource, params}` and `server {audience, now, plan: "single-step", provenance {mediator, kid, seed_label}}`.
The harness builds, per call, a fresh in-memory replay/state store (the stored counter would reject the second iteration) and calls the lane's public
authorize entry point with: the audience, the clock `now`, the grant resolved by `grant_ref`, nothing revoked, the plan mode, the argument-provenance gate on
(mediator key = seed(`seed_label`, 32), pinned as `{mediator, kid, public key}`; the principal-direct provenance bundle for the operation is built once before timing,
as it is the mediator's work), and the lane's calm/zero-risk setting (the grant's risk policy has zero weights). `expect.allow` is checked once before timing.

A scenario a lane cannot run is `status: "skipped"` with a `note`; one that should run but fails its check is `status: "error"`.

## 2. Metrics

Per scenario: `ops_per_sec` (1e9 / mean), `mean_ns`, `p50_ns`, `p95_ns`, `p99_ns` (nearest rank), `allocs_per_op` and `bytes_per_op` where the
runtime exposes them (else `null`), and `rounds_ns`: the median ns/op of each of at least 5 time-ordered rounds. `rounds_ns` is what the gate
tests. Per file: `cold_start_ns`, the first verify in a fresh process for `verify.ed25519.d1` and `verify.hybrid.d1` (median of the fresh
processes the tool started; reported, never gated, because one sample per process cannot carry a verdict).

Where a tool times batches (Go, Rust, Ruby, JMH average mode, PHPBench) a round is one batch run; where it times single calls (TypeScript,
.NET, Python, Swift) the samples are split into 7 contiguous chunks and each chunk's median is a round. p50/p95/p99 always come from single
calls (JMH sample mode and .NET `InvocationCount = 1` do this natively; Go, Rust and Ruby take an extra timed pass). Allocation figures:
Go and Rust allocation counts and bytes (testing.B, a counting allocator), Ruby object counts (`GC.stat`), JMH `gc.alloc.rate.norm` bytes,
.NET `BytesAllocatedPerOperation`, Python peak traced bytes of one call; TypeScript, PHP and Swift expose none.

## 3. The result file

`schema/result.schema.json`. One file per language per run: `lang`, `impl`, `impl_version`, `tool`, `runtime`, `runner {os, arch, cpu, cores}`,
`corpus {version, digest}`, `cold_start_ns`, `scenarios[]` as in section 2 plus `status` (`ok` | `skipped` | `error`) and `note`.

Tools whose native output is not this schema are converted by `convert.mjs` (`jmh`, `bdn`, `pytest`, `phpbench`, `swift`); the harness writes a
status sidecar (jsonl `{id, status, note}`) for scenarios it skipped or that failed their check, so none goes missing silently.

## 4. The regression gate (`lib.mjs`, `compare.mjs`)

Pure functions: the same inputs give the same verdict anywhere. CI runs each harness three times and pools the rounds of the runs.

1. **Corpus mismatch or other hardware** (different `corpus.digest`, or a different OS / arch / CPU model than the baseline's): the comparison is
   skipped with a notice and the baseline must be refreshed on this runner class. Absolute timings do not transfer between CPUs.
2. **Regression**: a scenario fails only if the median of its rounds is more than `threshold` (default 20%) above the baseline's **and** the exact
   one-sided Mann-Whitney U test over the pooled rounds rejects "no slower" at alpha = 0.05. One slow run or one slow round cannot fail the gate
   (the median and the rank test both ignore it); fewer than 5 rounds on either side means "not judged". A scenario that errors but ran in the
   baseline, or that vanished, fails.
3. **Deny paths**, judged inside the candidate run so hardware cancels out: a `deny.*` scenario fails if its median is more than 10% above its
   `pair`'s **and** the same rank test says it is slower. A refusal that costs more than the acceptance it derives from is a denial-of-service
   lever, so this holds on every run, with or without a baseline.
4. **No baseline yet**: pass, with a notice. Scenarios that errored are listed in the notice (and fail the gate once a baseline exists).

Exit codes of `compare.mjs gate`: 0 pass, 1 regression or deny-path failure, 2 bad input.

## 5. Baselines

A baseline is a result file produced by `compare.mjs merge` from three CI runs on the lane's fixed runner. TypeScript:
`packages/pca-bench/baselines/ts.json`; natives: `bench/baseline.json` in the SDK. To update: run the workflow on the branch (dispatch), download the
`bench-<lang>` artifact, commit its `bench-candidate.json` as the baseline path above, in the same change as the performance change that justifies it.
