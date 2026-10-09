# PCA conformance: coverage audit, findings and known differences

Entry point: `scripts/pca-conformance-all.sh` (see `--help` block at the top of `scripts/pca-conformance-all.mjs`).
It runs the TypeScript reference (oracle) plus every installed language verifier over one shared corpus and exits
non-zero on any accept/reject disagreement, any difference in reason class (first failing check) or full check map,
any HANG (per-vector time budget, default 15 s) or CRASH, any committed-manifest drift, and any native-suite failure.
A language whose toolchain is absent is reported SKIPPED, never passed; `--require a,b,c` (used in CI) turns a skip into a failure.

## What the corpus contains (`packages/pca-conformance/adversarial/`)

`gen-adversarial.ts` deterministically regenerates the corpus (`--check` proves byte-identity). The full corpus is
~20 MB because it contains 1 MiB+ inputs, so only `manifest.jsonl` (id, category, name, intent, sha256, reference
verdict) is committed; the runner regenerates the corpus, and fails if it no longer hashes to the manifest.

| layer | count | what |
|---|---|---|
| adversarial categories | 786 | truncation, over-long, trailing garbage, duplicate keys, key order, JSON numbers, Unicode, resource exhaustion, base64/base64url confusion, Ed25519 malleability, alg/suite confusion + PQ downgrade, field injection / prototype pollution, attenuation widening, plan/commit mismatch, `grant_ref` binding (53 vectors: mismatch, non-root hop id, leaf holder key, case/whitespace/Unicode variants, very long, empty/absent/typed, empty chain), epoch boundaries, empty/duplicate caveat lists, plus the 172 shared golden vectors re-expressed (non-PQ) |
| `regressions/*.json` | 1 | minimised fuzz/sweep disagreements, replayed on every run |
| structural sweep | 6000 | every path of every distinct-shape valid seed x 9 replacements (delete, null, {}, [], "", 0, "x", [v], true) |
| seeded mutation fuzz | 600 default (`--fuzz N --seed S`) | byte/token/span/case mutations + field-level mutations + format-only rewrites |

Each vector carries an `intent` (what a reviewer expects) and the reference verdict. A vector where the reference
contradicts the intent is flagged `refDeviates` and must be listed in `adversarial/known-differences.json`.

## Coverage audit (before this work)

* `packages/pca/conformance/vectors.json`: 154 vectors (87 core negatives, 13 core positives, 22+14 PQ negatives, 9+9 PQ positives) + primitives (54 json_parse, 21 b64u, 5 canonical, 3 merkle, 7 threshold shares, 20 pq_artifacts). Each language runs it with its own test file: go, python, ruby, php, dotnet, java, rust (kotlin and swift have runners but need heavy toolchains).
* `tools/pca-diff-fuzz`: ~15.7k-case differential run (ed25519 core only) for go, python, ruby, php, dotnet (rust/java drivers were stale v1 code and never ran).
* Not covered: no single entry point or matrix; no per-vector time budget (a hang froze the whole run); no PQ downgrade / suite-confusion mutations; no NFC/NFD, homoglyph or zero-width audience cases; no huge-array / very deep nesting (100k) inputs; no S+L / R-sign-bit / identity-R mutations at the leaf level beyond the small-order forgeries; no `__proto__`/`constructor` shapes; Java and Rust were never in the differential run.
* Fixed in this work: Java and Rust differential drivers rewritten for wire v2; Go driver `go.mod` (needed `go 1.25` + circl) and .NET driver BouncyCastle pin (2.4.0 -> 2.6.1) repaired, which had silently made those two drivers unbuildable.

## Findings

1. **Ruby wire bug (FIXED)**: `sdks/ruby-pca` accepted `"threshold": {}` / `{"shares": null}` / `{"__proto__": {...}}` (`optional_wire_ok?` returned true when `shares` was nil). Reference and go/python/php/dotnet/java reject it as a wire failure. Found by the adversarial corpus (`field-injection/threshold-container-proto`) and independently by the structural sweep; the minimised sweep vector is `adversarial/regressions/fuzz-5b6a0ea20817.json`. The random mutation fuzzer alone did NOT find it in 4000 iterations, which is why the sweep exists.
2. **`grant_ref` is not bound (FIXED)**: `plan-commit/grant_ref-other`. A PCActn whose holder-signed `grant_ref` differed from `cap_chain[0].id` was ACCEPTED by the reference and by all native verifiers, and `packages/pca/src/replay.ts` keys the counter and nonce stores on `grant_ref`, so a holder could mint fresh `grant_ref` values and reset counter/nonce replay protection. Fixed by the new normative check `grant_ref_bound` (non-empty string, byte-equal to `cap_chain[0].id`, evaluated right after `cap_chain`, fail-closed on an empty chain) in the TypeScript reference and in the go, python, ruby, php, dotnet, java, rust, kotlin and swift verifiers; covered by the `grant-ref-bound` category (53 vectors) here and 18 `grant-ref-*` vectors in `packages/pca/conformance/vectors.json`. `known-differences.json` is empty again.
3. **Reference is the odd one out**: none found in this corpus (no `REF-ODD-ONE-OUT`).

## Known limitations of the corpus (honest gaps)

* The corpus is JSON-lines, so inputs that are not valid UTF-8/UTF-16 cannot be carried: overlong UTF-8, raw invalid bytes and raw lone surrogates are NOT exercised (their escaped forms, e.g. `\ud800`, are). The fuzzer replaces raw lone surrogates with U+FFFD because PHP and .NET reject the corpus line itself.
* PQ vectors in the adversarial corpus are all negatives. A verifier without ML-DSA support (python without dilithium-py, java without slh-dsa) rejects them for the *wrong reason*; the matrix compares only the first failing check, so this cannot distinguish "rejected the downgrade" from "unsupported suite". Positive PQ behaviour is covered only by the native suites (which count skips explicitly).
* Rust ran in CI only (no cargo locally); Kotlin and Swift runners are not part of the matrix (native test files exist: `sdks/kotlin-pca/.../ConformanceTest.kt`, `sdks/swift-pca/Tests/.../ConformanceTests.swift`).
* Reference source: when `packages/pca/src` is momentarily unloadable (another change in flight) `ref.ts` falls back to `packages/pca/dist` and prints it; CI always uses source.
