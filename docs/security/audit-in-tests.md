---
title: Audit in tests
order: 34
---

# Audit in tests

**Audience: integrators and reviewers.** This page describes the automated self-audit that runs over the whole PCA lineup, what it found, what was fixed, and what it cannot tell you. It is the project's own testing. **It is not an independent audit and does not replace one.**

Re-run the cheap parts with one command: `bash scripts/pca-audit-all.sh` (a few minutes, offline). `--full` adds the slow and networked tools.

## What runs

| Area | Tool (pinned) | What it does |
|---|---|---|
| Mutation testing | Stryker 10.0.0 (vitest runner) | Mutates the security-critical modules and checks that a test fails for each mutant. |
| Fuzzing | Purpose-built structure-aware mutator, deterministic by seed (`tools/pca-audit/fuzz`) | 55 targets: strict JSON, PCActn decode and verify, `requirePCA`, capability chains, thresholds, replay, ledger and Merkle proofs, tree heads, revocation, beacons, post-quantum verify seam, the attestation evidence parsers and verifiers (Intel DCAP/TDX quotes, NVIDIA SPDM, AMD SEV-SNP, Azure MAA and GCP Confidential Space tokens, NVIDIA RIM/OCSP, Intel CRLs, allowlist manifests), SCITT/COSE, WebAuthn COSE keys, did:key, AP2 SD-JWT, GNAP, gateway paths, Cedar/Rego readers, and the `like`/`matches`/`re:` pattern operators. Seeds are the real captured hardware fixtures. |
| Static analysis | semgrep 1.180.0 (javascript, typescript, security-audit, nodejs, owasp-top-ten, secrets), eslint-plugin-security 3.0.1, `cargo clippy -D warnings` (Rust 1.99), cargo-deny 0.20.2 | Every finding is fixed or listed with a reason in `tools/pca-audit/static/triage.json`; the checker fails on anything untriaged. |
| Dependencies | osv-scanner 2.6.0 over `pnpm-lock.yaml` and 14 `Cargo.lock` files, pip-audit 2.10.1 over the Python adapters (all extras) | Triaged in the same file. |
| Secrets | gitleaks 8.30.1 | 194 raw hits over the PCA paths, all published test vectors, public hardware-attestation captures or build output; allowlisted by path with reasons in `tools/pca-audit/static/gitleaks.toml`. |
| Timing | dudect-style harness (Welch t-test on cropped distributions, `tools/pca-audit/timing`) | Positive and negative controls plus the signing, KEM and FROST operations. |
| Differential | `scripts/pca-conformance-all.sh` | Eight verifiers (TypeScript, Go, Python, Ruby, PHP, .NET, Rust, Java) over 5501 vectors including 80 new strict-JSON boundary vectors produced by the fuzzer: 0 disagreements. |
| Supply chain | `tools/pca-audit/supply/sbom.mjs` | A CycloneDX 1.5 SBOM per published package (76), lockfile integrity (3308 registry entries, all sha512, none from git or tarball URLs), install-script scan, provenance readiness (76 of 76 have repository, license, files list, public access, engines, README). |
| Threat model | `scripts/check-pca-traceability.mjs` | T-001..T-052 and G-01..G-19 all map to an existing test; the four previous gaps (T-008, T-015, T-019, T-041) now have tests. |

## Defects found and fixed

Each has a regression test that failed before the fix.

| Where | Defect | Found by |
|---|---|---|
| `pca` predicates (`re:` and `matches`) | Regular expressions in a signed grant that passed the "safe subset" check but take exponential time as a sequence of independent choices (`a?` repeated 30 times then `a` repeated 30 times then `b`: 54 s; `(?:a\|aa)` repeated 28 times: 29 s; also four-quantifier polynomial chains up to 21 s). The check now charges a backtracking-cost budget. | semgrep triage, then fuzzing with a regex grammar |
| `pca` predicates (`like`) | The glob operator, documented as linear, was not: `*a*a*a*b` against 500 characters took 45 s. Replaced by a two-pointer matcher, differential-tested against the old semantics on 20000 cases. | Reading the static-analysis hit, confirmed by measurement |
| `pca-analyzer` | `re:` intent scopes compiled with no guard at all. | Static analysis |
| `pca-policy-bridge` | Quadratic time in the Rego allow-rule scanner (200k spaces: 28 s) and in two Cedar clauses (80k spaces: 5 s). | Amplifying fuzz mutation |
| `pca-vc` | `did:key` base58 decode accepted unbounded input (150k characters: 8 s). | Fuzzing |
| `pca` ledger | `verifyWitnessedHead` and `detectEquivocation` threw on a head with an over-nested field instead of returning false. | Fuzzing |
| `pca` allowlist anchor | An inclusion proof could be relabelled with a different tree size than the signed head and still pass the proof check. The size is now bound to the head. | Fuzzing (property check) |
| `pca` | `strictParseBytes` leaked a raw `TypeError` on invalid UTF-8; `acceptBeacon` and `verifyChain` threw on malformed input. All now return typed errors or verdicts. | Fuzzing |
| `pca` dependency | `@xmldom/xmldom` 0.8.10 (15 advisories, plus a quadratic parse reachable before the RIM signature is checked) updated to 0.8.15. | osv-scanner, then fuzzing |
| `pca-abe` | AES-GCM decrypt without a pinned tag length. | semgrep |
| `rust-pca` | Not security-relevant lints; now clippy-clean. | clippy |

## Scores and results

- **Mutation score** (mutants killed, counting timeouts as kills; unviable and ignored excluded). `threshold.ts` 93.5 %, `replay.ts` 97.6 %, `pcactn.ts` 88.6 %, `server/verify.ts` 86.0 % (239 killed of 278 valid mutants), `capability.ts` 95.9 % (440 killed of 459; three further survivors were killed by tests added after that run). All five meet the 85 % target. Survivors in `capability.ts` and `server/verify.ts` are listed one by one, with the reason each is equivalent or unreachable, in `tools/pca-audit/stryker/equivalent-mutants.md`; the rest in the measured files are mostly optional-chaining and message-string mutants on paths that wire validation makes unreachable.
- **Fuzzing**: a 10 s per target run over all 55 targets executed about 5.4 million inputs with no untyped exception, no hang over 1 s, no prototype pollution and no accepted mutant after the fixes above. The fixed-seed gate (`fuzz.ts --regress`) also replays every stored crasher and takes about 15 s.
- **Dependencies**: osv-scanner reports 259 pnpm findings across the whole monorepo; 71 are in the production closure of PCA packages and 33 in dev closures. Fixed: xmldom. The rest are accepted with reasons in `triage.json` (peer chains of framework adapters, the optional snarkjs toolchain). Rust: one crate with no patch available, `pqc_kyber` 0.7.1 (KyberSlash division timing, unmaintained, an AVX2-only decryption flaw that does not apply to the wasm32 build), is vendored in the experimental lattice base-OT; this is an open, documented weakness. Python adapters: no known vulnerabilities in 5 resolved dependency sets.
- **Install scripts**: three dependencies in adapter closures run install scripts (`protobufjs`, `tree-sitter`, `@parcel/watcher`, via the LangChain, LlamaIndex and Next.js adapters). None is in the closure of `@atlasauth/pca`.

## Timing

The harness flags a deliberately leaky comparison with |t| of 400 to 530 and does not flag a branch-free one, so it can see a gross leak. Results on the author's machine (Apple silicon, Node 24, JIT, shared host):

- X25519 and FROST signing (fixed versus random share): no leak detected.
- Ed25519 signing and public-key derivation (fixed versus random secret): flagged (|t| about 100 to 220; the fixed secret is about 9 % faster). A null control (random versus random) is clean, but a fixed-A versus fixed-B test is only inconclusive (|t| 8 to 17). **This is unresolved.** It is consistent with cache and allocation effects of re-using one key, but this black-box test cannot separate that from a key-dependent timing difference in the underlying library. Do not read it either as a proof of a leak or as clearance.
- ML-DSA-65 signing: flagged, expected (rejection sampling runs a value-dependent number of rounds by design).
- Hybrid KEM decapsulation, valid versus random ciphertext: flagged; the harness cannot tell whether this reflects the implicit-rejection path's cost or a real distinguisher.

FROST scalar arithmetic is documented as not constant-time; the harness found no difference at this sample size, which is not evidence that there is none.

## Limits: what an independent human audit would still add

- A review of the protocol design and the threat model by people who did not write them; mutation and fuzzing check the code against its own tests and invariants, not the specification's soundness.
- Cryptographic review of the constructions (FROST, DKG, the post-quantum threshold and hybrid schemes, ABE, MPC, the proof systems), including parameter choices.
- Real side-channel evaluation. Wall-clock tests in a garbage-collected JIT runtime cannot establish constant-time behaviour; that needs instruction-level or hardware measurement and review of the dependencies' code (noble, the Rust crates).
- Coverage-guided fuzzing. The mutator here is structure-aware but has no coverage feedback, and runs for seconds to minutes per target.
- Review of operational assumptions the tests cannot reach: real multi-node stores, key custody, witness independence, hardware vendor root trust.
- Dependency review beyond advisories: a clean scan means no known advisory, not no vulnerability.
- Languages other than TypeScript are checked differentially against it on shared vectors, not independently fuzzed.

## Reproducing

```
bash scripts/pca-audit-all.sh            # cheap parts
bash scripts/pca-audit-all.sh --full     # adds long fuzz, timing, Stryker, osv-scanner, semgrep, clippy, cargo-deny, pip-audit, 8-language conformance
```

Steps whose tool is not installed are reported SKIPPED, never passed.
