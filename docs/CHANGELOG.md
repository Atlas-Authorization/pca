# Changelog

All notable changes to the `@atlasauth/pca*` packages and `create-pca-app`. Every package in the family is versioned in lockstep, so a release bumps all of them together. While the version is 0.x, minor releases may contain breaking changes.

## 0.2.0 - 2026-10-08

### Breaking

- **The resource-server verifier now lives in `@atlasauth/pca`.** Verdict computation and the framework-neutral `requirePCA` guard are exported from `@atlasauth/pca` itself. PCA no longer depends on any other product's SDK. The framework middleware packages (`@atlasauth/pca-fetch`, `-express`, `-fastify`, `-hono`, `-next`) depend only on `@atlasauth/pca` and no longer depend on any other product's SDK.
- **A new mandatory verification check, `grant_ref_bound`.** The holder-signed `grant_ref` of a PCActn must be a non-empty string byte-equal to the id of the root capability (`cap_chain[0].id`). The check is part of the default required checks and of the discovery defaults, and it fails closed on an empty or malformed chain. Previously a holder could sign arbitrary fresh `grant_ref` values and land on an empty replay/budget namespace for each action. PCActns that do not carry a matching `grant_ref` are now rejected; the conformance vectors were extended accordingly (the check is implemented identically in the TypeScript reference and the Go, Python, Ruby, PHP, .NET, Java, Rust, Kotlin and Swift verifiers).
- **AMD SEV-SNP: the invented "weights" slot is removed.** SEV-SNP has no native weights-measurement field; the previous convention read bytes that are actually part of the AMD report's committed-TCB / build fields. Reports no longer yield a `weights_measured` claim from those bytes. Anything that relied on that claim must obtain model-weights evidence from a source that really provides it.
- **`@atlasauth/pca-attest-eat` no longer carries its own AMD chain cryptography.** `verifySevSnpSignature` and `verifyAmdCertChain` are removed; `verifyAmdAttestation` (now async, as is `verifyFreshAttestedEAT`) delegates to the hardened `verifyGenuineSevSnpReport` in `@atlasauth/pca`. It now requires the verifier clock (`nowMs`; `verifyFreshAttestedEAT` passes its `now`), a `family` (`milan`, `genoa` or `turin`) or an explicit `trustAnchorArkSpkiSha384` in place of `rootFingerprint`, rejects debug-enabled guests unless `allowDebug` is set (replacing `requireDebugDisabled`), and enforces CA roles, strict extension parsing and the VCEK-to-report binding. `KNOWN_AMD_ARK_SPKI_SHA384` is now `{ milan, genoa, turin }`, so genuine Genoa hardware (Azure SEV-SNP) verifies.
- **The synthetic attestation profiles (SEV-SNP, Intel TDX, NVIDIA CC) are removed.** Use the real-evidence verifiers listed below.
- **NVIDIA GPU root: no workload identity by default.** The GPU root no longer derives a `runtime_measurement` from GPU state, so it composes with CPU TEE roots in an N-of-M policy instead of producing a false identity conflict. The GPU measurement digest is surfaced as `hostAsserted.gpu_measurements_sha384`; standalone deployments can supply `policy.deriveIdentity`.
- **Intel TDX: debug TDs are rejected** unless the policy explicitly sets `allowDebug`.

### Added

Attestation (verified against evidence captured from real hardware and real vendor services):

- AMD SEV-SNP report verifier with per-family ARK pins (Milan, Genoa, Turin), real report-field parsing (CPUID, committed/launch TCB, firmware versions, mitigation vectors), report v5, `minCommittedTcb` / `minLaunchTcb`, and runtime-data binding checked under AMD's signature.
- Intel TDX / DCAP quote verifier (`attestIntelDcap`) including Intel PCS collateral validation (TCB info, QE identity, CRLs), MRSEAM / MRSIGNERSEAM allowlists, and runtime-data binding checked under Intel's signature.
- NVIDIA GPU confidential-computing root (`attestNvidiaSpdm`) in the real SPDM / X.509 wire format, NVIDIA RIM golden-measurement verification and CRL revocation (`attestNvidiaRim`), OCSP revocation (`attestNvidiaOcsp`), and Hopper and Blackwell support (Blackwell RIM naming, wrong-family manifest rejection).
- Azure Attestation (MAA) root covering SEV-SNP and TDX CVMs, with a `sevSnpMinTcb` minimum reported-TCB policy and surfaced SVNs; built-in release-signed MAA trust pins (no trust-on-first-use) with multi-vantage corroboration.
- GCP Confidential Space root covering SEV-SNP and TDX on GCP.
- Multi-root N-of-M attestation policy across hardware roots, plus software/HSM post-quantum and PUF / TPM EK roots.
- Signed, versioned allowlist manifests (`attestAllowlist`), a rotation-safe MAA signing-key trust store (`attestMaaKeys`), transparency-anchored allowlist rollback protection, and crash-safe durable state (`@atlasauth/pca/durable-state`).
- `@atlasauth/pca-attest-eat`: per-session attestation freshness and channel binding emitting EAT (RFC 9711).

Authorization and protocol:

- Post-quantum t-of-n quorum certificates (`pqThreshold`): a composition of independent ML-DSA / SLH-DSA signatures with assumption diversity and rotation certificates. This is a quorum of signatures, not a compact threshold signature.
- Replay-store contract (`ReplayStore` / `CounterStore`, `guardPCActnReplay`) with a reference in-memory store, so multi-server deployments can plug in a shared store.
- Runtime-data binding for hardware attestation evidence (nonce and PCA action bound into the signed evidence).
- Step-up re-attestation: a held, attested step-up whose attestation nonce lapsed can complete with a fresh single-use nonce instead of failing unusably (hosted service).
- FN-DSA (Falcon, FIPS 206 draft) registered as the `fn-dsa-512` and `fn-dsa-1024` signature suites, backed by the new `@atlasauth/pca-fndsa-wasm`.
- LESS (a code-based signature, NIST additional-signature Round 2 candidate, not a standard) registered as the opt-in `less-cat1` and `hybrid-ed25519-less-cat1` suites (category 1, 97,484-byte public key, 1,153 to 1,329-byte signatures), usable on PCActn leaves and capability hops. Backed by the new `@atlasauth/pca-less-wasm`: the official LESS reference compiled to WebAssembly with a portable loader (Node, browsers, Deno, Bun, edge) and no dependencies. The backend is an optional dependency of `@atlasauth/pca`, loaded lazily; if it is absent the suites are reported unsupported and verification fails closed. LESS suites are implemented by the TypeScript reference only and are not in the shared conformance corpora; the other verifiers reject them as an unknown `alg`. The wasm reproduces the 100 official known-answer tests, matches native builds byte for byte on 600+ random inputs, and passed sanitizer runs; sanitizer fuzzing also found three memory-safety defects in the unmodified upstream verifier, which the wrapper works around. It is unaudited; use the hybrid.
- SHA-384 hash agility for Merkle and canonical hashing (non-breaking).
- Optional quantum-entropy mixing for key generation.
- Groth16 Policy-VM proofs are bound to the specific action.
- Post-quantum Module-LWE (endemic) base oblivious transfer in `@atlasauth/pca-mpc`, backed by the new `@atlasauth/pca-mpc-lwe-ot-wasm`.
- Native verifiers (Go, Python, Ruby, PHP, .NET, Java, Rust, Kotlin, Swift) reach conformance parity with the TypeScript reference, with an all-languages adversarial conformance matrix.

New packages: `create-pca-app` (scaffold a working app with `npm create pca-app@latest`), `@atlasauth/pca-fndsa-wasm`, `@atlasauth/pca-mpc-lwe-ot-wasm`. All three are published for the first time in this release; `@atlasauth/pca` and `@atlasauth/pca-mpc` now depend on the wasm packages.

All packages now ship a LICENSE file (MIT), repository / homepage / bugs / keywords metadata, an `engines` field (Node >= 20), and a README.

### Fixed

- Intel TDX: the PCK certificate chain's validity period is now checked against the verification clock (expired chains were previously accepted); issuers must be CA certificates with `keyCertSign` and respected path length, leaves must not be CAs (also applied to PCS TCB / QE issuer chains); debug quoting enclaves are refused.
- Elliptic-curve public points (Intel and AMD) are extracted through the platform key-object JWK export and fail closed; the byte-scan SPKI fallback is gone.
- `allowDebug` was lost on the collateral verification path.
- Denial-of-service: parsing of limit expressions backtracked quadratically (a 1 MiB run of whitespace hung the parser); it is now length-capped and linear. `decodeSafetyCertificate` now enforces the same maximum JSON size as the other strict parsers.
- Hosted service: a connection-pool deadlock and a race in step-up approval under concurrent approvals.
- `@atlasauth/pca-pq-threshold`: the classical FROST aggregate was verified through the multi-signature share verifier, which expects role-bound share bytes, so hybrid artifacts and folded step-ups it had just produced failed verification. The aggregate is now verified as an Ed25519 signature under the trusted group key.
- `@atlasauth/pca-fndsa`: the missing-backend error now names the real backend package, `@atlasauth/pca-fndsa-wasm`.
- `create-pca-app`: scaffolded projects depend on `^0.2.0` of the PCA packages.
- Packaging: `@atlasauth/pca-invariants` declares `fast-check` as a runtime dependency (it was a dev dependency and the package failed to load once installed); `@atlasauth/pca-conformance` ships `vectors.json`, which its `exports` map already referenced.

### Security notes

- `grant_ref_bound` closes a replay-namespace bypass (see Breaking). Deployments that persist replay state keyed by `grant_ref` do not need migration, but clients must send the root capability id as `grant_ref`.
- Hardware-attestation verification now rejects debug-mode TEEs, expired or non-CA certificate chains, and quoting enclaves in debug mode by default.
- The cryptography in these packages, including the post-quantum, threshold, MPC and zero-knowledge components, has not been independently audited. Experimental packages are labelled as such in their READMEs. FN-DSA tracks a draft standard and its encodings may change before the final FIPS 206 text.
- Report vulnerabilities through the repository's security advisory channel rather than a public issue.

## 0.1.0

Initial public release of the PCA package family.
