# Changelog

See the full release notes in [docs/pca/CHANGELOG.md](https://github.com/Atlas-Authorization/pca/blob/main/docs/pca/CHANGELOG.md).

## 0.3.0

Lockstep release of the whole family. 0.2.0 is superseded. Breaking: `@atlasauth/pca-scitt` leaf format (RFC 9162), `@atlasauth/pca-vdf` `setup` renamed `insecureDevSetup`, `stark-pca` / `stark-pca-plonky3` public-input layout (full 256-bit commitments). Security fixes: VDF zero-work forgery, non-canonical Ed25519 points (mpc-wasm), OPRF scalar malleability, CIBA guessable request id, Envoy query-string deny. See the link above for the full list and migration notes. This package itself has no API change.

## 0.2.0 (superseded by 0.3.0)

Breaking: the resource-server verifier (`requirePCA` and verdict computation) now lives in this package; new mandatory `grant_ref_bound` check; AMD SEV-SNP weights slot and the synthetic attestation profiles removed. Added: real AMD SEV-SNP, Intel TDX/DCAP, NVIDIA GPU, Azure MAA and GCP Confidential Space attestation roots, signed allowlists, PQ quorum certificates, the replay-store contract and FN-DSA suites. See the link above for the full list.
