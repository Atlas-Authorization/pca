# Changelog

See the full release notes in [docs/pca/CHANGELOG.md](https://github.com/Atlas-Authorization/pca/blob/main/docs/pca/CHANGELOG.md).

## 0.2.0

Breaking: the resource-server verifier (`requirePCA` and verdict computation) now lives in this package; new mandatory `grant_ref_bound` check; AMD SEV-SNP weights slot and the synthetic attestation profiles removed. Added: real AMD SEV-SNP, Intel TDX/DCAP, NVIDIA GPU, Azure MAA and GCP Confidential Space attestation roots, signed allowlists, PQ quorum certificates, the replay-store contract and FN-DSA suites. See the link above for the full list.
