# pca-less-c

The LESS signature verifier the native PCA verifiers link for the `less-cat1` and `hybrid-ed25519-less-cat1` suites
(packages/pca/conformance/SUITES.md). LESS is a NIST additional-signature round-2 candidate, not a standard.

## Provenance

- `include/`, `lib/`: the 16 headers and 12 core sources of `Reference_Implementation/` from
  https://github.com/Atlas-Authorization/LESS, branch `atlas-verifier-hardening`, commit
  `0b8b9a07ce029bd9af12d701f5093c5ca0d9418b`: upstream https://github.com/less-sig/LESS at
  `6383430b9123e69d2ef6a6224f930972e3225610` (the commit `@atlasauth/pca-less-wasm` is built from) plus the verifier fixes
  of commits `d61ccf1` and `65befe3`. Copied unmodified; not copied: `lib/bench`, `lib/test`, `lib/nist` (the KAT harness,
  which needs OpenSSL), the CMake files. License: CC0 (`LICENSE`, upstream's).
- The fixes, for the three upstream verifier defects on forged signatures:
  1. `crypto_sign_open` (`lib/sign.c`) rejects an empty input and one shorter than the signature its trailing seed count
     claims (upstream underflows `smlen - sig_len` and `memcpy`s out of bounds);
  2. `CheckCanonicalAction` (`lib/monomial.c`) rejects a `cf_monom_actions` row with any padding bit 252..255 set (upstream
     counted them toward the weight check, then wrote past the 252-entry arrays);
  3. `crypto_sign_open` requires the seed count stored in the signature to equal the number of seeds the challenge makes
     `RebuildGGM` read (`CountPublishedSeeds`, `lib/seedtree.c`; upstream read up to 176 bytes past the signature). This
     also refuses a valid signature padded with extra seed bytes and a raised seed count, which the unpatched reference
     accepts.
  The fixed `crypto_sign_open` is memory-safe for every input length and content per the CBMC results in
  docs/pca/security/implementation-verification.md (section 3).
- `atlas_less.c` / `atlas_less.h` (Atlas): the verify-only API `atlas_less_cat1_verify(pk, msg, sig)` with the PCA
  semantics of `lessCat1Verify` in packages/pca/src/pq.ts: public key 97,484 bytes, detached signature 1,153..1,329 bytes in
  steps of 16, valid iff `msg || sig` opens under the key and yields exactly `msg`. It runs the reference on its own thread
  with a 16 MiB stack (the verifier keeps about 0.4 MB of matrices on the stack) and touches no global state, so it is
  thread-safe.

## Building

Parameter set `-DCATEGORY=252 -DTARGET=45` (less-252-45), C99, no SIMD defines. Consumers:

- Rust (`sdks/rust-pca`, feature `less`): `build.rs` compiles the crate's copy `less-c/` (or `ATLAS_PCA_LESS_SRC`) with `cc`.
- Go (`sdks/go-pca`, `-tags less` with cgo): `less_cgo.c` includes the module's copy `lessc/` into the package.

This directory is the canonical copy. The Rust crate and the Go module carry their own copies so that a crates.io build and
a published-module build need nothing outside them; `./sync-copies.sh` refreshes them and `./sync-copies.sh --check` reports
drift (each SDK's tests also compare its copy with this directory when both are present).
- Python (`sdks/python-pca`): `./build.sh [outdir]` builds `libatlas_less.{dylib,so}` (default `build/`); the ctypes
  backend finds it there or at `ATLAS_PCA_LIBLESS`.

Known answers: packages/pca/conformance/less-vectors.json (`gen-less.mjs`), run by each consumer's tests.
