# wasm artifact

`less_cat1.wasm` (NIST category 1, `CATEGORY=252 TARGET=45`) is built by `scripts/build-wasm.sh` from the patched reference
in `sdks/pca-less-c` (wasi-sdk 25.0, hash-pinned; reproducible on x86_64 Linux and arm64 macOS). `BUILD.json` records the
toolchain, the source digest and the artifact SHA-256; see ../README.md "Build provenance". After replacing it run
`node scripts/embed-wasm.mjs`.
