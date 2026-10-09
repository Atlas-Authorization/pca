# wasm artifact

`less_cat1.wasm` (NIST category 1, `CATEGORY=252 TARGET=45`) is built off-box with `scripts/lessbuild.sh`
(wasi-sdk-25 on x86_64 Linux); see ../README.md "Build provenance". After replacing it run
`node scripts/embed-wasm.mjs`.
