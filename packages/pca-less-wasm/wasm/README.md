# wasm artifact drop-in

The compiled LESS module goes here as **`less_cat1.wasm`** (NIST Category 1,
`CATEGORY=252 TARGET=45`).

It is **not** built on this Mac (no `wasi-sdk`). Produce it off-box:

```bash
# on an x86_64 Linux VM:
~/.pca-vm-state/lessbuild.sh /tmp/less-work /tmp/less-out
cp /tmp/less-out/less_cat1.wasm ./less_cat1.wasm
```

See `../BUILD_NOTES.md` for the full recon and `../README.md` for usage.
Until `less_cat1.wasm` exists here, every `@atlasauth/pca-less-wasm` call throws
a `LessError` pointing back to this step.
