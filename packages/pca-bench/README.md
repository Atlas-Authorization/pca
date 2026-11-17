# @atlasauth/pca-bench

The cross-language performance gate for PCA: one deterministic benchmark corpus, one result schema, a statistical regression check, the
TypeScript harness (tinybench), and converters for the native SDKs' benchmark tools (Go testing.B, Rust criterion, JMH for Java and Kotlin,
BenchmarkDotNet, pytest-benchmark, benchmark-ips, PHPBench, swift-benchmark). Private workspace package; nothing here ships.

```sh
pnpm --filter @atlasauth/pca build
node packages/pca-bench/gen-corpus.mjs > corpus.json                      # public data only, byte-reproducible
node packages/pca-bench/bench.mjs --corpus corpus.json --out result.json   # TypeScript harness
node packages/pca-bench/compare.mjs gate --baseline packages/pca-bench/baselines/ts.json --candidate result.json
node packages/pca-bench/compare.mjs table result.json                      # markdown results table
pnpm --filter @atlasauth/pca-bench test                                    # the gate's own tests
```

[SPEC.md](./SPEC.md) is the contract (scenarios, metrics, schema, the gate rule, the baseline procedure). The native harnesses are in
`sdks/<lang>-pca/bench/`; the workflows are `bench.yml` in each repository's workflow directory.

Baselines are produced by CI on its fixed runner and committed after the first green run; until then the gate passes with a
"no baseline yet" notice.
