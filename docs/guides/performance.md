# PCA verification performance

The numbers below are the cost of the hot path: verifying a Proof-Carrying Action in each language SDK. They come from one fixed,
versioned set of scenarios that every SDK runs with its language's standard benchmark tool, and a regression check in CI keeps them from
silently getting worse. If you size a deployment from them, read the method first: they are medians on a stated machine, not promises.

## What is measured

| Scenario | What it is |
|---|---|
| `verify.ed25519.d1`, `d3`, `d8` | verify a signed action carried over a capability chain of 1, 3 and 8 hops, every signature Ed25519 |
| `verify.hybrid.d1`, `d3`, `d8` | the same chains with every delegation hop and the action signed under the hybrid suite (Ed25519 + ML-DSA-65) |
| `verify.hybrid-pqroot.d3` | 3 hops with the root grant also hybrid |
| `verify.caveats.d3` | 3 hops carrying 25 caveats per hop (a caveat-heavy policy) |
| `deny.*` | refusals: bad signature at the leaf or at the first hop, wrong audience, expired, malformed, and a chain one hop over the limit |
| `canon.pcactn.*` | canonical form plus SHA-256 of a whole signed action |
| `sign.*` | produce the signature(s) of an action body |
| `authorize.*` | the full resource-server pipeline in single-step mode (verification, grant predicate, replay store, argument provenance): one allowed payment and two refusals |

Every key is derived from a public seed label when the corpus is built, so the corpus is byte-for-byte reproducible and contains no secret.
Before a scenario is timed, the harness checks that it computes the recorded answer (the same verdict, hash or signature in every
language), so a fast wrong answer cannot be published.

## Metrics

Operations per second, the median (p50), p95 and p99 latency of a single call, allocations per call where the runtime reports them, and a
cold-start time: the first verification in a freshly started process (this includes loading code and warming caches, so read it as a
lower bound on the first request after a deploy, not as a steady-state cost).

## Method

Each SDK uses its ecosystem's standard tool: Go `testing.B`, Rust criterion, JMH (Java and Kotlin), BenchmarkDotNet, pytest-benchmark,
benchmark-ips, PHPBench, swift-benchmark and tinybench (TypeScript). All of them write one common JSON schema, so the tables below mix
languages without a translation step. Each scenario is timed in at least seven time-ordered rounds; the gate compares the median of the rounds.
Runs happen on one fixed hosted runner type per SDK, three times in a row; results from different hardware are never compared.

## The regression check

On every CI run, each SDK compares its result with a committed baseline. A scenario fails only if **both** hold: its median is more than 20%
slower than the baseline's, and an exact one-sided rank test over the rounds of the three runs says the slowdown is not noise (p < 0.05).
A single slow run or a single slow round cannot fail the check, and a faster run never does. The check is deterministic: the same files give
the same verdict.

A refusal must never be slower than the acceptance it derives from, or an attacker could make the verifier do more work by sending
garbage: every `deny.*` scenario is checked against its allow counterpart on every run (it fails if it is more than 10% slower and the
same rank test agrees), with or without a baseline. The over-long chain is refused by its hop count before any signature work.

Before the first baseline is committed the check passes with a notice. To record or refresh a baseline, run the benchmark workflow on the
branch, download the artifact it uploads, and commit the candidate baseline file it contains in the same change as the performance change
that justifies it.

## Results

Filled in by the benchmark workflow from its latest run; empty until the first baseline run completes.

<!-- bench-results:start -->

_No results yet._

<!-- bench-results:end -->

## Reproduce a number

```sh
# TypeScript
pnpm --filter @atlasauth/pca build
node packages/pca-bench/gen-corpus.mjs > corpus.json
node packages/pca-bench/bench.mjs --corpus corpus.json --out result.json
node packages/pca-bench/compare.mjs table result.json
```

The other SDKs ship a `bench/` directory with the same entry point for their tool and a short header comment with the exact command.
