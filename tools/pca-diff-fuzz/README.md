# pca-diff-fuzz: cross-implementation audit of the PCA verifiers (wire format v2)

Differential + metamorphic fuzzing of every PCA reference verifier against one oracle, the TypeScript
core in `packages/pca` (`decodePCActn` + `verifyPCActnCore`, run from **source** via tsx, not `dist`). It answers one
question objectively: do all language implementations accept/reject the same PCActn and report the
same per-check results (`wire`, `version`, `audience`, `validity`, `chain`, `plan_inclusion`, `leaf_signature`,
`counter`)? The normative contract is `packages/pca/conformance/README.md`.

Read-only with respect to the rest of the repo: nothing outside `tools/pca-diff-fuzz/` is modified.

## Run

    tools/pca-diff-fuzz/run.sh                    # ~18k cases, ~4 min (pure-Python Ed25519 is the slow part)
    tools/pca-diff-fuzz/run.sh --bases 200        # smaller
    tools/pca-diff-fuzz/run.sh --seed 7 --only go,ruby

Needs `pnpm install` done at the repo root (for tsx + @noble) and, per implementation, its toolchain.
Missing toolchains are detected and reported as `skipped` (never silently ignored):
go, python3, ruby, php (with sodium), dotnet are exercised; rust needs `cargo`, java needs a real JRE/JDK.
The Rust and Java drivers are written but were **not executed** where no toolchain existed (UNVERIFIED; they were
not updated to the v2 signature, so update them before enabling those toolchains).

Outputs in `out/` (git-ignored): `corpus.jsonl`, `meta.jsonl`, `oracle.jsonl`, `impl-<lang>.jsonl`,
`REPORT.md` (human; starts with the HEADLINE + adversarial-class table), `report.json` (machine),
`divergences/*.json` (one minimal vector per divergence group, conformance-vector shaped).
`counterexamples/` (committed, small) holds one minimal vector per adversarial class with every implementation's
verdict, plus a `DIVERGENCE__*` file per residual divergence group.

Exit/CI use: `report.json` -> `divergences` (per impl) and `crossImplementation`; zero divergence means every
implementation that ran matched the oracle bit-for-bit on every case.

## Determinism

The corpus is a pure function of `--seed` (default 20261006) and `--bases`: mulberry32 RNG, fixed key pool
(`sha256("pca-diff-fuzz/<label>")` seeds), deterministic Ed25519, fixed `now` (1_800_000_000_000) and audience
(`rs-fuzz`). Two generations produce byte-identical `corpus.jsonl`.

## Corpus line shape

* `kind = verify`: `{id, kind, raw, grant, now, aud}`. `raw` is the **exact PCActn JSON text**; every implementation
  feeds it to its OWN strict parser (a parse failure is a `wire` failure, verdict `{allow:false, checks:{wire:false}}`).
  `grant` is the verifier's own trusted grant (strict-canonical text, read with each SDK's lenient loader).
  Verifier call: `verify(pcactn, grant, now, audience)`.
* `kind = canon`: `{id, kind, raw}`: any JSON text; each implementation strict-parses, strict-canonicalizes and hashes it
  (parse/profile failure => `error`); this fuzzes the strict JSON profile + number form + canonical key order directly.

## What is generated (`gen/generate.ts`)

* **valid** v2 PCActns: random grants / delegation chains (1-5 hops, sometimes 16/17) / plans (1-64 leaves) / actions /
  counters / caveats with unicode + nested values + in-profile decimals; `aud`, `iat`, `exp` (inside the accepted window),
  and the optional signed slots (`nonce`, `caution`, `rationale_commitment`, `progress_step`, `prohibition_evidence`,
  `tool_binding`, `zk_compliance`, `bond_ref`) plus the unsigned `threshold` container. The generator asserts the oracle
  accepts every valid base.
* **~330 mutators**, each tagged with the expected effect where it is unconditional (`breaks`, `mustReject`): signature
  flips/truncation/padding/whitespace/non-canonical base64url tails; tampering of every signed field with and without
  re-signing; Merkle proof index/size/sibling/side/path edits; capability-chain splice, drop, duplicate, reorder, foreign
  hop, depth 16/17; caveat widen/drop/reorder/edit with *validly signed* hops; missing/null/type-swapped/unknown fields
  (closed top-level set); **freshness**: audience mismatch (case/whitespace/confusable/length/astral), expired, `now == exp`
  boundary, `iat` future skew boundary, lifetime boundary (3 600 000 ms), seconds-instead-of-ms, bad `iat`/`exp`/`nonce`
  types and lengths; optional-slot validity; threshold container (unsigned, so adding it must NOT break the signature);
  non-canonical JSON/numbers (`1.0`, `7e0`, `-0`, 2^53+1, 1e21, 16-digit decimals, `<1e-6`, trailing fractional zero);
  lone surrogates (raw escape, reversed pair), duplicate keys (incl. after unescaping), comments, BOM, non-JSON whitespace,
  deep nesting around the depth-32 boundary, size limit (2^20) probes; Ed25519 strictness (S+L malleability, small-order /
  identity / non-canonical-y holder and issuer keys with forged `(R=small-order, S=0)` signatures).
* **canon** cases: ASCII escapes, BMP/astral, lone surrogates, random key-order objects, number-profile probes
  (digit counts 1..18, `1e-6` boundary, trailing zeros, lexeme-vs-value), JSON-profile probes (whitespace, comments, depth).
* **meta-preserving** (2.5k): format-only rewrites (whitespace, key shuffle, `\u` escaping, `\/`) of valid *and* mutant
  cases, done with a literal-preserving JSON AST (`gen/jsonast.ts`); each must give every implementation the same verdict
  as its base.
* **meta-numrepr**: integer literal `N` -> `N.0` / `Ne0`; in v2 this is non-canonical, so it must REJECT.

## What is compared (`compare.mjs`)

* suite capability (`suites.mjs`, conformance README "Suite capability"): every driver answers `{"id", "kind": "suites"}`
  with its manifest `{"id", "suites": [...]}` and tags a verdict whose reason carries `unsupported_suite` with an
  `unsupported_suite` field. A tagged refusal of a vector that carries a registered suite is the required verdict for an
  undeclared suite and is not compared with the oracle (a tag on a vector without one is a `SUITE(unsupported_suite)`
  divergence). The full rule, with each language's declared set, is enforced by `scripts/pca-conformance-all.mjs`.
* oracle vs each implementation: `allow` and the exact per-check key->bool map (a wire failure is `{wire:false}` only),
  parse-or-crash vs verdict (`accept-vs-error` is a real divergence; `reject-vs-error` is reported as `soft`), canonical
  string + hash for `canon` cases. Divergences are grouped by (impl, class, mutator); the shortest case in each group is the
  minimal counterexample with the changed byte region vs its base.
* implementation vs implementation with the oracle excluded (`sdkVsSdk`).
* metamorphic: preserving variants must keep each implementation's verdict; breaking mutants must make `allow=false` and
  every tagged check false (a wire failure counts as failing every check) in the oracle and in every implementation.
* the **adversarial-class table** at the top of `REPORT.md`: for each hostile class, how many must-reject cases each
  implementation ACCEPTED (0 everywhere = closed).

## Layout

    gen/generate.ts   corpus + mutators + metamorphic variants      gen/oracle.ts   TS oracle (strict parse + v2 verifier)
    gen/jsonast.ts    literal-preserving JSON AST + emitter         gen/safejson.ts spec parse (grant text / generator only)
    drivers/<lang>/   thin drivers over the UNMODIFIED sdks/<lang>-pca libraries (go, python, ruby, php, dotnet; rust*, java* not run)
    compare.mjs       diff + metamorphic assertions + REPORT.md     extract-counterexamples.mjs
    counterexamples/  curated minimal repros (committed)            repro/          pure-runtime repros

## CI gate

`.github/workflows/pca-conformance.yml` runs the TS reference tests, each language's conformance runner against the shared
`vectors.json`, and this fuzzer; `assert-zero.mjs` fails the job on any divergence from the oracle (and, with `--require`,
if an implementation did not run). Reproduce locally with `pnpm run pca:conformance` (skips missing toolchains, loudly).
For Java set `PCA_BC_JAR` to a `bcprov-jdk18on` jar.

**Follow-on:** each standalone per-language repo (`Atlas-Authorization/pca-*`) should carry the same conformance CI against
its vendored `vectors.json` once those repos are refreshed to wire-format v2, so a drift is caught in the published repo too.
