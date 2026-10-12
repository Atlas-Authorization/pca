# Verification index

One page listing every machine-checked or tool-checked claim in this repository: the artifact, the tool and
version, how to re-run it, and what it does **not** cover. Tool versions are pinned in
[`TOOLCHAIN.lock`](../../TOOLCHAIN.lock); the Dafny pin is additionally hash-checked by
`formal/dafny/verify-toolchain.sh`.

**No independent third-party audit has been performed.** Read [the security review summary](./security-review-summary.md)
before relying on anything here. "Verified" below always means "accepted by the named tool for the named
artifact"; it never means "the shipped system is secure". The system-level gaps are in section 4.

## 1. Re-running on a fresh Linux machine

Target: Linux x86_64 (the recorded runs used Ubuntu 22.04 and 24.04), 4+ cores, 16 GB RAM or more for the
heavy tools. From the repository root:

```sh
verify/install-toolchain.sh all-cheap      # Dafny (hash-pinned) + Tamarin/Maude + TLA+ jar; uses sudo apt
make toolchain-check                       # installed versions vs TOOLCHAIN.lock
make verify                                # cheap pass: Dafny core + TLA+ contract models (minutes)
make verify-all                            # everything below (many hours, all tools needed)
```

Each `verify-*` target copies the sources to `.verify-work/` and runs there, so the committed result files
under `formal/*/results/` are not overwritten; compare with `diff -r formal/<x>/results .verify-work/<x>/results`.
A timeout in Tamarin or ProVerif is printed as `TIMEOUT` and is **not** a proof. Raw logs larger than 256 KiB
were not mirrored into this repository; `formal/OMITTED-LARGE-LOGS.txt`
lists them with sizes and SHA-256 of the originals, and the per-model result summaries are kept.

| Tool | Pinned version | Install |
|---|---|---|
| Dafny (bundled Z3 4.12.1) | 4.11.0 | `verify/install-toolchain.sh dafny` (zip hash verified before unpacking) |
| Tamarin prover + Maude | 1.12.0 + 3.5.1 | `verify/install-toolchain.sh tamarin` |
| ProVerif + CryptoVerif | 2.05 + 2.13 (OCaml 4.14.2, opam) | `verify/install-toolchain.sh proverif` |
| TLC (TLA+) | recorded with nightly 2026.10.06.014338; a release `tla2tools.jar` is a valid re-check | `verify/install-toolchain.sh tla` |
| Apalache (optional) | 0.62.3 | manual |
| EasyCrypt | r2026.09-29-ge7eff05 (git e7eff05dcef1), Why3 1.8.2, Alt-Ergo 2.6.4, Z3 4.8.12, CVC5 1.1.2 | `verify/install-toolchain.sh easycrypt` (slow opam build; then install Z3 and CVC5 at the pinned versions) |
| Lean 4 / Mathlib | v4.34.1 / tag v4.34.1 | `verify/install-toolchain.sh lean` (Mathlib via `lake exe cache get`) |
| Verus, Kani, CBMC, Miri | release 0.2026.10.04.426d8b0 (rustc 1.98.1); Kani 0.68.0; CBMC 6.11.0; Miri nightly 2026-10-08 | `verify/install-toolchain.sh verus` |
| Node / pnpm / tsx | >= 20 (recorded on 22) / 9.15.0 / 4.23.1 | your package manager; `pnpm install` |

The install scripts for Dafny, Tamarin, TLA+ and the Lean/opam bases follow the recorded setup. The
EasyCrypt installer is a best-effort recipe of the recorded versions and has not been re-run from scratch on
a blank machine; check it with `make toolchain-check` before trusting a result.

## 2. Claims, artifacts, tools, and gaps

### 2.1 Verified decision core (Dafny)

| Claim | Artifact | Tool | Re-run | Not covered |
|---|---|---|---|---|
| The verdict combinator, capability-chain walk and attenuation, caveat evaluation, threshold step-up and replay guard decisions are correct against their specifications, for all inputs; the compiled JavaScript equals a fresh compile | `formal/dafny/{Common,Chain,Caveats,Threshold,Replay,Verdict}.dfy`; generated code in `packages/pca-verified-core/generated/` | Dafny 4.11.0, Z3 4.12.1 | `make verify-dafny` (also `formal/dafny/build.sh --verify-only` and `--check`) | Parsing and wire validation, Policy VM, freshness and attestation verification, ZK and bond verification, the numeric details of doubles; cryptographic security of any primitive; side channels; liveness. Only how check *results* combine is proved |
| Extension modules: strict JSON and canonical encoding, Merkle inclusion and consistency (RFC 6962/9162), taint, attestation-result combination, Policy VM decision, regex engine | `formal/dafny/{Wire,Merkle,Taint,Attest,PolicyVm,Regex}.dfy` | Dafny 4.11.0 | `make verify-dafny` | Each is a verified model-level module with a typed adapter and differential tests; check [verified core](../security/verified-core.md) for which are wired into production paths. SHA-256 beneath Merkle is an assumption |
| The glue contract that the TypeScript must meet | `formal/dafny/GlueContract.dfy` | Dafny 4.11.0 | `make verify-dafny` | The contract is stated and used, not proved of the TypeScript; it is checked at run time by a monitor and by differential testing |
| Trusted-base shrinking: toolchain hash pin, proofs, reproducible generated code, compilation to five targets compared on millions of cases, SBOM | `tools/pca-trustbase/`, `formal/dafny/TOOLCHAIN.lock`, `formal/dafny/difftargets/` | Dafny 4.11.0 plus .NET, Go, Java, Python, Node | `make verify-trustbase` (needs those runtimes) | Dafny front end, Boogie and Z3 soundness; common-mode compiler bugs; primitives are cross-checked across implementations, not proved; the Node/V8 runtime is trusted. See [trusted base](../security/trusted-base.md) |

### 2.2 Symbolic protocol models

| Claim | Artifact | Tool | Re-run | Not covered |
|---|---|---|---|---|
| Authorization, leaf-signature authenticity, root and hop attenuation, nonce and counter replay freedom, audience binding, step-up requirements, attestation binding hold on the shipped models; each check is shown necessary by an attack when removed | `formal/tamarin/*.spthy`, results in `formal/tamarin/results/` | Tamarin 1.12.0, Maude 3.5.1 | `make verify-tamarin` | **Open or not proved**: the explicit-clock expiry lemma on the shipped clock models; counter-store race; budget invariants; FROST `shares_bound_to_session` and, on the shipped model, `share_secrecy` and `sig_needs_t_signers`; allowlist rollback on the shipped model and the anchored fix. Expiry in the v1 models is an ordering restriction. Perfect-cryptography (Dolev-Yao) model only |
| Unbounded delegation chains | `formal/tamarin/pca_actn_unbounded.spthy` | Tamarin 1.12.0 | `make verify-tamarin` | Bounded v1 models cover depth 1 to 3; unbounded models cover the lemmas listed as verified in [formal verification](../security/formal-verification.md); the rest timed out |
| The same properties in a second tool | `formal/proverif/*.pv`, `formal/proverif/AGREEMENT*.md` | ProVerif 2.05 | `make verify-proverif` | Replay uses a restriction, because ProVerif cannot express an atomic consume-once store; atomicity is shown only in Tamarin and Lean. Bounded chain depth |
| Computational proofs found automatically: leaf and root authorization, depth-2 delegation, `grant_ref` binding | `formal/proverif/cv/*.cv` | CryptoVerif 2.13 | `make verify-cryptoverif` | Everything beyond those statements (replay, unbounded chains, key compromise, threshold, attestation, FROST) rests on perfect cryptography in the symbolic models |
| Effective authority only narrows along chains of any length; replay machine never double-accepts; counters strictly increase | `formal/pca-lean/`, `formal/pca/*.tla`, `formal/refinement/` | Lean v4.34.1 (no `sorry`, axioms `propext`, `Quot.sound`); TLC | `make verify-lean` | Link to the shipped code is by identical definitions and differential tests, not extraction. The refinement note states the one gap Lean cannot close |

### 2.3 Computational (reductionist) proofs

| Claim | Artifact | Tool | Re-run | Not covered |
|---|---|---|---|---|
| Action-authorization unforgeability with bound `Adv_cr + mu * Adv_suf`; domain separation; EUF-CMA at most SUF-CMA | `formal/computational/ec/{PcaCore,MU,Sig}.ec` | EasyCrypt r2026.09-29-ge7eff05 | `make verify-easycrypt` | Ed25519 SUF-CMA and SHA-256 collision resistance are premises, not proved. Encoding-injectivity facts are explicit `axiom`s listed in the assumption index of [computational proofs](../security/computational-proofs.md) |
| Role-bound t-of-n multisig, no role or threshold confusion, counting; hybrid AND-combiner (EUF-CMA, corrected SUF-CMA for a deterministic first component, unpinned second key) | `ec/{PcaMultisig,Hybrid,HybridSUF}.ec` | EasyCrypt | `make verify-easycrypt` | Hardness of the component schemes is assumed (including the post-quantum ones). The original SUF statement for randomised components is false, and the file proves the corrected one |
| Pedersen binding and hiding; Schnorr and OR-proof special soundness; range extraction; budget integer step | `ec/PcaPedersen.ec` | EasyCrypt | `make verify-easycrypt` | Algebraic core only: the rewinding that yields two transcripts is the forking lemma (below). Abstract prime-order group instead of ristretto255 |
| Forking lemma, ROM knowledge soundness of one proof and of the 33-challenge composite range proof, completeness, HVZK, FROST verification equation, STARK/FRI proven-bits arithmetic, primality of 2^61-1 | `formal/computational/leanmath/` | Lean 4 v4.34.1 + Mathlib v4.34.1 | `make verify-leanmath` | Statements in the random-oracle model; the Ed25519 forking-lemma bound is not proved; STARK formulas are taken as given from the cited theorems; instantiating some numbers is paper arithmetic |
| Chain attenuation at the digest level with the collision escape | `formal/computational/lean/` | Lean v4.34.1 (core) | `make verify-lean` | Collision resistance assumed |
| SPDZ MAC-check and triple sacrifice soundness; multi-phase MAC-check game; composition over adaptive sessions; hash-commitment hiding in the ROM; ROM collision bound | `ec/{PcaSpdz,PcaSpdzProto,PcaSpdzSeq,PcaCommitROM,PcaRomCollision,Prime61}.ec` | EasyCrypt | `make verify-easycrypt` | The protocol-level hop for commitment hiding is a paper reduction. Idealisations are listed in section 5 of [computational proofs](../security/computational-proofs.md). **KOS oblivious transfer parameters are argued, not proved**, and the offline MPC selective-failure analysis is a documented limitation, see [MPC soundness](../security/pca-mpc-spdz-soundness.md) |

Full claim ledger with status words (EC, Lean, Paper, Named assumption, Open) and the named assumptions:
[computational proofs](../security/computational-proofs.md). Items marked Paper (for example replay-freedom
under the store contract, canonical JSON injectivity, FROST DKG) are written proofs that are not machine-checked;
FROST DKG is listed as open.

### 2.4 Replay store

| Claim | Artifact | Tool | Re-run | Not covered |
|---|---|---|---|---|
| The replay contract (`consumeOnce`, `prune`, `advance`) gives exactly-once acceptance under bounded clock skew; each store strategy (Postgres variants, Redis, in-memory, durable file lock) is either shown correct or shown broken by a counterexample | `formal/tla/*.tla`, `formal/tla/cases.txt`, results in `formal/tla/results/` | TLC (recorded nightly 2026.10.06.014338), Apalache 0.62.3 for the unbounded-time inductive invariant | `make verify-tla` (cheap subset: `make verify`) | Bounded models (TLC); finite server, key and time bounds. Not a proof of the real database or Redis |
| The real stores are linearizable under concurrency and crash injection in the recorded campaigns; known-bad stores are detected | `tools/pca-linearizability/` (Go checker, scenarios, campaign result files) | Custom Go checker with real Postgres and Redis | `make verify-linearizability` runs only the checker's own unit tests; the campaigns need Postgres and Redis (see `scenario.sh`, `campaign.sh`) | Sampled executions, not exhaustive; one deployment configuration per scenario; the checker's correctness is itself tested but not proved |

### 2.5 Implementation verification

| Claim | Artifact | Tool | Re-run | Not covered |
|---|---|---|---|---|
| Selected arithmetic and bounds in the Rust verifier, STARK reader, zkVM core and Plonky3 validator hold for all inputs of stated range (RFC 6962 split, path shape, safe-integer check, bounded reader, risk arithmetic, bounds validation) | `tools/pca-implverif/kani-*`, `verus/*.rs`, results in `tools/pca-implverif/results/` | Kani 0.68.0 (CBMC 6.11.0), Verus 0.2026.10.04.426d8b0 | `make verify-implverif` runs the Verus files and the Lean reference model. **Kani, CBMC and Miri lanes need the native verifier sources from their own repositories** and are driven by `tools/pca-implverif/*.sh` after adjusting paths; they are not part of `make verify-all` | Several Kani harnesses ran out of memory and are recorded as not concluded; scope labels (unbounded, full-size, bounded-N) are stated per result in [implementation verification](../security/implementation-verification.md). Verus files are transliterations related to the shipping code by line correspondence, not machine-checked refinement. Trusted: `base64`, `serde_json`, RustCrypto, dalek, `fips204` and other dependencies |
| No undefined behaviour on the full conformance corpus and decoders in the Rust verifier | `tools/pca-implverif/results/miri-rust-pca.txt` | Miri nightly 2026-10-08 | as above | Interpreted execution of exactly those inputs, not a proof; some decoder drivers were still running when the page was written |
| LESS (post-quantum, category 252) verifier memory safety on selected functions | `tools/pca-implverif/results/` | CBMC 6.11.0 | as above | Some solver runs ended without a conclusion; LESS_verify itself and other parameter sets were not verified |
| An independent Lean reference verifier agrees with the corpora | `tools/pca-implverif/lean-ref/`, `tools/pca-formal/lean-xcheck/` | Lean v4.34.1 | `make verify-implverif` | Agreement on the corpus, not equivalence |
| Side channels | `tools/pca-implverif/results/`, `tools/pca-audit/timing/` | valgrind (ctgrind), dudect-style harness | `make verify-audit` runs the harness self-check | LESS signing is measurably **not** constant time; JavaScript/TypeScript, Go, Python and the other verifiers were not checked for constant time |

### 2.6 Model-to-code conformance, differential testing and the audit program

| Claim | Artifact | Tool | Re-run | Not covered |
|---|---|---|---|---|
| The executable models agree with the real TypeScript implementation on millions of generated scenarios; deliberately broken model mutants are all detected | `tools/pca-formal/conformance/`, `tools/pca-formal/results/` | Node, tsx 4.23.1 | `make verify-conformance` (`CONF=full` for the large profile) | **Testing, not proof**: bounded configuration space (3 verbs, up to 3 hops, 3 holders, few nonces and counters). Memory safety, side channels, arbitrary-byte parsing and the unmodelled checks (plan, taint, freshness, revocation, ZK, bond, hooks) are not covered |
| Eight-language agreement on one conformance corpus | `conformance/`, `packages/pca/conformance/` | per-language runners in the native verifier repositories | see [`verifiers/README.md`](../../verifiers/README.md) | Agreement on the corpus and on the adversarial set, not a proof |
| Mutation-kill, fuzz regression, traceability, static analysis, supply-chain, timing self-check | `tools/pca-audit/`, `scripts/pca-audit-all.sh` | Stryker 10.0.0, eslint-plugin-security 3.0.1, custom fuzzers, SBOM tooling | `make verify-audit` (minutes, offline); `--full` adds long runs | Justified-equivalent mutants are a human judgement recorded in `tools/pca-audit/mutation-equivalents.json`; secret scan is skipped, not passed, if `gitleaks` is absent |

## 3. Result files kept in this repository

| Path | Contents |
|---|---|
| `formal/tamarin/results/`, `formal/proverif/results/`, `formal/proverif/cv/results/` | One summary per model and variant, with step counts, attack traces for removed-check variants, and tool version stamps |
| `formal/tla/results/` | One TLC output per configuration; `SUMMARY.txt` shows expected versus got |
| `formal/computational/CHECK-LOG.txt` | The recorded full run of the EasyCrypt and Lean checks, including the axiom listing of every headline theorem |
| `tools/pca-formal/results/`, `tools/pca-implverif/results/`, `tools/pca-linearizability/results/` | Conformance summaries; Kani, Miri and CBMC outputs; campaign summaries |
| `formal/OMITTED-LARGE-LOGS.txt` | Raw logs over the size cap that were not mirrored, with SHA-256 of the originals |

## 4. System-level gaps

These apply to the whole of section 2.

- **Model versus code.** Proofs are about hand-written models. No theorem is about the TypeScript, Rust, Python,
  Go, Swift or Kotlin implementations except the selected code in 2.1 (through the compiled core and its
  glue contract) and 2.5.
- **Primitives.** Ed25519, SHA-2/3, the post-quantum schemes, pairings and discrete-log assumptions are assumed.
  Nothing here proves them.
- **Toolchain.** The Dafny front end, Boogie, Z3, EasyCrypt, the Lean kernel, Tamarin, ProVerif, Maude and the
  JavaScript engine are trusted. Diverse compilation of the Dafny code reduces, but does not remove, compiler risk.
- **Distributed state.** Replay-store atomicity, durability, multi-instance clock skew and clock integrity are
  contracts the deployer must meet. The models check the contract; they do not check your database.
- **Specification gap.** "The key signed it" is not "the principal intended it". Prompt-injection and semantic
  attacks are outside every symbolic model here.
- **Not audited.** No independent third-party audit has been performed. Red-team proof-of-concept programs are
  intentionally not published; a sanitised account of the review rounds is in the
  [security review summary](./security-review-summary.md).

Detailed write-ups: [formal verification](../security/formal-verification.md),
[verified core](../security/verified-core.md), [computational proofs](../security/computational-proofs.md),
[implementation verification](../security/implementation-verification.md),
[replay-store verification](../security/replay-store-verification.md),
[trusted base](../security/trusted-base.md), [threat model](../security/threat-model.md).
