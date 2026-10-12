# PCA verified decision core (Dafny)

This page states what is machine-proved about the **decision logic** of the PCA verifier, how that proved code reaches the
shipped TypeScript, what the trusted base is, and exactly what is *not* covered. Read the "Not covered" section.

It complements `formal-verification.md` (Tamarin: symbolic protocol model, bounded chains; Lean: unbounded chain / store models
that are separate hand-written abstractions). The difference here: the Dafny sources are **compiled to JavaScript and that
JavaScript is the code the verifier runs** for the decisions listed below, so there is no model-to-code gap for them (the gap
moves to the primitive-evaluating glue, listed under the trusted base).

## What the core is

The verifier is split into two layers:

1. **Glue (TypeScript, trusted)**: parses the artifact and evaluates every cryptographic or structural primitive (Ed25519 /
   ML-DSA / SLH-DSA / FN-DSA signature checks, canonical hashing, strict wire validation, Merkle inclusion, hook calls) and
   renders the legacy error strings. Files: `packages/pca/src/verified-decision.ts` and the call sites in
   `packages/pca/src/pcactn.ts` and `packages/pca/src/server/verify.ts`.
2. **Decision core (Dafny, proved)**: takes the *results* of those primitives (booleans, small enums, integers, opaque
   messages, and lazy pure closures standing for primitive evaluations) and decides: the order in which facts are consulted,
   the first failure, depth bounds, caveat-prefix attenuation, the threshold distinct-role count, the replay decision order,
   suite / PQ-pin rules, the check fold, the hook-enforced-`t` rule, `enforceRequired`, and the final `allow`.

Source: `formal/dafny/{Common,Chain,Caveats,Threshold,Replay,Verdict}.dfy` (about 1,600 lines). Compiled output, committed:
`packages/pca-verified-core/generated/pca_core.js`. Typed API (no Dafny runtime type leaks): `@atlasauth/pca-verified-core`.

## Tool versions and trusted-base audit of the Dafny sources

| Item | Value |
|---|---|
| Dafny | 4.11.0 (`4.11.0+fcb2042d6d043a2634f0854338c08feeaaaf4ae2`) |
| Z3 (bundled with Dafny, used for all proofs) | 4.12.1 (the Dafny zip also carries 4.14.1; the default 4.12.1 is used) |
| .NET runtime | 8.0.131 |
| Last full verification | **171 verified, 0 errors** (`dafny verify ... --verify-included-files`, re-run 2026-10-12; `GlueContract.dfy` with the core included: 174 verified, 0 errors) |
| `assume` statements | **0** |
| `{:axiom}` attributes | **0** |
| `{:extern}` / `extern` | **0** |
| `{:verify false}` / `{:fuel}` hacks | 0 (no verification is switched off) |

`formal/dafny/build.sh` greps the sources for `assume`, `{:axiom}` and `extern` on every run and fails if any appear. The only
things the proofs *inherit* are Dafny's built-in axioms for sequences, sets, maps and mathematical integers, and the soundness
of Dafny's Boogie / Z3 pipeline (see the trusted base).

## Theorems (Dafny file : lemma)

All statements are for **all inputs**, including chains of any length (up to the explicit depth guard, which is itself proved),
any number of shares, and any interleaving of replay-store operations. None uses a bound or a fixed instance.

### Capability chain walk and attenuation (`Chain.dfy`, `Caveats.dfy`)

| Lemma | Statement |
|---|---|
| `Chain.ChainSound` | `VerifyChain` accepts => `1 <= |hops| <= 16`, every hop well-typed, root has no parent and the expected issuer, every hop passed its suite-policy, PQ-binding, parent-link, issuer-is-parent-holder and signature facts, the budget_alloc check passed, **and each hop's caveat list has its parent's as a prefix** (as judged by caveat equality). |
| `Chain.ChainComplete` | the converse: if every fact above holds, the chain is accepted (no spurious denial). |
| `Chain.WalkSound`, `Chain.WalkComplete` | the same by induction on the hop index (the unbounded-length argument). |
| `Chain.ChainAttenuates` | for any caveat semantics `allows` that respects caveat equality: if an action is permitted at hop `i` of an accepted chain, it is permitted at **every** ancestor `j <= i`, i.e. effective authority is antitone down the chain. Built on `Chain.PrefixAntitone`. |
| `Chain.ChainCaveatsGrow` | along an accepted chain the caveat list never shrinks. |
| `Chain.DepthBound` | a chain of more than 16 hops is **always** `TooLong`; acceptance implies at most 16 hops. |
| `Chain.WalkExt` | determinism: the verdict depends only on the observable facts of the hops (extensionality). |
| `Caveats.VerbResourceSubset` | concrete algebra (verb pins, resource pins, expiry): in an accepted chain, an action permitted at hop `i` has its verb in every verb pin and its resource in every resource pin of every ancestor, and is not past any ancestor's expiry. |
| `Caveats.ChainExpiryMonotone` | the effective expiry (min over `ExpiresAt` caveats) along an accepted chain only moves earlier. |

### Threshold step-up (`Threshold.dfy`)

| Lemma | Statement |
|---|---|
| `Threshold.BuildRegValid`, `RegBounded` | a signer set that validates is a registry with one key per role and one role per key, with at most 3 entries. |
| `Threshold.StepInv`, `FoldInv`, `BaselineInv`, `RolesDistinct` | the counted keys are pairwise distinct, every counted `(role, key)` is registered, and the counted roles are pairwise distinct. |
| `Threshold.ThresholdSound` | `Verify` accepts => `t` in {1,2,3}; count == number of **distinct roles** == number of distinct keys, `count >= t`, `count <= 3`; every counted role is registered. |
| `Threshold.ThresholdThreeNeedsAllRoles` | `t = 3` accepted => agent, guardian and principal all contributed. |
| `Threshold.FailsClosed` | an invalid `t` or a malformed signer set is never rescued by shares or the agent baseline. |
| `Threshold.DuplicateIgnored` | a repeated key is never counted twice. |
| `Threshold.FoldExt`, `StepExt` | determinism / extensionality. |

### Replay guard and replay store (`Replay.dfy`)

| Lemma | Statement |
|---|---|
| `Replay.GuardSound` | the guard accepts => audience matches, the window is valid and bounded, `iat <= now + skew`, `now <= exp`, leaf / components / counter well-formed, and the nonce store answered "first" and the counter store answered "greater" whenever they were consulted. |
| `Replay.NoStoreBeforePre`, `GuardHardFailures` | no store is consulted before every pre-check passed; an audience mismatch is always `Audience`; expiry and not-yet-valid are hard failures. |
| `Replay.NoDoubleAccept` | **nonce replay freedom** for the store contract (model of `InMemoryReplayStore`): once `consumeOnce(k, retain r)` is accepted, after ANY sequence of consume / prune / advance operations whose clock readings are `<= r`, a further `consumeOnce(k, ...)` at a time `<= r` is never accepted. Supported by `RunKeepsHeld`, `PruneKeepsLive`. |
| `Replay.CounterStrict` | once counter `c` is accepted on a stream, any later advance with `c2 <= c` is never accepted, whatever happened in between (strictly increasing accepted counters). |
| `Replay.ConsumeFailClosed` | an invalid key or a retention horizon before `now` is never accepted. |

### Verdict combinator (`Verdict.dfy`)

| Lemma | Statement |
|---|---|
| `AudienceSound` | pass only when the verifier's audience equals the signed `aud`; a forgotten verifier audience on a PCActn that carries `aud` is **Fail** (fail-closed); `null` is the only opt-out. |
| `ValiditySound`, `NoAcceptAfterExpiry`, `ValidityWindowBound` | pass <=> safe-integer clock, `exp > iat`, `exp - iat <= 3,600,000`, `iat <= now + 60,000`, `now <= exp`; an expired PCActn is never valid. |
| `GrantRefBoundSound` | `grant_ref_bound` passes only for a non-empty string `grant_ref` byte-equal to the root capability id. |
| `PqResolveSound` | R2-01 / R3-01 choke point: a PQ verification key is resolved only with verifier-side authority (own configured key, a pin, or a `holder_pq` commitment, or the explicit legacy opt-out); a pin that disagrees with the artifact is **always** a refusal, even with the opt-out; the unbound path is reachable only when enabled and nothing else vouches. |
| `PqBindingSound`, `SuitePolicySound` | F-2 / R2-01: a PQ-key suite is accepted only under a matching `holder_pq` commitment (unless the loud legacy opt-out is set); F-4: with `allowedSuites` set, an algorithm outside it is never accepted. |
| `LeafSound`, `CapChainSound` | the leaf passes only if present, its suite / binding is fine, and the signature is a string and verifies; `cap_chain` passes only if non-empty, rooted at the grant, and the walk accepted. |
| `CoreAllowIff`, `CoreFailDenies`, `WireTerminal`, `CoreFirstReasonWins` | core `allow` <=> no check failed; a recorded failure always denies; a wire failure is terminal (only `wire` reported); the reason is the first failure recorded. |
| `ZkRuleSound`, `ZkRuleMonotone`, `AttestGateSound` | a zk proof that no verifier enforced is denied; the attestation gate never weakens a verdict. |
| `MissingBindingDenies` | **no allow on a missing binding**: a grant that binds the agent with no passing `attestation` check is always denied. |
| `HookEnforcedT`, `ThresholdRuleSound` | **F-1**: if the final verdict allows, the server requires `t > 1` and the policy released the share, then the threshold check passed **and** the hook reported enforcing at least `t`. |
| `ReversibilitySound` | the agent's declared class can only make the effective class stricter. |
| `EnforceMonotone`, `EnforceRequiredPass`, `EnforceChecksStable`, `EnforceNoFail` | `enforceRequired` never turns a deny into an allow; if it allows, every required check is `pass`. |
| `FinalizeSound` | the end-to-end statement: final `allow` => core allowed, the Policy VM released the share, no check is `fail` (before and after enforcing), and every required check is `pass`; reasons only grew. |
| `EnforceReasonsAppend`, `ReasonsAppendOnly`, `DeniedAlwaysHasReason` | reason ordering: reasons are append-only in event order; a deny is never silent. |
| `EnforceDeterministic` | determinism of the combinator. |

## How the proved code reaches production

* `formal/dafny/build.sh` verifies every file and compiles with `dafny translate js ... --include-runtime`, then appends the
  export footer `formal/dafny/Footer.js`, writing `packages/pca-verified-core/generated/pca_core.js`.
* `formal/dafny/build.sh --check` (script `check:generated` in the package) recompiles into a temp directory and fails unless the
  committed JavaScript is **byte-identical**.

### Wiring status (what production actually runs)

| Decision | Proved in | Production TypeScript runs the verified code? |
|---|---|---|
| check fold of `verifyPCActnCore` (first reason, allow iff no fail, wire terminal, malformed, zk rule, attestation gate) | `Verdict.dfy` | **yes** (`pcactn.ts` uses `CoreState`) |
| audience, validity/skew/expiry, version, `grant_ref_bound`, counter, leaf decision, F-2 PQ-binding rule, F-4 suite policy, hook status, `cap_chain` status (empty / root-is-grant / walk) | `Verdict.dfy` | **yes** (`pcactn.ts`, `verified-decision.ts`) |
| `verifyPCActn` combinator: `grant_ref`, plan, beacon, reversibility, delegated caveats, policy, F-1 threshold rule, attestation-required rule, final `allow`, `enforceRequired`, reasons order, `denied` fallback | `Verdict.dfy` | **yes** (`server/verify.ts` uses `VerdictState`, `enforceRequired`) |
| capability-chain **walk** (hop order, depth bound, caveat-prefix attenuation, first failure) | `Chain.dfy` | **yes** (`capability.ts` `verifyChain` -> `decideChain`; `pcactn.ts` then folds its status) |
| F-2 PQ-binding rule and F-4 suite policy for chain hops | `Verdict.dfy` | **yes** (`capability.ts` `pqBindingError` / `suitePolicyError` -> `pqBinding` / `suitePolicy`) |
| threshold distinct-role count, signer-set validation (one key per role, one role per key), `t` rule, first failure | `Threshold.dfy` | **yes** (`threshold.ts` `verifyThreshold` -> `decideThreshold`) |
| replay-guard decision order (no store call before every pre-check passed), consume-once nonce plan, verdict | `Replay.dfy` | **yes** (`replay.ts` `guardPCActnReplay` -> `replayPre` / `replayNonceStage` / `replayDecide`) |
| replay STORE model (`ConsumeOnce` / `PruneMap` / `AdvanceCounter`) | `Replay.dfy` | **no, by design**: the proof is of the store contract; `InMemoryReplayStore` is differential-tested against `VerifiedReplayStoreModel`. |
| effective expiry = min over `ExpiresAt` caveats (`Caveats.ChainExpiryMonotone`) | `Caveats.dfy` | **no**: a semantic lemma about caveat evaluation; production has no TypeScript counterpart in the chain verifier (caveat semantics are evaluated by the Policy VM, not proved here). |

In each wired function the TypeScript evaluates the primitives (parsing, canonical hashing, `resolvePqVerifyKey`, signature
verification, `allocationsMonotone`) and passes the *results* as lazy pure closures (evaluated in order, only when the core asks),
and renders the verified decision back into the unchanged legacy error string. The chain verifier only materialises the first 17
hops, so an absurdly long chain still costs O(1) before it is rejected.

The files edited for the full wiring: `packages/pca/src/{verified-decision,pcactn,capability,threshold,replay}.ts`,
`server/verify.ts`, and `packages/pca/package.json` (dependency on `@atlasauth/pca-verified-core`).

### CI gate

`scripts/check-verified-core.sh` runs (a) `formal/dafny/build.sh --check` (all proofs + byte-identical generated JS), (b) the
differential tests (`pnpm --filter @atlasauth/pca-verified-core test`, or `VC_TEST_CMD`), and (c) a static scan of
`packages/pca/src` that fails if `capability.ts`, `threshold.ts`, `replay.ts`, `pcactn.ts` or `server/verify.ts` stop calling the
verified core, or if hand-written copies of the replaced decision loops reappear (`--scan-only` runs only (c), `--no-dafny` /
`--no-tests` skip a / b). A refactor cannot silently bypass the proofs.

## Differential testing

`packages/pca-verified-core/test/diff-*.test.ts` run the production TypeScript decision code and the verified-core-backed code
on the same inputs and require **identical** results (verdict, every check, reason strings, check order, store calls):

Reference for "legacy": `packages/pca-verified-core/test/support/legacy/{pcactn,verify,capability,threshold,replay}.ts`, frozen copies of the
pre-wiring TypeScript (never edit them). The production functions are now the verified-core-backed ones; the legacy copies are the oracle. Random inputs come from
fast-check entropy (shrinkable, replayable by seed). **Result: zero disagreements** (9 files, 25 tests, all passing against the working tree that includes R3-01 and the chain / threshold / replay wiring).

| Suite | What is compared | Inputs |
|---|---|---|
| `diff-verdict.test.ts` | `verifyPCActnCore` and `verifyPCActn`, legacy vs production: JSON-identical results (verdict, every check, check order, reason strings, `r`, threshold, budget) | all **3,221** decodable vectors of the conformance corpus (`vectors.json` + `vectors-adversarial.json.gz`) at the core level (plus suite-policy / absent-audience / `audience:null` / `allowUnboundPq` variants on every 6th) and at the full `verifyPCActn` level (plus `require` lists on every 3rd); the **1,278** vectors rejected at parse time through `verifyPCActn(rawString)`; **4,000** random PCActns (field mutations, junk values, window attacks, chain damage, zk/bond fields) x options (audience, clock, suites, `require`) x hooks (threshold hooks reporting `t` in {1,2,3,2.5,NaN,Infinity,-1,"3",undefined}, throwing, rejecting, async) x contexts (risk, budget present/absent, plan, `planAuthorized`, `reversibilityClass`, params); **1,500** random cores with the opt-in attestation/freshness gates; `enforceRequired` truth table |
| `diff-chain.test.ts` | production `verifyChain` (verified walk) vs frozen legacy `verifyChain`: verdict **and exact reason** | 6 base chains (Ed25519 depth 1-6 with `budget_alloc` ladders, hybrid ML-DSA-65 with `holder_pq` commitments) x policies x expected issuers; **6,000** random mutations (delete / duplicate / truncate / swap hops, junk fields, flipped signature/digest/parent characters, alg swaps, caveat drop / add / reorder / alter including unhashable values); all 3,221 corpus chains x 2 policies; non-array and 5,000-hop chains |
| `diff-chain-helpers.test.ts` | production `pqBindingError` (verified `pqBinding`) vs legacy | full grid: 10 algs x 5 pq_pk values x 4 commitments x 4 policies (800 cases) |
| `diff-threshold.test.ts` | production `verifyThreshold` (verified count) vs frozen legacy: verdict, count, roles, reason | t in {1,2,3} x role subsets x baseline; **8,000** random mutations of signer sets (duplicate / conflicting / malformed entries, junk `pq_pk`), shares (duplicates, wrong roles/keys, tampered signatures, unknown algs), `t` (0, 4, 1.5, "2", NaN), baseline variants |
| `diff-replay.test.ts` | production `guardPCActnReplay` (verified guard) vs frozen legacy: verdict, code, reason **and the exact store calls**; `InMemoryReplayStore` vs the verified store model | **6,000** random PCActns/options/scripted store answers (incl. store failures); **400** random operation sequences of 60 ops (monotone clock, store capacities 1-6) |
| `pq-resolve.test.ts` | PQ key-authority decision | full 2^7 truth table vs a literal transcription, and against the real `resolvePqVerifyKey` (R3-01) |
| `constants.test.ts` | protocol limits hard-coded in the Dafny sources (chain depth 16, lifetime 3,600,000 ms, skew 60,000 ms) | equal to the TypeScript constants; window boundaries |
| `finding-clock.test.ts` | the one deliberate behaviour change (below) | PoC + fail-closed behaviour |
| `bridge.test.ts` | the typed API | sanity |
| `ext-regex.diff.test.ts` + `tools/pca-regex-diff` | proved regex engine and `re:` guard (Regex.dfy; JS and Go builds) vs `compileSafeRegex` / `safeRegexFullMatch` / `isSafeRegexSource` / `predicateMatches` and V8 | vitest: 70-pattern corpus, random ASTs, garbage, ReDoS shapes, budget boundary (seeds 101/202/303 at FUZZ_N=12000); farm run: **6,000,040** pairs, 996,244 patterns, 20 seeds, **0 disagreements** on every comparison, 4,703,737 pairs also checked against V8 with 0 disagreements (`tools/pca-regex-diff/RESULTS.md`) |

The expected counts are asserted (e.g. at least 3,000 corpus chains, at least 1,000 random denials and some allows), so a
generator that stops reaching interesting inputs fails the suite.

## Trusted base (what the guarantee still depends on)

1. **Cryptographic primitives** (noble Ed25519, ML-DSA, SLH-DSA, FN-DSA, hybrid constructions, SHA-256, canonical JSON) behave as
   their contracts say: a `true` from signature verification means the holder signed, equal hashes mean equal content. Nothing
   here proves any primitive. Equality of caveats is decided by canonical-hash equality; the semantic theorems
   (`ChainAttenuates`, `VerbResourceSubset`) assume that hash-equal caveats grant identically (collision resistance and
   injective canonicalization). It is an explicit precondition (`EqSound`), not an `assume`.
2. **The TypeScript glue** that evaluates primitives and builds the facts handed to the core (`verified-decision.ts` and the call
   sites in `pcactn.ts` / `verify.ts`): e.g. that "the signature fact" really is the result of verifying under the right key and
   message, that the lazily evaluated closures are pure, and that error strings are rendered from the right decision. The glue is
   exercised by the differential tests above, not proved.
3. **Dafny, Boogie and Z3** (a bug in the verifier could accept a false lemma) and **Dafny's JavaScript compiler** (a miscompile
   could change behaviour). The generated JS is committed and reproducible; the differential tests are the end-to-end check on it.
4. **The JavaScript engine** (V8 / Node) and the Dafny runtime inside `pca_core.js`, including `bignumber.js` for Dafny integers.
5. **Replay-store implementations.** `Replay.dfy` proves the contract and the in-memory reference model. A real (distributed,
   durable) store must itself be atomic and honour the retention rule; that is outside this proof. The nonce theorem also
   assumes a non-decreasing clock across operations (precondition `TimesAtMost`).
6. **Clock integrity.** The window rules are proved relative to the verifier clock the caller supplies.

## Not covered

* **Cryptographic security** of any primitive, side channels, post-quantum assumptions, key management, revocation correctness.
* **Parsing and wire validation** (`validateWireV2`, strict JSON, canonicalization, strict base64url): evaluated in TS.
* **The Policy VM** (`decide`, risk score, budget, predicates, `evaluateAgentCaveats`), **Merkle plan inclusion**, **taint**,
  **freshness / beacon / revocation-epoch verification**, **attestation verification**, **ZK verification**, **bond settlement**:
  evaluated in TS; only how their *results* combine into the verdict is proved.
* Numeric details of the freshness gate (`epochMs`, `maxAgeMs` arithmetic on doubles) and of Policy-VM risk values.
* Distributed replay-store atomicity, durability, and multi-instance clock skew.
* Liveness / availability: the proofs say nothing about a verifier that is slow or unavailable.
* Anything outside the listed modules (hosted API, MCP tools, SDKs in other languages: they have their own verifiers, kept in
  agreement by the conformance corpus, not by this proof).
* The Tamarin properties about attackers with compromised keys; this core proves the decision logic those models abstract.

## Behaviour notes

* The verifier clock must be a safe integer (epoch ms). A NaN, infinite or fractional `nowEpoch` now makes `validity` fail
  closed. Previously a NaN clock made both window comparisons false and an **expired** PCActn got `validity: pass`
  (PoC: `packages/pca-verified-core/test/finding-clock.test.ts`). Integer clocks behave exactly as before.
* A non-integer `clockSkewMs` is floored for the replay guard's window check; this is not a behaviour change (`iat` and `now` are
  integers, so `iat > now + skew` is equivalent for a fractional skew and its floor). Retention still uses the exact `exp + skew`.

## How to re-verify

```bash
# prerequisites: Dafny 4.11.0 (z3 4.12.1). Locally, or on a cloud box (formal/dafny/install-dafny.sh, remote-verify.sh).
formal/dafny/build.sh --verify-only   # prove everything, no output files
formal/dafny/build.sh                 # prove + regenerate packages/pca-verified-core/generated/pca_core.js
formal/dafny/build.sh --check         # fail unless the committed JS is byte-identical to a fresh compile
pnpm --filter @atlasauth/pca-verified-core test   # bridge + differential suites (needs @atlasauth/pca source)
```

---

# Extension components: wire, Merkle, taint, attestation combination, Policy VM, regex

Standalone Dafny modules (each verified and compiled by `formal/dafny/build-ext.sh <Component>`, output `packages/pca-verified-core/generated/pca_<component>.js`). None is wired into production TypeScript yet: each ships as a typed adapter in `@atlasauth/pca-verified-core` (`src/ext-*.ts`) with differential tests against the production code. Where a drop-in is not byte-identical the section lists why.

## Wire layer (`Wire.dfy`): strict JSON, canonical encoding, UTF-8 order, base64url, hex

Source: `formal/dafny/Wire.dfy` (modules `Utf`, `B64`, `Json`, `Api`; standalone, no includes). Build: `formal/dafny/build-ext.sh Wire`
(verify + compile) writes `packages/pca-verified-core/generated/pca_wire.js`; `--check` recompiles and compares byte for byte.
TypeScript adapter: `packages/pca-verified-core/src/ext-wire.ts` (`wireCanonicalOfText`, `wireCanonicalizeStrict`,
`wireCompareUtf8`, `wireDecodeB64uStrict`, `wireB64uEncode`, `wireHexDecode`, `wireHexEncode`).
Last full verification: **325 verified, 0 errors** (`ObjLoopPrint` now uses `{:isolate_assertions}`, which splits it into more VCs; before: 229) (Dafny 4.11.0, Z3 4.12.1). `assume` / `{:axiom}` / `{:extern}` / `{:verify false}`: **none**
(`build-ext.sh` greps for them). **Trusted contracts for this component: none** (no hash or signature primitive is involved; the hash
is applied to the output of the canonical printer, outside this module).

### Model

* Strings are `seq<int>` of UTF-16 code units, exactly like JavaScript strings. `Valid16` = every unit is 16 bit and there is no
  lone surrogate (identical to `!hasLoneSurrogate`).
* Values: `Null | Bool | Int(n) | Dec(neg, ip, fr) | Str | Arr | Obj(seq<KV>)`. `Int` is an exact safe integer (|n| <= 2^53-1; there
  is no negative zero). `Dec` is the canonical plain decimal lexeme (integer part, 1+ fractional digits, last digit nonzero, at most
  15 significant digits, magnitude >= 1e-6). **Not modelled: the IEEE-754 double behind a decimal.** The step "a decimal with at most
  15 significant digits round-trips through a double and `String(v)` returns the same digits" is an arithmetic fact about V8 that the
  differential tests exercise but the proof does not.
* `ParseTop` mirrors `strictParse` (UTF-8 byte bound 1 MiB with a lone surrogate counted as 3 bytes like `TextEncoder`, depth <= 32
  containers, whitespace set, escapes, `\u` hex, lone-surrogate rejection *after* escape resolution so a raw high + escaped low
  surrogate is accepted exactly as in TS, duplicate keys, number lexeme rules including the regex's greedy exponent/fraction behaviour).
  `Print` mirrors `ser(..., strict=true)` (`JSON.stringify` string escaping: `\" \\ \b \f \n \r \t`, other controls as lower-case `\u00xx`,
  no whitespace); `NormJ` sorts every object's members by UTF-8 bytewise key order; `CanonText v = Print (NormJ v)` when `Valid v`.
* The compiled code is loop-based where it matters (`Valid16`, `Utf8LenLoose`, plain string runs), each proved equal to its recursive
  specification (`Valid16Unfold`, `Utf8LenLooseSpec`, `StrBodyFEq`).

### Theorems (all for every input, no bound other than the profile's own caps)

| Lemma | Statement |
|---|---|
| `Json.ParseTopValid` | **parse soundness**: `ParseTop t = Some v` => `Valid v`: no duplicate key at any nesting level, no lone surrogate in any string or key, every number in the canonical wire form, container depth <= 32, and `Utf8LenLoose t <= 1 MiB`. |
| `Json.OversizeRejected`, `TooDeepRejected`, `DeepContainerInvalid`, `ObjDuplicateRejected` | explicit rejections: > 1 MiB never parses; a container at depth 33 never parses; a repeated key makes the object loop fail. |
| (all `Parse*` functions, by Dafny termination checking) | **termination**: every parser function carries a decreasing measure `(|t| - i, rank)`; every `Ok` result satisfies `i < pos <= |t|` (progress and in-bounds, an `ensures` of each function). |
| `Json.RoundTrip`, `RoundTripTop` | **parse o print = id**: `Valid v` => `ParseValue (Print v) = Ok v` (and `ParseTop (Print v) = Some v` whenever the text is <= 1 MiB). |
| `Json.PrintInjective`, `CanonTextInjective`, `CanonTextEquiv` | **injectivity**: print is injective on valid values; `CanonText v1 = CanonText v2 <=> NormJ v1 = NormJ v2`, i.e. two different values never canonicalise equal and two spellings of one value (any member order, any whitespace or escape spelling) share one canonical text. |
| `Json.CanonRoundTrip`, `CanonRoundTripTop`, `CanonReparse` | the canonical text of any valid value re-parses to its normal form, and re-canonicalising gives the same text (idempotent). |
| `Json.ParseNumSpelling` (+ `DigOfVal`) | an accepted number has exactly ONE spelling, the canonical one: if `ParseNum` accepts `t[j..pos)` then that slice equals `Print` of the value (no `1.0`, `1e2`, `01`, `-0`, `+1` ever pass). |
| `Json.SortSorted`, `SortMultiset`, `SortedUnique`, `StrictSortedDistinct` | sort-by-key facts: the result is strictly ascending in the key order, is a permutation of the input (multiset equality) and is the UNIQUE strictly sorted arrangement of its members. |
| `Json.ValidNorm`, `NormIdem`, `NormNorm` | normalisation preserves validity, yields a canonical value, and is idempotent. |
| `Utf.Utf8OrderIsCodePointOrder`, `KLessIsUtf8Bytewise` | **UTF-8 order consistency**: comparing the UTF-8 *bytes* of two well-formed strings is the same as comparing their code point sequences (`compareUtf8` in `hash.ts`). Rests on `Enc8PrefixFree` and `Enc8Order`. |
| `Utf.KLessIrrefl/Asym/Trans/Trichotomy` | the key order is a strict total order on well-formed strings (trichotomy needs `CpsInjective`). |
| `Utf.Utf8Injective`, `Utf8Of16Injective`, `CpsInjective`, `Enc8Injective` | UTF-16 -> code points -> UTF-8 is injective on well-formed strings (two different canonical texts never hash from equal bytes). |
| `Utf.Utf8LenIsEncoding` | the byte-size used for the 1 MiB cap equals the length of the UTF-8 encoding. |
| `B64.DecEnc`, `EncDec`, `AcceptedUnique` | **base64url**: decode(encode b) = b; every accepted string equals encode(decode s) (exactly one accepted spelling per byte string: unpadded, no non-zero trailing bits); two accepted strings that decode equal are equal. |
| `B64.Mod1Rejected`, `AlphabetOnly` | length mod 4 = 1 is never accepted; acceptance implies every character is in `[A-Za-z0-9_-]` (no `=`, whitespace, `+`, `/`). |
| `B64.EncLength`, `DecodeStrictSound`, `DecodeStrictComplete` | encoded length is `ceil(4n/3)` (integer form `(4n+2)/3`); the fixed-length mode accepts exactly encodings of `len` bytes. |
| `B64.HexRoundTrip`, `HexCanonical`, `HexOddRejected` | canonical lower-case hex: round trip; accepted => canonical spelling; odd length rejected. (The TS tree has no strict hex helper; this is the reference for one.) |
| `Api.CompareUtf8Spec`, `CanonicalOfTextTotalOnAccepted` | the compiled comparison returns 0 iff equal and negative iff the UTF-8 bytes are lexicographically smaller (antisymmetric); every accepted document has a canonical text. |

### Differential testing (production TS vs the compiled proved code)

`packages/pca-verified-core/test/ext-wire.diff.test.ts` (adapter `src/ext-wire.ts`): **zero disagreements** in every family.
* Conformance corpus (`vectors.json` + `vectors-adversarial.json.gz`): 8,936 texts (every `pcactn_json`, and `JSON.stringify` of every `pcactn` and `grant`; 64 texts over 20,000 characters skipped for cost), 7,665 accepted; plus 4,656 objects through `canonicalizeStrict`. Canonical text compared for equality (reject <=> reject).
* Bulk run on a cloud box, seed 11, N = 1,500,000 per family: mutated structured JSON texts (626,775 accepted / 873,225 rejected), 1,500,000 random strings over a JSON token alphabet, 1,500,000 random JS values through `canonicalizeStrict` (1,196,282 ok / 303,718 throw), 1,500,000 `compareUtf8` pairs over BMP/astral/boundary code points, 4,500,000 strict-base64url decodes (with and without a fixed length) + 1,500,000 encodes and round trips, 1,500,000 canonical-hex decodes (vs a literal regex transcription).
* Hand-picked edge cases (raw high + escaped low surrogate, duplicate keys at depth, `-0`, `1.0`, `1e1`, `00`, BOM, 1 MiB-adjacent structure is not tested, trailing commas, empty input) and the depth boundary (32 accepted, 33 rejected, arrays and objects).
* Re-run: `WIRE_FUZZ_N=<n> WIRE_FUZZ_SEED=<s> [WIRE_SKIP_CORPUS=1] pnpm exec vitest run test/ext-wire.diff.test.ts` inside `packages/pca-verified-core` (on a cloud box; the Mac has no installed `bignumber.js`).

### Findings

**No production-TypeScript bug found** in `strict-json.ts` / `hash.ts` (`strictParse`, `canonicalizeStrict`, `compareUtf8`, `decodeB64uStrict`): the proved model and the TS agree on every input tried, including the subtle rules (lone surrogates are judged after escape resolution, so a raw high surrogate followed by an escaped low surrogate is accepted; the regex-greedy exponent and fraction handling; the UTF-8 size cap counting a lone surrogate as 3 bytes).
Two observations that are not bugs: (1) `hash.ts` has no strict hex decoder (hex checks are ad-hoc regexes elsewhere), so the proved canonical-hex pair has nothing to be compared with except a regex transcription; (2) the verified reference implementation itself had two proof steps that were fragile across Z3 runs (slice equalities); they were made explicit and the file now verifies identically on four boxes.

### Not covered / remaining gap

* The double behind a decimal (see Model); the JS-value -> `J` import in the adapter (`toJ`: classifies a JS number as integer or decimal
  lexeme via `String(v)`; the profile decisions themselves are the proved `Valid`). Sparse arrays and accessor properties are not modelled.
* Cost: the compiled reference is a literal functional transcription. It is linear for strings but **quadratic in the number of
  members of one array / object** (`acc + [x]`, `HasKey`), so it is NOT wired into production and the corpus differential caps texts
  at 20,000 characters (64 of 9,000 corpus texts are larger). Wiring would need an array-backed accumulator proved equal to this
  specification.
* `canonicalizeStrict` accepting a value that cannot be produced by `strictParse` is *proved impossible* only for the lexical model;
  the "canonical text of an accepted document is itself <= 1 MiB" fact is a precondition (`CanonRoundTripTop`), not proved.
* Not wired into `packages/pca/src` (default as instructed): `strict-json.ts` / `hash.ts` still run the TypeScript.


### Merkle trees: inclusion and consistency proofs (`Merkle.dfy`, RFC 6962 / RFC 9162)

Source `formal/dafny/Merkle.dfy` (standalone, **189 verified, 0 errors**, Dafny 4.11.0), built by `formal/dafny/build-ext.sh Merkle`
into `packages/pca-verified-core/generated/pca_merkle.js`; typed adapter `packages/pca-verified-core/src/ext-merkle.ts`.

**Trusted base of this component.** No `assume`, no `{:axiom}`, no `extern` (the build greps for them). The hash function is **a parameter**
`H: bytes -> bytes` of every function and lemma, never an axiom. The only hypothesis on it is `HashLen(H, L)` (every output has L bytes: true of
SHA-256 / SHA-384), taken as a lemma precondition. Collision resistance is not assumed: every soundness lemma concludes `claim || Collides(H)`,
where `Collides(H)` is the existential "two different byte strings with equal H", and each proof builds the colliding pair explicitly
(domain separation `0x00` leaf / `0x01` node, and equal-length children, are what make the pair constructible). Corollaries: with `!Collides(H)`
the claim holds outright. Glue that is **not** proved: the hash primitive (node:crypto SHA-256/384), strict base64url decoding of roots and
siblings, JS number <-> Dafny int conversion, the proof-object shape checks, and the revocation `bindRoot` string.

| Lemma | Statement (all tree sizes, all indices) |
|---|---|
| `RootInj` | `Root(a) == Root(b)` => `a == b` (including equal lengths) or H collides. Leaf, node and empty hashes never alias. |
| `InclComplete` | honest tree, honest proof (`InclPath`, the `prove()` of merkle.ts) => `VerifyInclusion` accepts. |
| `InclSound` | an accepted proof for `(root, index, size, leaf)` against ANY leaf list of that size with tree hash `root` => `ds[index] == leaf` or H collides. Built on `InclDescend`. |
| `InclMember` / `InclSoundAnySize` | with no assumption on the size: an accepted proof's fold reaching the root of any leaf list => the leaf is one of its entries, or H collides. |
| `IndexSizeNotAuthenticated` | PROVED LIMITATION: `(index, size)` are not bound by the root: `[Step(L, leafhash a)]` at `(2, 3)` verifies leaf `b` against the root of `[a, b]`. Callers must pin the size (mesh.ts does: `inclusion.size !== head.size`). |
| `InclFailClosed`, `InclPathShape`, `ShapeLenBound` | size < 1, index out of range, wrong side tags, wrong path length, a sibling not exactly L bytes => reject. The path shape is a function of `(index, size)` alone, length <= size-1 (and <= 54 for safe integers). |
| `InclusionRootIff` | `VerifyInclusion(root) <=> InclusionRoot(...) == Some(root)` (used for the size-bound revocation root). |
| `ConsForward`, `ConsComplete` | the RFC 9162 verify loop (bit-manipulation `fn`/`sn`, `SkipEven` promotion of the unpaired tail, power-of-two prepend of the old root) accepts the honest proof for every `0 <= m <= n`. The refinement from the iterative loop to tree ranges is proved with level-indexed block invariants (`WF`, `StepA`, `StepB`, `Promote`, `XStep`, `BStep`), not assumed. |
| `ConsBack`, `ConsSound` | an accepted `(oldRoot, newRoot, m, n, proof)` checked against ANY leaf list of size n whose tree hash is `newRoot` => `oldRoot == Root(ds[..m])`, or H collides. |
| `ConsPrefix` | two logs A (size m), B (size n): an accepted proof between their roots => `A == B[..m]` or H collides (the old log is a prefix of the new). |
| `SubEq`, `GeneratorComplete` | the RFC 6962 `SUBPROOF(m, D[n], true)` generator (`ledger.ts consistencyProof`, transcribed as `SubProof`) equals the list the verifier loop consumes (`HonestCons`) for all 0 < m < n, and is accepted. Proved by induction on n via `HLLeft` / `HLRight` / `HLTail` (the left sub-problem is the first 2^j leaves, the right sub-problem is shifted by the block offset). |
| `EmptyTreeIff` | size 0 (RFC 9162 §2.1.4.1, matches the fixed `verifyLedgerConsistency`): accepted iff the path is empty and `oldRoot == H("")`, and when the new size is also 0 `newRoot == H("")`; `newRoot` is unconstrained only for a non-empty new tree. |
| `ExpLen`, `CLoopExactLen`, `VerMidExactLen`, `ExpLenShiftK`, `PreShiftOffK`, `SkipEvenOffK`, `NotPow2Shift`, `MidRejectsEmpty`, `NoAliasShiftK` | NO ALIASING UNDER ANY SHIFT k*2^j: the number of path elements the loop consumes is a function of the sizes alone and an accepted path has exactly that length; adding k*2^j (any k >= 1, any j) above every bit of the sizes strictly increases it, and an empty path is never accepted between two non-empty sizes; hence for every 0 <= m < n <= 2^j and k >= 1 a path accepted for `(m, n)` is NEVER accepted for `(m + k*2^j, n + k*2^j)`, whatever the roots (j = 32: every 32-bit truncation alias with n <= 2^32, all k, not only powers of two). |
| `SigDecides`, `DyadicTwins` | THE EXACT TRUTH: the decision is NOT a function of the exact (m, n) and need not be: for 0 < m < n it is a function of the dyadic signature `(IsPow2(m), PreShift(m-1, n-1))`; pairs sharing it are the same RFC 9162 problem (same old-boundary node shape), e.g. `(1, 2)` and `(2, 3)` decide identically for every path and roots (`DyadicTwins`), which also shows the `n <= 2^j` bound of `NoAliasShiftK` is necessary. This is not a soundness gap: soundness is per pair (`ConsSound`, `ConsPrefix`) and signed heads bind each size to its root. |
| `PathCapRedundant` | for n < 2^53 an accepted path has at most 54 elements, so the production / adapter cap of 2*53+2 is a DoS bound only, never a decision. |
| `ConsFailClosed`, `CLoopLenFail`, `LoopLenBound` | m < 0, m > n, equal sizes with different roots or a non-empty path, a root or element that is not L bytes => reject; any accepted proof has at most `Bits(n-1)` elements (an over-long proof hits the `sn == 0` guard), so verification is O(log n) and terminates. |

**Relation to `ledger.ts verifyLedgerConsistency`.** The two production findings of this component are FIXED and the model now has the fixed
semantics (no adapter shim): F1 (size 0 accepted any roots) -> `EmptyTreeIff`; F2 (32-bit `>>`/`&` truncation: a proof for `(3, 7)` verified for
`(3 + 2^32, 7 + 2^32)`) -> production uses BigInt and safe-integer sizes, the model uses exact integers, `NoAliasShiftK`. F3 is a property, not a bug:
inclusion proofs do not authenticate `(index, size)` (`IndexSizeNotAuthenticated`); callers compare the head size. The only remaining
difference is encoding strictness: the proved adapter requires canonical base64url of exactly 32 bytes for roots and elements, production
accepts any decodable string (the random campaign finds this alone only at m = 0 with a non-canonical root).

**Wiring.** Not wired into `merkle.ts` / `ledger.ts` (the adapter hashes with `node:crypto`, production with noble). Drop-ins: `verifyInclusionVerified`, `verifyMembershipVerified`, `verifyConsistencyVerified`, `merkleRootVerified`, `inclusionProofVerified`, `consistencyProofVerified`.

**Remaining gap.** `Wire`-level canonical encoding of the leaf (`canonicalBytes`) is the caller's (leaf bytes are an input); the sha384 suite is covered by the inclusion verifier only (ledger.ts consistency is SHA-256 only); the `bindRoot` string of revocation.ts is glue; STH signatures / witness signing are not part of this component.

**Differential results** (`packages/pca-verified-core/test/ext-merkle.diff.test.ts`, bulk run on a cloud box: `PCA_MERKLE_N=1500 PCA_MERKLE_MAXN=4096 PCA_MERKLE_EXH=200 PCA_MERKLE_MUT=12`, 10 tests, 854 s, **zero disagreements**):
every tree size 1..200 and every index under both suites (about 80,000 honest proofs: root bytes, proof JSON and verification equal to merkle.ts); 1,500 random trees up to 4,096 leaves; every `(m, n)` with 0 <= m <= n <= 200 (about 20,000 pairs: ledger.ts proof JSON byte-equal to `SubProof`, accepted by both); about 400,000 mutated consistency proofs (bit flips, drops, duplicates, swaps, size and root junk, non-canonical trailing bits, proofs from other `(m, n)`): ledger.ts accepted 16,908 and rejected 389,136, the proved verifier never accepted what ledger.ts rejects, and every strict-only rejection is explained by oldSize = 0 (F1) or a non-canonical / non-safe-integer input in the same m = 0 case (`m>0` divergences: none); mutated inclusion proofs (bad hashes, flipped sides, extra / missing nodes, junk index / size incl. NaN, -1, 2^53, fractions, unknown `hash_suite`, non-canonical base64url, junk steps); the conformance corpus (all plan inclusion proofs of `vectors.json` and `vectors-adversarial.json.gz`); revocation.ts `verifyMembership` honest and mutated; 20,000 random strings against `decodeB64uStrict`. The Mac run (vitest, N=8) shows the same results.


### Taint / information-flow (`Taint.dfy`, `generated/pca_taint.js`, `src/ext-taint.ts`)

Standalone module (no includes); built by `formal/dafny/build-ext.sh Taint`. **63 verified, 0 errors**; no `assume`, `{:axiom}`, `extern`
or `{:verify false}`. The only things taken as given are the *facts* the glue computes (see Trusted base): the registry's answer, the
resource-graph answer, the type/emptiness checks of the provenance, and the ref length.

| Lemma | Statement |
|---|---|
| `JoinComm`, `JoinAssoc`, `JoinIdem` | label join (`joinLabel`, **including the id-collapse on equal rank**) is commutative, associative, idempotent. (Associativity on ids is exactly true; no TS bug here, checked also on all 3375 triples of the production code.) |
| `BottomIdentity`, `TopAbsorbing` | `BOTTOM` is the identity for every label that has no id or is above the bottom rank (a `trusted` label that carries an id collapses it: runtime-only shape, not producible through the typed API); `TOP` absorbs **every** label. |
| `JoinLub` | the result's rank is the max of the ranks and is the least upper bound. |
| `JoinListSpec`, `IsJoinUnique`, `JoinListPerm` | the seedless fold has an order-free characterisation over the multiset (max rank attained; id = the common id of the max-rank members when they agree, else absent); therefore **any permutation of the lineage yields the identical label, ids included**. |
| `JoinListUpper`, `JoinListMonotone`, `JoinListRankIsMax`, `FoldEq` | every member is bounded by the join; adding refs (anywhere) never lowers the rank of a non-empty lineage; the rank is exactly the maximum; the linear tail-recursive fold used in the compiled code equals the proved fold. |
| `UnvouchedIsAgent` | a ref the server neither vouches for (with a real level) nor finds in its resource graph classifies as `agent` (worst), whatever id it carries. |
| `UnknownKindIsNotVouching`, `RawRank`, `UnknownKindRanksWorst`, `RawRankBounds` | OWN-KEY lookups: a registry answer whose kind is not one of the five own level names (`constructor`, `__proto__`, `toString`, a number, ...) is not a vouching (classifies exactly like no answer); `labelRank` of an unknown kind is the worst rank 4, never `undefined` / `NaN`. |
| `ComputeSafe`, `EvalErrorFailsClosed`, `ComputeSafeNoThrow`, `ComputeSafeTotal`, `GateFailsClosedOnError` | `computeTaint` NEVER THROWS: the glue evaluates the facts in production order and stops at the first exception (registry / provenance getter, Proxy trap, `registry.lookup`); the result is then `valid=false`, label `agent`, taint 1 (`taint: evaluation error (fail closed): <msg>`); the result label is always a lattice element, so the taint value is one of 0, .25, .5, .75, 1 (never NaN); the gate never passes an evaluation error, an invalid lineage or a NaN / negative bound. |
| `ClassifyAllPerm`, `ComputePerm` | the whole computation (classification + join + validity) is invariant under permuting the declared refs. |
| `FailClosed`, `EmptyLineageIsWorst`, `RankInRange` | no registry, absent / non-object provenance, `trusted_refs` not an array, or a non-string/empty element => `valid=false`, taint exactly 1 (label `agent`); the empty lineage is taint 1; taint = rank/4 in [0,1]. |
| `LowTaintNeedsEvidence`, `TaintDominatesEveryRef`, `ComputeIsJoinOfClassified` | a valid taint below 1 needs a non-empty lineage in which **every** ref is server-vouched (registry with a non-agent label) or a resource-graph hit; the taint is >= the rank of every classified ref (a bad ref cannot be diluted); nothing but server facts is read (`RefFact` has no agent-declared field). |
| `ComputeAddRefMonotone` | for a non-empty lineage, appending a ref never lowers taint nor changes validity. (From the *empty* lineage, adding a trusted ref lowers 1 -> 0 by design: the only way below the worst case.) |
| `GateSound`, `GateMonotone`, `GateImpliesAllRefsWithinBound`, `GatePassZeroMeansTrusted` | the `enforce.taint` gate passes iff valid, well-configured bound and rank <= bound; lower taint / looser bound never turns a pass into a fail; a pass implies every classified ref is within the bound; with bound 0 every ref is registry-vouched `trusted`. |
| `CombineSound` | `max(computed, claim)`: >= both, the claim can only raise, monotone in both arguments, commutative. |

Differential (`test/ext-taint.diff.test.ts`, vs `packages/pca/src/taint.ts` and a verbatim copy of the `pcactn.ts` gate): exhaustive
joins (all 225 pairs, all 3375 triples, all 56,641 sequences of length 0..4 over 15 labels, reversal-invariant), exhaustive
`computeTaint` over all lineages of length 0..3 x 17 server states (5,220), malformed-provenance table, ids of 127/128/129/1000 chars,
20,000-ref lineages and a 200,000-label fold, throwing registry / graph / getters / proxies, and random worlds (see the result table
in the report). Compared: full result JSON, per-ref labels, reason strings, **and the exact registry / graph call sequence**.

Production bugs found by this proof effort (both FIXED; the model now has the fixed semantics, PoCs kept as regressions in the test file):
(1) a registry kind that is an inherited key (`constructor`) gave a NaN taint that passed `enforce.taint` at `maxTaint: 0`; (2) "never throws"
was false (sparse `trusted_refs`, throwing `registry.lookup`). `computeTaintVerified` is now observably identical to production on every
tested input, including the hostile ones (throwing registry / getters / proxies, sparse arrays, inherited kinds).

Wiring: **not wired** into production; `computeTaintVerified` is a drop-in.

Gap / not covered: the numeric risk formula (`riskScore`'s `unit()`/clamp on the taint term) and `max(computed, agentClaim)` is
proved only on the rank scale (`Combine`); no function named `deriveRisk` exists in `packages/pca/src` (the combination is described in
`taint.ts` but not implemented there), so there is no code to differential-test. DLP / prohibition flow rules are not modelled.
Ids are modelled by equality only (adapter interns strings); non-string runtime ids are out of profile.


## Attestation result combination (`Attest.dfy`)

Standalone Dafny file `formal/dafny/Attest.dfy` (build: `formal/dafny/build-ext.sh Attest`, output `packages/pca-verified-core/generated/pca_attest.js`,
typed adapter `src/ext-attest.ts`, production drop-ins and differential tests under `test/`). Verification result: **134 verified, 0 errors** (Dafny 4.11.0,
Z3 4.12.1). No `assume`, no `{:axiom}`, no `extern`, no `{:verify false}`; **no cryptographic contract at all** is needed: compared values are interned to integers by
the glue and primitives (signature checks, shape checks, clocks) arrive as booleans or integers.

### Theorems

| Component | Lemma | Statement (all inputs, any number of roots M and any threshold N) |
|---|---|---|
| Multi-root (`createMultiRootVerifier`) | `RunIff` | accept <=> no result malformed (reading the result threw, e.g. a hostile getter) AND every required root passed AND count(passing roots) >= N AND the passing identities do not contradict (sound and complete; independent of root order) |
| | `NullIsFailedRoot`, `NullNeverAborts` | a null / undefined / non-object root result (`NullRes`) is exactly a FAILED root (same output as any non-passing result): it never aborts the N-of-M check, a required one denies, and all-null results never accept |
| | `RunSound` | an accept implies: no malformed result, every required root passed, counted indices strictly increasing (each root counted once), `>= N`, every passing root counted, every accepted non-empty identity field equals the reconciled one, the reconciled identity invents no value, `weights_measured` only if a counted root measured that exact digest |
| | `RunFailsClosed` | malformed result / failed required root / below threshold / conflict / `N > M` each force a reject |
| | `CountedIdsDistinct`, `ValidPolicy` | under the constructor's validity (distinct non-empty ids, `1 <= N <= M`) the counted roots have pairwise distinct ids: duplicates cannot double count |
| | `ReconcileIff`, `PickSpec` | identity reconciliation succeeds iff all non-empty values per field agree (first conflict reported in field order) |
| | `AppendFailing` | appending a failing optional root changes nothing (identical output); appending a malformed result or a failing required root can never produce an accept |
| | `RejectToAccept` | a reject can become an accept by appending a root only if the base had no malformed/required failure, no conflict, was strictly below N, and the new root passes |
| | `AppendPassing` | if the base accepts, appending a passing root yields an accept iff its identity is compatible with every counted one (the conflict exception, exactly) |
| | `ThresholdAntitone`, `RunSameOutcome` | raising N never turns a reject into an accept; exact output equality for the optional-failure case |
| Agent binding (`matchAgentBinding`, `requiresAttestation`) | `MatchIff`, `PinnedAbsentDigestFails`, `EmptyBindingAccepts`, `TighteningRejects` | accept <=> every pinned constraint holds; a pinned prompt/tool digest the identity does not carry fails closed; narrowing a binding never accepts more |
| `verifyAttestation` stage order | `VerifyIff`, `VerifySound` | accept <=> every stage on the route holds; first failing stage wins; accept implies grant/epoch/nonce binding, `require_hardware` => hardware verifier AND hardware document, hardware route => ok + bound + measured, software route => trusted attestor + known alg + verifying signature + equal binding + window, and the agent_binding match; a software attestation can never satisfy `require_hardware` |
| Arithmetic | `NonceAgeSound`, `EffMaxAgeBounds`, `WindowSound`, `HeadFreshnessSound` (with `optionsOk`: invalid `clockSkewMs` / `maxHeadAgeMs` => `HeadBadOptions` first) | fresh <=> `issued - skew <= now <= issued + maxAge + skew` with `maxAge <= 5 min` whatever the caller configured; validity window iff `iat <= exp` and `iat - skew <= now <= exp + skew` |
| Hook nonce rule | `HookSound` | hook accepts only an ok verdict, and with a store configured and a bound verdict only if the store answered "first" |
| Nonce store (`memoryNonceStore`, time + retention + capacity) | `SingleUse`, `LiveNeverEvicted`, `LiveRejected`, `ApplyKeepsLive`, `ConsumeWf` | after n is accepted at t0, ANY number of later consumes at times t with t - t0 < retention keep n resident and reject every re-presentation of n; a live entry is never evicted; nonces stay distinct and the store never exceeds `max` (>= 1) |
| | `FullOfLiveRefuses`, `AgedOutReaccepted` | a store full of live entries refuses a new nonce (fail closed) and evicts nothing; a nonce is re-accepted only once it has aged out of retention (exactly at the boundary) |
| Allowlist (`verifyAllowlistManifest`) | `AllowSound` | accept implies issuer known, alg match, signature, `notBefore - skew <= now <= expiresAt + skew`, lifetime, `version >= minVersion`, `version >= lastSeen`, same version => same digest, and VALID numeric options (`!optionsOk` => reject); a version below the last seen one is never accepted |
| | `OptionsFailClosed` | an authentic manifest with an invalid option (non-finite skew / lifetime, non-integer version bound) gets exactly the options verdict (`malformed`), never `ok` |
| Durable high-water mark | `DurableSound`, `DRunMonotone` | for ANY stale read and any interleaving of writers: an accept leaves the store exactly at the accepted `(version, digest)`, the stored version never decreases, and accepted versions are non-decreasing over any run |
| | `EqualVersionConflict`, `WritesStrictlyIncrease` | versions are append-only: an equal stored version with another digest is `conflict` and the store is untouched; a write happens only over a missing record or a strictly older version |
| Anchored feed | `AnchorSound` | accept implies the log holds no two digests for any version of the issuer, the manifest's version is >= every anchored version (so it is the highest), and its own entry is in the log |
| | `CacheSound` | smaller head => rollback, equal size and different root => split view, larger head => accepted only after a consistency proof |

### Findings in the production TypeScript (all FIXED; the model has the fixed semantics, PoCs kept as regressions)

1. Non-finite `clockSkewMs` / `maxHeadAgeMs` (and NaN `maxLifetimeMs` / version bounds) failed OPEN (expired / not-yet-valid manifests and stale /
   future heads verified) -> validated and refused (`OptionsFailClosed`, `HeadBadOptions`).
2. `verifyAllowlistDurable` accepted and stored a same-version / different-digest write; the conflict branch was dead -> `EqualVersionConflict`.
3. `memoryNonceStore` re-accepted a nonce after `max` newer ones (`a, b, a` at `max = 1`) and gave no protection at `max = 0` -> refuses when full
   of live nonces, evicts only aged-out ones, `max >= 1` (`SingleUse`, `LiveNeverEvicted`, `FullOfLiveRefuses`).
4. A `null` root result aborted the whole multi-root check -> a failed root (`NullIsFailedRoot`).

Clocks: both production and the proved store take integer epoch ms only (`Date.now()` is): a non-integer `retentionMs` throws `TypeError`
and a clock reading that is not a safe integer refuses the nonce (fail closed, nothing recorded), identically in both.

### Wiring status

Nothing is imported by production yet. `matchAgentBindingVerified`, `createMultiRootVerifierVerified` (pure, in `src/ext-attest.ts`) and
`verifyAttestationVerified`, `createAttestationVerifierVerified`, `verifyAllowlistDurableVerified`, `verifyAllowlistAnchoredVerified` (in `test/support/attest-dropins.ts`,
because they need production primitives and `@atlasauth/pca` depends on this package) are byte-identical re-implementations whose decisions are made by the compiled Dafny.
Remaining gap: the primitive glue (signature verification, `parseBody` shape checks, canonical binding bytes, tree-head signature checks, `nonceEntropyOk`) is not proved;
non-integer clock operands use the production double arithmetic (integer operands use the proved arithmetic; a fractional skew is floored, which is exact for integer
operands); `verifyAllowlistManifest` itself is not re-implemented (its ordering is proved over facts and checked against production, `allowlistGate`).


### Predicate DSL, caveat evaluator and Policy-VM decision (`PolicyVm.dfy`, `generated/pca_policyvm.js`, `src/ext-policyvm.ts`)

Standalone module (no includes); built by `formal/dafny/build-ext.sh PolicyVm`. **271 verified, 0 errors**; no `assume`, `{:axiom}`, `extern` or
`{:verify false}` (the build greps for them). Dafny 4.11.0 / Z3 4.12.1. The compiled JavaScript is committed and `build-ext.sh PolicyVm --check`
recompiles and requires it to be byte-identical.

**Model.** JavaScript values are a Dafny datatype (`null`, `undefined`, booleans, numbers as the EXACT rational of the double, non-finite number,
function/symbol/bigint, strings as UTF-16 code-unit sequences, arrays, objects with an ordered entry list and a plain/non-plain flag). Conditions,
predicates, caveats and contexts are all such values, so the evaluator reads fields exactly as the TypeScript does (`c.field`, `'all_of' in c`, own
properties only, `undefined` vs absent, arrays are objects, `reversibility_max` reads strings only). The following are *parameters*, never
axioms, so every theorem holds for every choice: `Rx` (the regex guard `isSafeRegexSource` and the matcher `safeRegexFullMatch`, proved elsewhere),
`ToolEv` (the `tool_schema` evaluator), and `Fl` (the one inexact double expression of the `rate` caveat, `now - per_secs * 1000`).

| Lemma | Statement |
|---|---|
| `EvalAllOf`, `EvalAnyOf`, `EvalNot`, `AllChar`, `AnyChar`, `AllPerm`, `AnyPerm`, `AllSetOnly` | `all_of` / `any_of` / `not` are exactly the Kleene strong connectives of the children's verdicts: the TS short-circuit changes nothing, the result depends only on the SET of child verdicts (any permutation / duplication gives the same answer). |
| `DeMorganAll`, `DeMorganAny`, `NotInvolutive`, `NotUnknown` | De Morgan duality of the two connectives; `not` involutive on clean verdicts, `not unknown = unknown`. |
| `AllRefines`, `AnyRefines`, `NotRefines` | information monotonicity (Kleene): making children more defined can only make the group more defined, never contradicting an earlier definite answer. |
| `AllTrueIff`, `AnyTrueIff`, `AllOfSatisfiedImpliesChildren`, `AnyOfSatisfiedImpliesChild`, `NotSatisfiedIffChildFalse`, `NotUnknownNeverSatisfies` | a satisfied `all_of` has every child true, a satisfied `any_of` some child true, a satisfied `not` a child that is cleanly FALSE; an `unknown` child never satisfies a `not`. |
| `EvalGroupMalformed`, `EvalNonObjectUnknown`, `LeafMalformedUnknown`, `ParamsUnavailableUnknown`, `UnknownOpUnknown` | fail closed: empty / non-array groups, non-object conditions, a leaf without a non-empty string `field` and a string `op`, a params-rooted condition when params were not supplied (so `exists:false` cannot pass vacuously), an unknown operator are all `unknown`, never satisfied. |
| `EvalVisitsAtMostSize` (`CountBoundC/A/N`), `BudgetedSound` | termination (structural) and bounded resource use: every condition node is visited at most once, so visited nodes <= size of the condition tree; the budgeted evaluator refuses (`None`) a tree larger than the budget and otherwise equals the evaluator. |
| `GlobFullCounted`, `GlobLeafBound`, `ClosureBounded`, `ClosureReflexive` | the Dafny `like` matcher (a dynamic program) is proved equal to the declarative glob semantics `Gm` for ALL patterns and subjects, and performs exactly (|pattern|+1)(|subject|+1) cell updates (<= 513 x 513 under the enforced caps 512/512); the `member_of` closure is a bounded BFS (<= 10,000 expansions by construction, terminates), reflexive. |
| `DeepEqSym`, `DeepEqRefl`, `DeepEqTrans`, `DeepEqFailClosed` | `deepEq` (lenient `canonicalize` equality, modelled including V8's stable key sort with `compareUtf8`) is an equivalence on serialisable values; anything not serialisable (undefined, function, NaN/Infinity, non-plain object) is equal to nothing. |
| `CmpStrZero`, `CmpStrAntisym`, `CmpStrTrans` (+ `CmpBytes*`, `UnitsInj`) | `compareUtf8` (fixed) is a STRICT TOTAL ORDER on strings: UTF-8 byte order (lone surrogate -> U+FFFD), ties between different strings broken by UTF-16 code-unit order; 0 only for equal strings. |
| `InsertProps`, `SortProps`, `SortedUnique`, `SortPerm`, `DeepEqObjPerm` | KEY-ORDER INSENSITIVITY: for an object (pairwise distinct keys) the sort yields the unique strictly sorted arrangement, so any permutation of its entries gives the identical canonical text and never changes a `deepEq` verdict (`eq` / `ne` / `in` / `nin`), lone-surrogate keys included. |
| `Normalize`, `SerNorm` / `SerNormL` / `SerNormE`, `NormEqSer`, `DeepEqDeepPerm`, `NormPermTop`, `NormCongArr`, `NormCongObj` (+ `SortNormComm`, `SortIdem`) | NESTED KEY-ORDER INSENSITIVITY, by induction over the value structure: `Normalize` sorts the entries of every object at every depth; for well-keyed values (pairwise distinct keys in every object, as in any JS value) `Normalize(a) == Normalize(b)` implies `Canon(a) == Canon(b)` and equal canonical text, hence `DeepEq(a, x) == DeepEq(b, x)` and `DeepEq(x, a) == DeepEq(x, b)` for every `x`; permuting the entries of an object (`NormPermTop`) and replacing an array element or an entry value by one with the same normal form (`NormCongArr`, `NormCongObj`) preserve the normal form, so permutations at any depth (iterated along the path) never change a verdict. |
| `FirstMatchSpec`, `PredicatesAllowedIff`, `EmptyPredicatesDeny`, `MalformedActionNeverMatches`, `PredicatesAppendUnion` | default deny: an empty / non-array predicate list allows nothing; allowed <=> some predicate matches, and the reported one is the FIRST; a malformed action (verb / resource not strings) matches nothing; appending a predicate only broadens (union) and never changes the first match. |
| `WhereAllAppend`, `WhereAttenuates`, `WhereAllIff`, `UnknownWhereDenies` | `where` is a conjunction: more conditions can only narrow; a condition that is not cleanly true denies. |
| `CavOkIff`, `CavConcat`, `CavAppendAttenuates`, `CavPrefixAntitone`, `CavPerm`, `CavFailedEmptyIff` | **monotone attenuation of the caveat conjunction**: `evaluateCaveats(cs ++ [c])` ok => `evaluateCaveats(cs)` ok; `failed(cs ++ [c]) = failed(cs) ++ (c fails ? [name c] : [])`; ok(prefix) whenever ok(whole); verdict invariant under permutation; ok <=> every caveat satisfied, for ANY evaluator. |
| `EnvelopeUnknownTypeUnsatisfied`, `EnvelopeNoClockUnsatisfied`, `EnvelopeMalformedUnsatisfied`, `AgentMalformedUnsatisfied` | fail closed: unknown / non-string caveat type, missing or non-finite clock, non-object caveat or context => unsatisfied. |
| `ExpiresSound`, `NotBeforeSound`, `MaxBlastSound`, `DelegationDepthSound`, `ReversibilitySound`, `RateSound`, `ExpiresTimeMonotone`, `NotBeforeTimeMonotone` | the numeric kernels: a satisfied `expires` has `now < at`, `not_before` has `now >= at`, etc.; `expires` satisfied later => satisfied earlier; a satisfied `reversibility_max` has a STRING class and a STRING context class with index(context) <= index(class). |
| `ReversibilityNonStringUnsatisfied` | TYPE CHECK: a non-string `class` (e.g. `['irreversible']`, an object with a `toString`) or a non-string context class never satisfies `reversibility_max` (no `String()` coercion). |
| `RxAgree`, `LeafOpRxExt`, `EvalTriRxExt`, `PredicateRxExt`, `ResourceRxExt`, `ReOnlyUnderGuards` | the regex oracle is consulted ONLY under the guards (guard accepted, |pattern| <= 200, |subject| <= 512): two oracles that agree on the guarded region give identical verdicts on every condition, predicate and resource pattern. So the guard-and-cap discipline is a theorem of the evaluator, and the Regex proof only has to discharge that region. |
| `ReqThrMonotone`, `ReqThrCoherent`, `ReqThrRange`, `EscalateNeverLowers` | required threshold monotone non-decreasing in risk, optimistic acceptance anti-monotone and only at t=1 and never for an irreversible action; `escalateThreshold` never lowers t or proof, keeps proof = t-1 (coherent) and never gains optimism. |
| `ReleaseIff`, `NoReleaseNoAdmit`, `AdmitSound`, `ExhaustedBudgetEscalates`, `DebitRequiresCover`, `IrreversibleNeverOptimistic`, `OptimisticOnlyAtT1`, `ThresholdNeverBelowRequired` | the Guardian share is released <=> predicates AND grant caveats AND delegated caveats AND chain; no release => no admit, no debit, step-up; auto-admit => released, t=1, risk <= theta1, budget covers cost; **a depleted budget never admits, never debits and escalates to a human (t=3)**; machine-only spending (debit) only when the budget covers the cost. |
| `AdmitAntitoneInRisk`, `AdmitMonotoneInBudget`, `CostMonotone`, `FloorOnlyRaises` | with everything else fixed: a riskier action is never auto-admitted / debited if a safer one is not, never gets a lower threshold; a larger budget never turns an admit into a refusal; the signed risk floor can only raise risk. |
| `SafetyBound`, `DebitNeverRaises`, `LeakNeverRaises` | the trust-budget safety theorem as a machine-checked induction over ANY history of leaks and actions: total admitted machine-only cost <= starting budget, and the budget stays >= 0 (so sum of r <= bMax / kappa). |
| `ReleaseSound`, `DelegationAttenuates`, `GrantCaveatAttenuates` | end to end: a released share implies a matching predicate, every grant caveat and every delegated caveat satisfied; adding a delegated or grant caveat never turns a refusal into a release. |

**Trusted base specific to this module.** (1) the regex guard / matcher (parameters; see `RxAgree`); (2) the `tool_schema` evaluator (parameter);
(3) the double arithmetic of `riskScore`, `leak`, `cost`, `debit` and `now - per_secs*1000`: the decision kernels take the RESULTS of that arithmetic
(exact rationals of doubles) and decide by comparisons, which are exact; the budget lemmas are in exact real arithmetic (also true for IEEE doubles
because rounding is monotone, but that step is not mechanised); (4) the converter `toValue` (JS value -> model), which refuses cyclic data, sparse arrays,
accessor properties; Proxy traps and a class whose `toString` is overridden are out of the model.

**Not covered / gap.** `verifyChain` inside `decide()` (covered by `Chain.dfy`); `readEnvelope`; the floating-point risk functional and plan geodesic;
`tool_schema` internals; the regex engine; the deep-recursion behaviour (the TS catches a stack overflow at the deepest frame and reports `unknown` there;
the proved evaluator is total but its host recursion is bounded by the JS stack as well, so conditions nested far beyond any real policy are outside the
equivalence; production inputs are depth-capped by the wire profile at 32). **Not wired** into production: `predicates.ts` / `policy-vm.ts` were not
edited. A drop-in is NOT byte-identical for free: the production evaluators accept live JS values (getters, class instances) and the converter refuses
some of them, so wiring would need the converter's refusals to fall back to the TS path. The drop-in `decide()` used by the tests is
`test/support/policyvm-decide.ts` (verbatim copy of `decide()` with the five decision points replaced by the proved code).

**Differential** (`test/ext-policyvm.diff.test.ts`; production `predicates.ts` / `agent-native.ts` / `policy-vm.ts` / `risk.ts` vs the proved code):
see the report for counts. Compared: tri-valued verdict of random conditions (leaves over all 14 operators, nested groups, malformed shapes, `__proto__`
and null-prototype objects, astral and lone-surrogate strings, NaN / +-0 / 2^53 / 5e-324 operands), exhaustive op x path x operand grids and exhaustive
group shapes, `evaluatePredicates` (verdict, matched identity, reason string), every single caveat under both evaluators, whole caveat lists
(ok + failed names), every caveat list of the 4,500 conformance vectors, the threshold / escalation / admission kernels exhaustively, and
`decide()` end to end (release, threshold, admit, step-up, reasons, budget). The production two-pointer glob matcher is not itself proved; it is
differential-tested against the proved DP on all of the above.

**Production findings** (both FIXED in production; the model now has the fixed semantics, no adapter shim; PoCs kept as regressions in the
test file, section "production findings - FIXED"): (1) `deepEq` was not key-order insensitive for keys with different lone surrogates
(`compareUtf8` returned 0, the sort fell back to insertion order) -> code-unit tie-break, `DeepEqObjPerm`; (2) `reversibility_max` coerced
`class` with `String()` (`['irreversible']` behaved like the word) -> strings only, `ReversibilityNonStringUnsatisfied` (also in `agent-native.ts`).




## Regex engine and guard (`Regex.dfy`)

Component: the linear-time regex engine `packages/pca/src/safe-regex.ts` and the `re:` guard `isSafeRegexSource` / `resourceMatches`
(`packages/pca/src/predicates.ts`). File `formal/dafny/Regex.dfy` (standalone module, no assume/axiom/extern, **245 verified, 0 errors**,
checked with `formal/dafny/build-ext.sh Regex` on a cloud box). Compiled to `packages/pca-verified-core/generated/pca_regex.js`;
typed adapter `src/ext-regex.ts` (`safeRegexFullMatchVerified`, `compilesVerified`, `isSafeRegexSourceVerified`, `reMatchesVerified`).

## What is proved (all inputs, strings = sequences of UTF-16 code units)
1. **Parser** (`Parse`, mirrors `class Parser` exactly): total and terminating (`decreases |s|-i`); its result is a `Node` that satisfies
   `ValidN` and `BoundedN` (the datatype *is* the supported subset: set/bol/eol/cat/alt/rep, repeat bounds <= 64, no assertion
   under a quantifier, alternations non-empty) (`ParseSound`). One refusal lemma per unsupported class: backrefs `\1-\9`
   (`BackrefRefused`), `\k` (`NamedBackrefRefused`), `\p \P` (`UnicodePropertyRefused`), `\B` (`NonWordBoundaryRefused`), `\b` outside a
   class (`WordBoundaryRefused`), trailing backslash, octal `\00-\09`, any other letter/digit/underscore escape
   (`EscapeRefusesUnsupported`), lookaround / named groups (`GroupExtensionRefused`), bare quantifier (`BareQuantifierRefused`), malformed
   `{` (`MalformedBraceRefused`), quantified `^`/`$` (`QuantifiedAssertionRefused`), repeat bound > 64 (`RepeatBoundRefused`), doubled
   quantifier (`DoubledQuantifierRefused`), unbalanced `)` (`UnbalancedCloseRefused`); `TopLevelRefusals` lifts them to `Parse(s) == None`.
2. **Semantics.** `Match(node, s, i, j)` is the denotational full-match relation (anchors absolute, `[]` matches nothing, `[^]` anything,
   `.` excludes 0A 0D 2028 2029, `\s \w \d` tables as in the TS, class-escape-as-range-endpoint Annex B rule).
3. **Compile correctness.** `Emit` reproduces the TS Thompson shapes (split/jmp, `{m,n}` as m copies + (n-m) nested optionals, unbounded loop).
   `EmitProps`: `|Emit| == Size(n)` and all jump targets stay inside the fragment; `FragAt`: for every node and every embedding of its
   code at `a`, a path `(a,i) ->* (a+Size,j)` exists iff `Match(n,s,i,j)`; `CompileCorrect`: program accepts s iff `Match(ast,s,0,|s|)`;
   `CompileWF`: program well-formed, ends in `IMatch`, `|P| <= 4096` (`CompileCapRespected`; larger programs give `None`: `CompileCapFailsClosed`).
4. **Pike simulation** (`Add` = DFS epsilon closure, `Phase`, `Advance`, `Run`; imperative with arrays): closure is sound (only reachable
   configurations), closed under epsilon steps, thread list complete and duplicate-free, `matched` exact; `Run` returns `Some(b)` with
   `b <==> Accepts(P,s)` and `work <= 6*|P|*(|s|+1)` (linear, no backtracking; per-character cost <= 6|P|). Determinism: `Run` is a function.
5. **Budget.** `Run` returns `None` iff `|P|*(|s|+1) > 2_000_000` (exactly the TS `MAX_MATCH_STEPS` test); `FullMatch` is `None` whenever parse/compile fail.
6. **Guard.** `IsSafeSource` mirrors `isSafeRegexSource` (class scanning, group frames, `|`/`?`/`{m,n}`/unbounded bit costs, <=3 unbounded,
   <=22 bits, `{n}` <= 64, lazy modifier). `GuardImpliesCompiles`: whatever the guard admits compiles (parser-to-guard link). `ReMatches`
   encodes `resourceMatches`: src <= 200, subject <= 512, guard, engine, true only on `Some(true)`.

## Not proved / honest scope
- The guard's *precision* (that the bit budget really bounds backtracking cost) is moot for the linear engine and is not proved; only that
  the Dafny guard equals the TS function (differentially) and that it implies the engine compiles. No statement about V8 `RegExp` itself:
  equality with V8 is tested differentially, not proved (V8 is not formalized).
- JS number semantics: the TS guard reads `\d+` with `Number()`; Dafny uses unbounded ints. Differences only for > 2^53 literals, where both
  reject (the engine refuses repeat bounds > 4 digits, and the guard's final conjunct is the engine).
- `ceil(log2(options))` uses `Math.log2`; Dafny uses an integer recursion (equal on 2..65).
- **Not wired into production** (`safe-regex.ts`/`predicates.ts` unchanged): the compiled Dafny uses BigNumber/Seq and is ~100x slower than the
  TS matcher (about 100 ms per random pattern in tests), so it is used as an oracle and as `ext-regex` for callers who want the proved path.

## Differential results
`test/ext-regex.diff.test.ts` compares the proved engine against (a) production `compileSafeRegex`/`safeRegexFullMatch`, (b) production
`isSafeRegexSource`, (c) V8 `new RegExp('^(?:'+src+')$')` on every pattern the engine accepts, (d) the `re:` entry point. Inputs: a 70-pattern
corpus (incl. all refusal classes, ReDoS shapes), random ASTs printed to source, random garbage, budget-boundary programs, random UTF-16
subjects (surrogates, line terminators, NBSP, BOM). vitest runs: Mac FUZZ_N=300, cloud FUZZ_N=12000 for seeds 101, 202 and 303, all green
(V8 is consulted there only for guard-admitted patterns; see below).

**Million-case run** (`tools/pca-regex-diff`, results in `tools/pca-regex-diff/RESULTS.md`): the proved engine compiled with Dafny's **Go**
backend against production TS and V8 on **6,000,040 pattern/subject pairs** (996,244 patterns; 20 seeds on 5 farm boxes; random ASTs,
corpus mutants, garbage, corpus, ReDoS shapes, and step-budget-boundary subjects on both sides of `|P|*(n+1) = 2,000,000`).
`Compiles`/`SafeSource`/`FullMatch`/`ReMatches` vs `compileSafeRegex`/`isSafeRegexSource`/`safeRegexFullMatch`/`predicateMatches`
(`re:` path): **0 disagreements** on each. Against V8 where the engine gives a verdict: 4,703,737 pairs, **0 disagreements**. Budget
refusals: 480, identical on both sides. V8 itself timed out (more than 2 s on a subject of 12 characters or fewer) on 419 pairs, which
were not compared. That is backtracking the production engine avoids by design. An earlier vitest stall (seeds 202/303) was such a V8
backtrack in the test oracle, not either engine.

No disagreement found; **no TS bugs found** in safe-regex.ts / isSafeRegexSource. Note: since this proof was written, `predicates.ts`
added the per-document regex budget (`chargeRegex`, R4-05). `ReMatches` does not model it. A single `re:` evaluation is always within that
budget (64 evaluations, 8,192 source chars, 5,000,000 steps per document vs one pattern of at most 200 chars and 2,000,000 steps), so
`ReMatches` equals the single-predicate path, which the run confirms. Multi-pattern documents can be refused by the budget, and that is not covered.


## Status of the extension findings (fixed in production AND in the models)

Every production finding listed for `Attest`, `Merkle`, `Taint` and `PolicyVm` is fixed in `packages/pca/src` (regressions in
`src/verified-core-findings.test.ts`, package CHANGELOG), and the four Dafny models were re-proved against the FIXED semantics, so the
adapters no longer normalise anything: the proved code is the behaviour. Re-verification (Dafny 4.11.0, queued farm jobs, compiled JS
byte-identical to a fresh compile):

| Model | Result | New / changed lemmas |
|---|---|---|
| `Attest.dfy` | 134 verified, 0 errors | `NullIsFailedRoot`, `NullNeverAborts`, `SingleUse` (time-based), `LiveNeverEvicted`, `LiveRejected`, `ApplyKeepsLive`, `FullOfLiveRefuses`, `AgedOutReaccepted`, `ConsumeWf`, `OptionsFailClosed`, `EqualVersionConflict`, `WritesStrictlyIncrease`; removed `EvictionReopensReplay`, `ZeroCapacityNoProtection`, `ConflictBranchDead`, `SameVersionRaceAccepted` |
| `Merkle.dfy` | 189 verified, 0 errors | `EmptyTreeIff`, `ExpLen`, `CLoopExactLen`, `VerMidExactLen`, `ExpLenShiftK`, `PreShiftOffK`, `NotPow2Shift`, `MidRejectsEmpty`, `NoAliasShiftK` (all shifts k*2^j, n <= 2^j), `SigDecides`, `DyadicTwins`, `PathCapRedundant` |
| `Taint.dfy` | 63 verified, 0 errors | `UnknownKindIsNotVouching`, `RawRank`, `UnknownKindRanksWorst`, `ComputeSafe`, `EvalErrorFailsClosed`, `ComputeSafeTotal`, `GateFailsClosedOnError` |
| `PolicyVm.dfy` | 271 verified, 0 errors | `CmpStrZero`, `CmpStrAntisym`, `CmpStrTrans`, `SortProps`, `SortedUnique`, `SortPerm`, `DeepEqObjPerm`, nested `DeepEqDeepPerm` / `NormEqSer` / `NormPermTop` / `NormCongArr` / `NormCongObj`, `ReversibilityNonStringUnsatisfied` |

`formal/dafny/build-ext.sh` (and `build.sh` via `remote-verify.sh`) now run through the pcaq queue (`formal/dafny/qrun.sh`), and
`scripts/check-verified-core.sh` checks every standalone model (`Regex`, `Wire`, `Merkle`, `Taint`, `Attest`, `PolicyVm`) plus the core.
