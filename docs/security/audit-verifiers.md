# Cross-language verifier audit: parser differentials

This page records an adversarial audit of the independent PCActn verifiers. Every verifier is expected to
return the same verdict, and the same per-check result, for every input an attacker can send. Where two
implementations parse the same bytes differently, an attacker can craft a message that one accepts and
another rejects. That is a parser differential.

## What was tested

Implementations in the matrix: the TypeScript reference, Go, Python, Ruby, PHP, .NET, Rust and Java.
Kotlin and Swift are not in the process-per-vector matrix; their native runners are executed over the same
core and full corpora instead (see "Kotlin and Swift").

Each verifier runs its own strict JSON parser, its own canonicalizer and its own Ed25519 code on the same raw
text. We compare the accept/reject verdict and the full check map
(`wire, version, audience, validity, chain, grant_ref_bound, plan_inclusion, leaf_signature, counter`), so a
verifier that rejects for a different reason also counts as a disagreement.

### Committed corpus (`packages/pca/conformance/`)

The corpus is split in two so that the language mirrors and every native test suite stay small:

* `vectors.json` is the curated **core** (about 1.9 MB): the 172 golden vectors plus a deterministic,
  representative sample of every adversarial family (90 `adv-*` vectors, for each family the smallest vector of
  every distinct outcome class and then an even stride) and a sample of the adversarial primitives. Every
  language's native suite and every public mirror vendors only this file.
* `vectors-adversarial.json.gz` is the **full** adversarial set (about 1.1 MB compressed, 15 MB expanded).
  It is vendored only into the flagship `pca` repository and read by the monorepo gate. Native suites assert
  minimum vector counts, never exact sizes. Before the split `vectors.json` was 20 MB.

`packages/pca/scripts/gen-conformance-adv.mjs` (stage 3 of the generator pipeline) writes the full set and
splices the core sample; both outputs are deterministic and idempotent. It produces the deterministic
`adv-*` vectors. Expected verdicts come from the TypeScript reference, and where the correct answer is
unconditional the generator asserts the intended outcome against the reference.

| Family | Vectors | What it covers |
|---|---|---|
| equiv | 76 | format-only rewrites that must accept: indentation, key order, `\u` escapes (either case), `\/`, allowed whitespace |
| ws | 112 | forbidden whitespace and invisible characters at eight token positions |
| top | 124 | non-object roots, BOM, trailing and leading garbage, comments, truncation at 48 points, bad escapes, `NaN`/`Infinity` |
| dupkey | 108 | duplicate keys at every object (same value, different value, escaped spelling), `__proto__`-style keys |
| num | 728 | 56 number literals at 13 numeric slots: `-0`, `1.0`, `1e400`, 2^53+1, leading zeros, non-ASCII digits |
| struct | 984 | null / missing / empty / array-vs-object / type confusion at every path of a signed PCActn, re-signed |
| uni | 193 | NFC vs NFD, surrogates, noncharacters, control characters, audience and nonce byte-length bounds per UTF-8 width, UTF-8 vs UTF-16 key order |
| b64 | 566 | base64url at 14 byte fields: padding, standard alphabet, whitespace, trailing bits, wrong length, wrong type |
| alg | 369 | `alg` none / case / whitespace / lookalike, stray or missing `pq_pk` / `pq_sig`, half-missing hybrids, at leaf and hop |
| key | 224 | small-order, identity and non-canonical Ed25519 keys with forged signatures; wrong-length keys |
| gref | 40 | `grant_ref_bound` variants; chains of 1 to 20 hops |
| depth | 41 | nesting 20 to 100000 levels, wide arrays and objects, huge digit strings and exponents |
| merkle | 170 | genuine proofs for plan sizes 1 to 129; shape-correct paths for index and size up to 2^53-1 |
| time | 398 | `iat` / `exp` / `now` boundaries to the millisecond, including int32 and int53 magnitudes |
| atten | 76 | the append-only caveat rule with validly signed hops: every reorder, drop, value edit, junk caveat |

That is 4,209 vectors at the time of this audit (4,358 in the current corpus, after the size-cap, caveat-cap and weak-key families were added), plus 1,178 primitive vectors (425 `json_parse`, 718 `b64u`, 35 `canonical`).
Before this audit the file held 172 vectors.

### Differential gate (`bash scripts/pca-conformance-all.sh --fuzz 300`)

The core plus the full adversarial set, and the earlier adversarial corpus, run through every verifier, together with a
6,000-mutant structural sweep, 300 seeded fuzz mutants and a size/time corpus. The gate fails on any
accept/reject difference, any check-map difference, any crash, and any vector that takes more than one
second beyond the language's cold-start time.

The size/time corpus (`tools/pca-diff-fuzz/gen/dos.mjs`, 59 vectors) includes: inputs of exactly 512 KiB
(524,288 bytes) and one byte more, padded with 1-, 2-, 3- and 4-byte characters and with escapes; 1 MiB and
just-under-512-KiB documents of `[`, of `{"a":`, of digits, of exponent text, of base64 characters (the 1 MiB ones are now
refused by the artifact cap before parsing, the under-cap twins still reach the strict parser); 25k-key and 20k-duplicate-key
objects; 150k-element arrays; a 100,000-step inclusion path; 5,000-hop and 17-hop chains; and caveat lists of 15,000
entries. Caveat lists of that size are now rejected by a shared cap (see below), and limit-1 / limit / limit+1 vectors for
both caveat caps and for the artifact size cap, plus a ~200 KB hybrid-LESS-sized document that must be accepted, are part of the corpus.

### Caveat-size cap and the 15,000-caveat vector

The 15,000-caveat attenuation vector was the slowest in the corpus (Ruby about 1.6 s against a 96 ms baseline; Java,
TypeScript and Python 1.0 to 1.7 s at p95). The attenuation check itself is linear (one canonical hash per
parent caveat per hop), not quadratic; the cost was hashing and re-serialising 15,000-caveat lists,
plus, in Ruby, a slow pure-Ruby strict JSON parser and canonicalizer on the 760 KB input. Fix, applied to the
TypeScript reference and, in two steps, to every native verifier (first Ruby, Java and Kotlin, then Go, Python, PHP,
.NET, Rust and Swift):

* **Shared hard cap**: a chain is rejected, before any hashing or signature work and after the 16-hop bound, when a
  hop carries more than 256 caveats or the caveat counts of all hops sum to more than 1,024 (reason
  `chain exceeds caveat limit (max 256 per hop, 1024 per chain)`). Caveat lists are cumulative, so this bounds the
  prefix comparison work to at most 1,024 hashes per chain. Real use is far below it (at most 5 caveats in any
  in-repo example). **Breaking** for chains above the cap.
* **Dafny model**: unchanged. `Chain.dfy` models caveats as opaque sequences and bounds only depth (16); the caveat cap
  is a pre-check in the trusted glue (`verifyChainUnchecked`, before `decideChain`) and only turns an accept
  into a reject, so no proof obligation changes.
* **Ruby parser/canonicalizer**: plain-run string scan, short-integer fast path, no-escape fast path; output is
  byte-identical (0 disagreements on the corpus).
* New vectors at limit-1, limit, limit+1 for each cap (`caveats-per-hop-*`, `caveats-per-chain-*`), and the
  golden `adv-atten-many-500` / `-2000` and `caveat-lists/root-many-identical-1000` now expect reject.
* Go, Python, PHP, .NET, Rust and Swift now carry the same pre-check (same position, same reason string), so all nine
  native verifiers and the TypeScript reference agree on every over-cap vector.

### Artifact size cap (512 KiB)

The 15,000-caveat vector and the 17-hop fat-caveat vector are 760 KB documents. Even with the caveat caps, every
verifier still had to read, parse and (for the tree-building parsers) allocate the whole document before it could
refuse it. A second shared limit now bounds the raw wire size of a PCActn JSON document:

* **Hard cap**: 524,288 bytes (512 KiB) of UTF-8 text. It is the FIRST check in every verifier, before any JSON
  parsing, and the refusal is a terminal `wire` failure with the reason `artifact exceeds size limit (max 524288 bytes)`.
  For byte strings and for text in languages that store UTF-8 (Go, Rust, Ruby, PHP, Swift) it is a length read; Python,
  Java, Kotlin, .NET and TypeScript use a length bound first and count bytes only for text of roughly 128 K to 512 K
  characters. The strict JSON profile keeps its own 1 MiB bound for non-PCActn use (`canon` / `json_parse` primitives),
  which a PCActn can no longer reach.
* **Headroom**: a hybrid LESS PCActn carries a base64url `pq_pk` of about 130 KB plus the signature; with a few hops it
  is about 200 KB. The `adv-size-less-hybrid-200KB` vector (a signed PCActn of about 200 KB in the same shape) must be
  accepted.
* **Boundary vectors**: limit-1, limit and limit+1 (whitespace padding, trailing and leading), the same boundary
  with 2-, 3- and 4-byte characters (bytes, not characters or UTF-16 units, are counted), and the DoS corpus's
  `artifact-size-*` set.
* **Dafny model**: unchanged. `Wire.dfy` models the strict JSON profile's 1 MiB bound; the artifact cap is a stricter
  precondition applied before the modelled parser and only turns an accept into a reject, so no proof obligation changes.
* **Breaking** for documents above 512 KiB.


## Ed25519 strictness (weak keys and signatures), per verifier

The reference accepts a signature only if S < L, A and R are canonical on-curve encodings, neither is small-order, both are torsion-free, and the equation holds. Audit and results (family `adv-ed-*`, 133 vectors, plus 44 `ed-weak-*` threshold shares):

| verifier | implementation | strictness |
|---|---|---|
| Go | own big-int decode + `[L]P` check, then `crypto/ed25519` | full; agrees |
| Python | pure-Python Ed25519 (own arithmetic) | full; agrees |
| Ruby | own subgroup arithmetic (`8P`, `[L]P`), then OpenSSL | full; agrees |
| PHP | libsodium (`pk_to_curve25519` subgroup test on A and R, `verify_detached` for S, canonical A, R) | agrees (relies on libsodium behaviour, which the vectors pin) |
| .NET | own decode + `[L]P` check, then BouncyCastle | full; agrees |
| Rust | canonical re-encode, `is_small_order`, `is_torsion_free`, S < L, `verify_strict` | full; agrees |
| Java, Kotlin | small-order table + canonical y + BouncyCastle `validatePublicKeyFull` (A and R) + S < L | full; agree |
| Swift | small-order table, then CryptoKit | **was NOT strict**: mixed-order A with k = 0 (mod 8) verified. Fixed with an exact `[L]A = O` test (`Ed25519Torsion`) |

## Results after the size cap and the all-language caveat cap

* Gate (`--fuzz 300`, shared box, load about 4): 11,914 vectors, ten implementations, 0 cross-language disagreements
  (TypeScript reference, Go, Python, Ruby, PHP, .NET, Rust, Java by driver; Kotlin native 4,389 passed / 0 failed; Swift native on the
  Mac 4,393 passed / 0 failed on core plus the full adversarial set, 32 suite-skips). The `adv-size-*` family and the
  `artifact-size-*` DoS vectors agree everywhere.
* The two 760 KB vectors (`atten-15000-caveats-prefix-compare`, `chain-17-hops-fat-caveats`) are now refused by the size rule
  before parsing. Whole-process wall time p50 / p95 over 15 runs, including process start and the driver reading the 760 KB line
  (not exclusive: the farm had no idle box): Python 49/53 and 42/43 ms, Ruby 146/228 and 61/74, PHP 56/59 and 17/19, .NET 98/113 and 77/90,
  Rust 12/21 and 4/5, Java 175/197 and 130/137 (JVM start is 283 ms, so the excess is negative). Ruby's figure is dominated by the driver's own
  `JSON.parse` of the input line. Go and TypeScript were not benchmarked per vector; their worst vector in the gate was +81 ms and +99 ms over baseline,
  and neither is an over-cap vector. Swift: the size check is a single `utf8.count` (the unit test refuses a 512 KiB+1 document in under 100 ms).

## Results

* Disagreements between verifiers: 0, in the committed corpus and in the gate.
* The gate ran 11,762 vectors with the default seed and 10,421 vectors with a second seed (777, 5,000 fuzz mutants).
  All eight verifiers agreed on every one.
* Slowest vector, relative to each language's cold start: Ruby +588 ms, Python +422 ms, PHP +294 ms,
  .NET +237 ms, TypeScript +187 ms, Java +176 ms, Rust +55 ms, Go +43 ms. All on the 15,000-caveat
  chain. No vector approached the one-second limit, and none exceeded 100 MB.
* Algorithm and suite confusion (`alg: none`, wrong case, trailing whitespace, hybrid with half the
  signature, ed25519 with stray PQ fields), key-type confusion and every `grant_ref_bound` variant gave the
  same verdict in all eight.

None of the eight matrix verifiers needed a fix. Two things did need fixing in the test harness: a Python
test hard-coded the 172-vector corpus size, and the gate now compares the larger committed manifest.
The Swift verifier, run on the corpus for the first time, did have real bugs (see "Kotlin and Swift").

An earlier pass of the project had already driven the verifiers to agreement on 7,087 vectors, which is
likely why a further 4,209 targeted vectors found nothing. This audit raises the confidence; it is not a proof.

## Limits

* **Transport.** Vectors and fuzz inputs travel as JSON text. Invalid UTF-8 byte sequences (overlong
  encodings, lone surrogate bytes, truncated sequences) cannot be represented, so they are not tested.
  A deployment must decide how its host decodes bytes to text; a lenient decoder substitutes U+FFFD, which
  changes the signed content and makes the signature fail, but that behaviour is the host's, not the
  verifier's.
* **PQ key binding (R3-03, fixed).** Until this fix none of the nine native verifiers enforced the `holder_pq` binding the
  TypeScript reference enforces: a pure `ml-dsa-65` (or hybrid) hop or leaf verified under the artifact's own `pq_pk`, so a
  PCActn signed only with an attacker's ML-DSA key over an honest Ed25519 grant was accepted (Python demonstrated; TS denied).
  The natives also rejected `holder_pq` on the wire, so every correctly bound PQ vector failed. All nine now port
  `pqBindingError` for hops (index >= 1) and the leaf, hash `holder_pq` into the hop body, and take an optional `allowed_suites`
  policy (`context.allowed_suites` in vectors; `[]` refuses everything). They are fail-closed: there is no `allowUnboundPq`.
  Coverage: 26 `pqbind-*` vectors, run natively by every language and as the `pq-binding` gate category (the gate on 11,868
  vectors: 0 disagreements among ts, go, python, dotnet, rust and java; ruby and php agree with ts on a 6,668-vector run on a
  host with OpenSSL >= 3.5). Ruby and PHP verify ML-DSA through OpenSSL >= 3.5; on an older libcrypto they fail closed, so PQ
  positives are denied there (a host limitation, not a disagreement in the binding logic).
* **Post-quantum suites.** Verifiers implement different subsets of the ten signature suites. Vectors that
  need a real PQ verification under an unimplemented suite are skipped (reported, not counted as passed).
  Mutants derived from PQ vectors are committed only when their verdict does not depend on a PQ
  verification (terminal wire failure, or plain ed25519), so PQ downgrade confusion is checked at the wire
  layer only.
* **Kotlin and Swift.** Both now run natively over the core corpus and over the full adversarial set (core
  sample replaced by the full 4,381 vectors and all adversarial primitives; the runners read an uncompressed
  copy named by `PCA_CONFORMANCE_ADV`, which the gate creates). They are not in the per-vector process matrix,
  so the fuzz and sweep corpora are not run through them.
  * Kotlin: the verifier is plain JVM Kotlin plus BouncyCastle, so it is built without Android: the
    `kotlin-compiler-embeddable` jar from any Gradle distribution compiles `src/main` and the test
    `ConformanceRunner.kt`, which is then run with a JDK (Temurin 21 and the Homebrew JDK both work). Result:
    4,345 of 4,381 vectors run and pass, 36 skipped for the seven signature suites not implemented in Kotlin,
    0 failures, 25,253 assertions. It takes about 1.5 seconds. The core corpus alone: 226 run, 0 failures.
  * Swift: the earlier "did not finish" was a harness problem, not the verifier. The test's lone-surrogate
    sanitiser rebuilt a `String.UnicodeScalarView` one scalar at a time, which scaled far worse than linearly in a
    debug build (the 2 MB core took 1.4 s per load, the 15 MB set had not finished after 3.5 minutes). It is now a linear byte scan and the corpus is loaded
    once. Core corpus: 9 conformance tests in 0.7 s. Full set: 4,349 of 4,381 run and pass, 32 skipped for
    unimplemented suites, in about 4 s. Running it found three real Swift verifier bugs, all fixed:
    1. Swift `String` equality and hashing use canonical equivalence, so two distinct JSON keys, NFC `é` and
       NFD `e` plus U+0301, collided in the `[String: JSONValue]` dictionary and were rejected as duplicate
       keys. Object keys are now stored as `JKey`, compared and hashed by exact Unicode scalars, and the
       key sort no longer treats canonically equivalent keys as equal.
    2. The same equivalence made `aud` NFC and NFD compare equal, so a PCActn with an NFD audience was
       accepted by a verifier configured with the NFC spelling. The audience check is now scalar-exact.
    3. U+10FFFF was reused as the harness' lone-surrogate sentinel and honoured by the library's strict
       canonicalizer, so a valid U+10FFFF (`\uDBFF\uDFFF`) in signed content was rejected as a lone surrogate.
       The library no longer interprets any sentinel (the strict parser already rejects lone surrogates), and
       the harness uses a noncharacter.
    Swift's only remaining skips are the unimplemented suites, as before.
* **Gate timing under load.** The gate's one-second-over-baseline DoS check is wall-clock. On a shared machine
  with a load average of 40 to 67 (other jobs running) the 15,000-caveat vector exceeded it for Ruby, PHP, .NET
  and Java (1.4 to 2.0 s) while every verdict still agreed; on a quiet machine the same vector stayed under it.
  Treat that failure as a timing flake to re-run on an idle host, not a disagreement.
* **Scope.** Only core PCActn verification, capability chains, Merkle plan inclusion and threshold shares
  are covered. Ledger and transparency-log JSON are not verified by these SDKs and are not covered.
* **Timing is wall-clock on one machine.** It shows no quadratic blow-up at the sizes tried; it is not a
  constant-time claim.
* **The reference is the oracle.** A bug shared by the reference and all eight verifiers would not be
  seen. Where the correct answer was unconditional (the "want" assertions in the generator), the
  reference was checked against intent, and every such assertion held.

## Reproduce

    pnpm --filter @atlasauth/pca build
    node packages/pca/scripts/gen-conformance.mjs
    node packages/pca/scripts/gen-conformance-pq.mjs
    node packages/pca/scripts/gen-conformance-adv.mjs     # deterministic, idempotent
    bash scripts/pca-conformance-all.sh --fuzz 300
