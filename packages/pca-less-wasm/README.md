# @atlasauth/pca-less-wasm

**LESS** code-based signatures for [`@atlasauth/pca`](https://www.npmjs.com/package/@atlasauth/pca): the
official LESS reference C compiled to WebAssembly, with a tiny portable loader that has **no dependency
and no `node:` import** -- it runs in Node >= 20, browsers, Web Workers, Deno, Bun and edge runtimes.

> **Status, stated plainly.** LESS is a NIST *additional digital signature* **Round 2 candidate** -- it is
> **not a standard**. This wrapper is checked against the official known-answer tests, a native-vs-wasm
> differential, sanitizer runs and a robustness suite (numbers below), but it has had **no independent
> audit**, there is **no independent implementation** to compare against, the reference's keygen/sign are
> not constant-time, and the reference verifier had three memory-safety defects on forged signatures
> that this package works around. Use it for hardness diversity, **in a hybrid with a classical
> signature** (PCA's `hybrid-ed25519-less-cat1` suite), not as a sole signature.

LESS' security rests on the code-equivalence problem -- a hardness family distinct from lattices
(ML-DSA, FN-DSA) and hashes (SLH-DSA).

## Install

```bash
npm install @atlasauth/pca-less-wasm
```

## Usage

```ts
import { keygen, sign, open, signDetached, verify, seedWith, sizes, VARIANT } from '@atlasauth/pca-less-wasm';

console.log(VARIANT);   // 'less-252-45'  (NIST category 1, short-signature corner)
console.log(sizes());   // { publicKey: 97484, secretKey: 32, signatureMax: 1329, seed: 16 }

const { publicKey, secretKey } = keygen();               // seeds from crypto.getRandomValues
const msg = new TextEncoder().encode('proof-carrying authority');

const sm = sign(secretKey, msg);                          // attached: message || signature
const { ok, message } = open(publicKey, sm);              // ok === true

const sig = signDetached(secretKey, msg);                 // detached, 1153-1329 bytes
verify(publicKey, msg, sig);                              // true; never throws on bad input
```

`seedWith(seed48)` makes keygen/sign deterministic (KATs, tests). `verify`/`open` consume no randomness.

### Browsers, workers, Deno, edge: the portable path

The `browser` export condition (and the `/web` subpath) resolve to an ES-module build with no `node:`
imports. Browsers restrict synchronous compilation of large modules, so initialise asynchronously once:

```ts
import { initLess, keygen, verify } from '@atlasauth/pca-less-wasm/web';

await initLess(new URL('/assets/less_cat1.wasm', import.meta.url)); // or a URL string, a Response, or bytes
// ...or fully self-contained (base64 inside the JS, ~130 KB):
//   import { initLessEmbedded } from '@atlasauth/pca-less-wasm/embedded'; await initLessEmbedded();
```

The wasm file itself is exported as `@atlasauth/pca-less-wasm/less_cat1.wasm` for bundlers (`?url`,
`new URL(..., import.meta.url)`). In Node/Bun/Deno the default entry loads the bundled file synchronously,
so no init call is needed. The only host import the wasm needs is WASI `random_get`, implemented over
`globalThis.crypto.getRandomValues`; **if Web Crypto is missing, keygen/sign throw (fail closed)** rather
than seed from anything weaker, while verification (which needs no randomness) keeps working.

## Build provenance

| | |
|---|---|
| Artifact | `wasm/less_cat1.wasm`, 96,209 bytes |
| SHA-256 | `2d6c8141f5194d2b808627105b7bf593c97d3e6544084b40248f42dbd1bf096e` |
| Source | https://github.com/less-sig/LESS, commit `6383430b9123e69d2ef6a6224f930972e3225610`, `Reference_Implementation/`, `-DCATEGORY=252 -DTARGET=45` (public domain; unmodified) |
| Toolchain | clang 19.1.5 from wasi-sdk 25 (recorded in the wasm's `producers` section), `-O2 -std=c99`, portable scalar C (no AVX/NEON defines), `-mexec-model=reactor` |
| Added C | the ~40-line seam `less_wasm_glue.c` (embedded in `scripts/lessbuild.sh`): seeds the reference CSPRNG and exposes flat buffers |
| Reproduce | on x86_64 Linux: `scripts/lessbuild.sh /tmp/work /tmp/out` (downloads wasi-sdk-25, clones LESS), copy `less_cat1.wasm` here, then `node scripts/embed-wasm.mjs` |

The build script fetches and checks out exactly the commit above and refuses to build at any other commit. The
build log of the SHIPPED binary was not retained, so what ties that artifact to the commit is that it reproduces the
commit's KAT byte-for-byte; a fresh rebuild has not been shown to be bit-identical to the shipped file.

## Evidence and findings

Everything below was actually run (2026-10-08, Apple clang 21 / Homebrew LLVM clang 22.1.8 on arm64
macOS; wasm built by wasi-sdk-25). It is evidence of *implementation fidelity and robustness*, **not**
of cryptographic security.

**Source pinned**: upstream `https://github.com/less-sig/LESS` commit
`6383430b9123e69d2ef6a6224f930972e3225610` (current `main` head at time of writing; "Version 2.1"
tree), `Reference_Implementation/`, `-DCATEGORY=252 -DTARGET=45`. The shipped
`wasm/less_cat1.wasm` has SHA-256 `2d6c8141f5194d2b808627105b7bf593c97d3e6544084b40248f42dbd1bf096e`.
The build log does not record the commit it was built at; what ties the artifact to this source is that
it reproduces that commit's KAT exactly.

| Check | Result |
|---|---|
| Official KAT (`Utilities/KAT_Generation/KAT/PQCsignKAT_97484.rsp`, the file whose pk length = this build's 97,484 B; upstream ships 7 `.rsp`, one per parameter set, 100 entries each) reproduced by the **wasm** | **100/100** byte-identical (pk, sk, signed message) and all open (`src/kat.test.ts`, compact digest committed in `src/kat/`) |
| Same KAT, native clang `-O2` | 100/100 |
| Same KAT, Homebrew clang 22 `-O3 -fsanitize=undefined` | 100/100 |
| Same KAT, apple clang `-O0 -fsanitize=address,undefined -fno-sanitize-recover` | 100/100, no sanitizer findings (valid-input path) |
| Differential wasm vs native `-O2`, random (seed 32 or 48 B, msg 0-399 B) | 300/300 byte-identical pk, sk, signed message; each side opens the other's signature |
| Differential wasm vs native `-O3`+UBSan | 300/300, same |
| Differential wasm vs native ASan/UBSan `-O0` | 10/10, same |
| Exhaustive single-bit flips of every bit of one valid signature (native `-O2`) | 10,370 flips run, **0 accepted**; 6 more (final byte, see defect 1) skipped by the harness as they crash the raw reference |
| Native-vs-wasm accept/reject agreement on 100 tampered signatures | identical |
| Structure-aware fuzz of the raw native verifier (`scripts/fuzz-open.mjs`) | Unmasked random bodies / cf rows crash under UBSan+ASan (defect 2); forged digests crash ASan on an unpadded buffer (defect 3). With padding bits cleared and the buffer padded: ~760 malformed signatures under ASan/UBSan (4 structure classes), 0 sanitizer findings, 0 accepted |
| Wasm negative suite (`src/robustness.test.ts`, 12 tests) | tamper (sampled across all regions), wrong message/key/size, truncation (prefix and suffix), oversize, 400 garbage buffers, repeat-determinism, region complements/reversal: all rejected, never throws |

Not available / not run: `valgrind` (does not run on this macOS), LeakSanitizer (unsupported on
arm64 macOS), MSan, a second *wasm* toolchain (no wasi-sdk on this machine). The wasm and native builds
compile the **same** C, so their agreement rules out toolchain/ABI/UB-driven divergence on tested inputs;
it is not an independent implementation of the LESS specification, and the KATs were produced by that same
reference code.

### Upstream defects found (reference unmodified; mitigated in the wrapper)

All three are in the public-input path (a forged *signature*), so they matter to a verifier.

1. **`crypto_sign_open` has no `smlen >= sig_len` check** (`sign.c`). A short input, an empty input, or a
   *valid signature whose final leaf-count byte has one bit flipped upward* (e.g. `9 -> 11`) makes
   `*mlen = smlen - sig_len` underflow and the following `memcpy` crash: SIGBUS native, `RuntimeError:
   memory access out of bounds` trap in wasm (which previously made `open`/`verify` **throw** on
   garbage). Native ASan: `negative-size-param` at `sign.c:81`.
2. **Padding bits in `cf_monom_actions`**: `CheckCanonicalAction` requires popcount == K over all 256
   bits of a row but `UnpackCosetRep` only walks the first N=252, so a row with padding bits 252-255 set
   (and total weight K) makes the verifier write up to 4 bytes past `permuted_G_col_pivot[252]` and past
   the generator matrix. Native ASan/UBSan: `stack-buffer-overflow` at `monomial.c:201` / index 252
   out of bounds at `monomial.c:205`. In wasm there is no detector; it would silently corrupt adjacent
   stack memory (not demonstrated beyond the native sanitizer report).
3. **`RebuildGGM` over-reads past the signature** (`seedtree.c:262`): the number of seeds read comes from
   the challenge hash, not the stored leaf count, so a forged digest makes it read up to `(T-W)*16 = 176`
   bytes beyond the end of the signature (native ASan `heap-buffer-overflow`, 16-byte read, 0 bytes after
   the buffer). Read-only; not shown to leak anything.

Mitigations (in `src/index.ts`, no C changed): reject inputs shorter than their trailing byte claims
(1), reject any `cf_monom_actions` row with a padding bit set (2), and give the wasm a zero-filled
`signatureMax`-byte tail after the signed message (3). Honest output never trips these: every KAT and
several hundred freshly generated signatures pass through them. After the mitigations, the same fuzz classes run clean
under ASan and UBSan natively (padded driver, `LESS_PAD=1`). These defects have **not** been reported
upstream from this work.

### Malleability

No alternative encoding of a valid signature was found to verify: 0 of 10,370 single-bit variants,
plus region complement/reversal/cross-message tests. Signing the same (key, message) twice yields two
different valid signatures (randomized salt); that is scheme randomization, not malleability. This is
absence-of-evidence over the tested space, not a proof of strong unforgeability/non-malleability.

### What is still missing (why this is a candidate, not a recommendation)

Evidence that does **not** exist yet:

- An **independent implementation** (third-party, different codebase) agreeing on the KATs. Only the
  upstream reference exists here; all KATs are self-generated by it.
- **External cryptanalysis**: LESS's security (code equivalence) is an actively studied, young problem;
  none of the above says anything about it.
- The **NIST outcome**: LESS is a round-2 additional-signatures candidate, not a standard.
- A **security/code audit** of the reference (three memory-safety defects in the verifier were found
  with a few hours of sanitizer work, which argues the reference is not yet hardened) and the upstream
  fix or acceptance of the three defects.
- **Constant-time** evidence for keygen/sign (upstream itself says they are not fully constant-time).
- A reproducible wasm build in CI (today it is a manual off-box build; the script pins the upstream commit, but a
  bit-identical rebuild of the shipped file has not been demonstrated).

### Reproducing

```bash
scripts/build-native.sh /tmp/less-nat            # pinned upstream + 3 native variants
LESS_NATIVE_DIR=/tmp/less-nat/bin LESS_DIFF_N=300 npx vitest run src/crosscheck.test.ts   # ~16 min
LESS_PAD=1 node scripts/fuzz-open.mjs /tmp/less-nat/bin/less_O0asan 40                    # ASan fuzz
npx vitest run                                    # default: KAT + negative suite + portability + round trip (~3 min)
```
`scripts/make-kat-digest.mjs` regenerates `src/kat/less-252-45.digest.json` from the upstream `.rsp`.

## License

MIT (see `LICENSE`). The LESS reference implementation is public domain (see upstream `LICENSE`).
