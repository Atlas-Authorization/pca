# LESS → WASM build recon (STEP 1 findings)

Recon of the **official LESS reference implementation** to cross-compile its
code-based signature to WebAssembly (WASI). LESS is a NIST "additional
signatures" (round-1/2) candidate whose security rests on the **code
equivalence / syndrome-decoding** hardness family — the genuine *third* family
beyond lattices and hashes.

- Upstream: `https://github.com/less-sig/LESS` (cloned @ commit `6383430`, tag/version 2.1.x; `api.h` says "version 1.2, February 2025").
- Reference fallback mirror: `https://github.com/paolo-santini/LESS_project`.
- License: public-domain style (BSD-ish disclaimer in every file; see repo `LICENSE`).

> **Verdict up front:** the reference implementation **cross-compiles to
> `wasm32-wasi` with ZERO source edits.** The only x86 intrinsics in the whole
> reference tree live in `lib/sort.c` and are fully guarded behind
> `USE_AVX2` / `USE_AVX512` / `USE_NEON` / `LESS_USE_CUSTOM_HISTOGRAM`, with a
> plain scalar `memset`+histogram fallback that is selected whenever those
> macros are **not** defined. We simply do not define them and do not pass
> `-mavx2`. Everything else (Keccak/SHA-3, field arith, Gaussian elimination,
> seed tree, canonical forms) is portable C99.

---

## (a) Which directory is the portable REFERENCE implementation

`Reference_Implementation/` — a C99 library, no `main()`, exposing the NIST API
in `Reference_Implementation/include/api.h`. It ships its **own generic Keccak**
(`lib/fips202.c`, `lib/keccakf1600.c`), so there is **no OpenSSL dependency** for
the core primitive.

Do **NOT** use `Optimized_Implementation/{avx2,avx512,neon}` — those pull in
`KeccakP-1600-AVX2.s` (x86 asm), `transpose_avx2.c`/`transpose_neon.c`, and set
`-march=native` + vector ISA flags. They cannot target wasm.

The repo's build system is **CMake** (not Make). Relevant files:
- `Reference_Implementation/CMakeLists.txt` — builds bench/test/KAT binaries directly.
- `Utilities/KAT_Generation/CMakeLists.txt` — the canonical "pick an implementation" driver: `-DUSE_REFERENCE=1` (default ON) vs `-DUSE_AVX2/AVX512/NEON=1`. This is the file that documents exactly which sources make up one build.

## (b) Exact C sources for keygen + sign + VERIFY (one param set)

From `Reference_Implementation/CMakeLists.txt` `SOURCES` (the 12 core `.c`), all
under `Reference_Implementation/lib/`:

```
codes.c        # RREF / Gaussian elimination over F_q, information sets
fips202.c      # generic SHA-3 / SHAKE (portable)
keccakf1600.c  # generic Keccak-f[1600] permutation (portable, NO asm in ref)
LESS.c         # LESS_keygen / LESS_sign / LESS_verify (the scheme)
monomial.c     # monomial (permutation+scaling) matrices
rng.c          # the CSPRNG seam (SHAKE-based) + platform_csprng_state
seedtree.c     # GGM seed tree (sign/verify seed disclosure)
sign.c         # NIST wrappers: crypto_sign_keypair / crypto_sign / crypto_sign_open
sort.c         # constant-ish sorting + histogram (AVX paths are #if-guarded; scalar fallback used)
utils.c        # bit (de)packing helpers
canonical.c    # canonical-form computation for codes
transpose.c    # matrix transpose (portable; AVX/NEON transpose lives only in Optimized_*)
```

Headers needed (`Reference_Implementation/include/`): `api.h`, `LESS.h`,
`parameters.h`, `codes.h`, `fips202.h`, `sha3.h`, `keccakf1600.h`, `fq_arith.h`,
`monomial_mat.h`, `rng.h`, `seedtree.h`, `utils.h`, `sort.h`, `transpose.h`,
`canonical.h`, `lookup_table.h`.

**Explicitly EXCLUDED for wasm:**
- `lib/nist/KAT_NIST_rng.c`, `lib/nist/PQCgenKAT_sign.c` — the NIST KAT harness; its DRBG is **AES-CTR via OpenSSL** (`find_package(OpenSSL)` / `OpenSSL::Crypto`). We replace its randomness with a WASI/`getentropy` seam (see (e)).
- `lib/bench/*` (`cycles.h` uses `__asm__ rdtsc`), `lib/test/*`.

Public API (`LESS.h`) — this is what the wrapper binds:
```c
void   LESS_keygen(prikey_t *SK, pubkey_t *PK);                                  // cannot fail
size_t LESS_sign  (const prikey_t *SK, const char *m, size_t mlen, sign_t *sig); // returns #opened seeds
int    LESS_verify(const pubkey_t *PK, const char *m, size_t mlen, const sign_t *sig); // 1=ok, 0=fail
```
NIST flat-buffer wrappers (`sign.c`, attached-signature `sm = message || sig`):
```c
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);                                   // 0 ok
int crypto_sign(uint8_t *sm, u64 *smlen, const uint8_t *m, u64 mlen, const uint8_t *sk); // 0 ok
int crypto_sign_open(uint8_t *m, u64 *mlen, const uint8_t *sm, u64 smlen, const uint8_t *pk); // 0 ok, -1 fail
```
The wasm glue binds the **NIST flat-buffer wrappers** (they handle the variable
seed-tree signature length: last signed-message byte carries the opened-leaf
count, read back by `crypto_sign_open`). The wrapper also exports size-query
functions so TS never hard-codes a magic number.

## (c) Exact preprocessor defines to select ONE parameter set

Parameter set = **`-DCATEGORY=<252|400|548> -DTARGET=<...>`** (see
`include/parameters.h`). `CATEGORY` is the field length `N`, not the NIST level
number. **NIST Category 1 == `CATEGORY=252`** (N=252, K=126, q=127,
`SEED_LENGTH_BYTES=16`). The three category-1 corners:

| `-DTARGET=` | NUM_KEYPAIRS | T   | W  | MAX_PUBLISHED_SEEDS | pubkey (approx) | sig worst-case (approx) | character          |
|-------------|--------------|-----|----|---------------------|-----------------|-------------------------|--------------------|
| `45`        | 8            | 45  | 34 | 11                  | ~95 KB          | ~1.3 KB                 | **short signature** |
| `68`        | 4            | 68  | 42 | 26                  | ~41 KB          | ~1.8 KB                 | intermediate       |
| `192`       | 2            | 192 | 36 | 87                  | ~14 KB          | ~2.6 KB                 | small key / balanced |

**Chosen default: `-DCATEGORY=252 -DTARGET=45`** — the short-signature corner
(the one the upstream README showcases, `LESS_benchmark_cat_252_45`). Smallest
signature is the property that matters when a code-based signature travels
inside a PCA proof/token. The build script (`lessbuild.sh`) takes
`LESS_CATEGORY`/`LESS_TARGET` env overrides so switching to the balanced `192`
(small pubkey) or `68` is a one-flag change with no other edits.

Sizes above are *approximate* and documented only for orientation — the wrapper
reads the **exact** `CRYPTO_PUBLICKEYBYTES` / `CRYPTO_SECRETKEYBYTES` /
`CRYPTO_BYTES` / `CRYPTO_RANDOMBYTES` from the compiled module at load time
(exported `less_public_key_bytes()` etc.), so no size is hard-coded in TS.

Derived (from `parameters.h`, for 252): `HASH_DIGEST_LENGTH = 2*SEED_LENGTH_BYTES
= 32`, `SALT = 32`, `SHAKE = shake128` for CATEGORY 252 (shake256 for 400/548).

**Do NOT define** `USE_AVX2`, `USE_AVX512`, `USE_NEON`, or
`LESS_USE_CUSTOM_HISTOGRAM`. Leaving them undefined:
- selects the scalar histogram in `sort.c` (`#ifndef LESS_USE_CUSTOM_HISTOGRAM`);
- keeps `parameters.h` padding at `N_pad=N`, `K_pad=K`, `N_K_pad=N-K` (the
  `#if defined(USE_AVX2|AVX512|NEON)` branch forces 32-multiple padding; the
  reference branch does not — important for struct/byte layout).

## (d) Include dirs

Exactly one: `-I <repo>/Reference_Implementation/include`. (All headers are flat
in that one directory; `include_directories(include)` in the ref CMakeLists.)

## (e) Randomness — the CSPRNG seam (critical for wasm)

**There is no `/dev/urandom`, `getrandom`, or `rdrand` anywhere in the reference
core.** Grep of `Reference_Implementation/lib` + `include` finds entropy calls
only in the excluded `nist/` KAT harness (`KAT_NIST_randombytes_init`, AES-CTR
DRBG / OpenSSL) and a comment in `rng.c`.

The entire library funnels randomness through a **single global SHAKE CSPRNG**
(`rng.h` / `rng.c`):
- `extern SHAKE_STATE_STRUCT platform_csprng_state;` (defined in `rng.c`).
- `randombytes(x, xlen)` — `static inline` in `rng.h` — just squeezes
  `platform_csprng_state` (`xof_shake_extract`). It is **not** OS entropy; it is
  a deterministic XOF stream that must be *seeded first*.
- `init_randombytes(seed, seed_len)` — `static inline` in `rng.h` — seeds
  `platform_csprng_state` via `initialize_csprng` (SHAKE init/update/final).
- Only two core callsites consume it: `LESS_keygen` (draws the secret-key seed)
  and `LESS_sign` (draws the salt). **`LESS_verify` consumes no randomness** —
  verify is fully deterministic and needs no entropy at all.

So the wasm randomness strategy is clean and needs **no source edits** — just a
tiny glue file (emitted by `lessbuild.sh` as `less_wasm_glue.c`) that seeds the
existing global state:
- `less_autoseed()` → `uint8_t s[32]; getentropy(s, sizeof s); init_randombytes(s, sizeof s);`
  `getentropy` is provided by **wasi-libc** and lowers to the WASI
  `random_get` host call — the correct, sandbox-safe wasm entropy source
  (NOT glibc `/dev/urandom`).
- `less_seed(seed, len)` → `init_randombytes(seed, len)` — inject a caller seed
  (for KATs / deterministic reproducibility / BYO-RNG from JS
  `crypto.getRandomValues`).

The caller (KAT harness / TS wrapper) MUST call `less_autoseed()` or
`less_seed(...)` **once before `less_keypair`/`less_sign`**; `less_verify`/
`less_open` need no seeding.

---

## Build knobs the VM script applies (summary, see `~/.pca-vm-state/lessbuild.sh`)

- Toolchain: `wasi-sdk-25.0` (`clang --target=wasm32-wasi`, its bundled
  `wasi-sysroot`). `getentropy` resolves from wasi-libc; no `--allow-undefined`.
- Compile: `-O2 -DCATEGORY=252 -DTARGET=45 -I .../Reference_Implementation/include`,
  the 12 core sources + `less_wasm_glue.c`. **No** `-mavx2`/`-march=native`, **no**
  `USE_AVX*`/`USE_NEON`/`LESS_USE_CUSTOM_HISTOGRAM`.
- Link (reactor): `-mexec-model=reactor`
  `-Wl,--export=less_autoseed,--export=less_seed,--export=less_keypair,`
  `--export=less_sign,--export=less_open,--export=less_public_key_bytes,`
  `--export=less_secret_key_bytes,--export=less_signature_max_bytes,`
  `--export=less_seed_bytes,--export=malloc,--export=free`
  plus `-Wl,-z,stack-size=8388608` (LESS puts ~31 KB code matrices on the stack;
  the wasi-libc default 64 KiB stack is too small — this is the one non-obvious
  footgun, so we raise it to 8 MB).
- KAT: a Node WASI harness (`less_kat.mjs`) instantiates the reactor, runs
  `autoseed → keypair → sign(msg) → open`, asserts the recovered message equals
  the input and `open` returns 0. Emitted to `<out>` and run if `node` is present.

## Honest status / caveats

- This is **NIST round-1/2 reference** code for an **additional-signatures**
  candidate. LESS is **not standardized** and **not production-audited**. The
  reference implementation is explicitly **not** fully constant-time (see the
  `SIGN_PIVOT_REUSE_LIMIT` comments and `sort.c`: "absolutely not constant
  time"). Treat the wasm artifact as **experimental hardness-diversity**, not a
  drop-in for a standardized signature.
- Compiled verbatim from the official reference — **nothing hand-rolled**. The
  only added C is the ~40-line `less_wasm_glue.c` seam described in (e).
- The `.wasm` artifact itself is produced by the VM (no `wasi-sdk` on this Mac);
  this package ships the recipe + TS wrapper skeleton and the wasm is dropped in
  later at `packages/pca-less-wasm/wasm/less_cat1.wasm`.
