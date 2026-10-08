# @atlasauth/pca-less-wasm

> **EXPERIMENTAL — not standardized, not production-audited.**

A **code-based** signature backend for [`@atlasauth/pca`](../pca): the official
**LESS** reference implementation compiled to WebAssembly.

LESS is a NIST **additional-signatures** candidate (round 1/2). Its security
rests on the **code-equivalence / syndrome-decoding** problem — the genuine
*third* post-quantum hardness family, distinct from:

- **lattices** — ML-DSA (Dilithium), FN-DSA (Falcon), and
- **hashes** — SLH-DSA (SPHINCS+).

Adding it to the PCA post-quantum suite registry buys real cryptographic
diversity: a future break of lattice assumptions does not touch a code-based
leaf signature.

## What this is (and is not)

- **Compiled from the official reference, not hand-rolled.** The crypto core is
  the upstream LESS reference C (https://github.com/less-sig/LESS, public
  domain), compiled verbatim to `wasm32-wasi`. The only added C is a ~40-line
  seam (`less_wasm_glue.c`) that seeds the reference's own SHAKE CSPRNG from
  WASI entropy and exposes flat byte-buffer entry points. No algorithm code is
  modified. See [`BUILD_NOTES.md`](./BUILD_NOTES.md) for the full recon.
- **EXPERIMENTAL / non-default.** LESS is **not standardized** (no final FIPS)
  and **not production-audited**. The reference implementation is explicitly
  **not fully constant-time** for keygen/sign (see the upstream
  `SIGN_PIVOT_REUSE_LIMIT` notes and `sort.c`). Do **not** make this your
  default signature suite. It exists to add hardness diversity as an opt-in.
- **Verification is the intended use.** `verify` / `open` are **deterministic
  and consume no randomness** — exactly the public-key operation the PCA
  verifier performs. Keygen/sign are included for completeness and KATs.

## Parameter set

One **NIST Category 1** set is compiled: **`CATEGORY=252, TARGET=45`** — the
short-signature corner (`q=127, n=252, k=126`). Approximate sizes (the exact
values are read from the wasm at load time via `sizes()`, never hard-coded):

| | bytes (approx) |
|---|---|
| public key | ~95 KB |
| secret key | 32 |
| signature (worst case) | ~1.3 KB |

To build the balanced small-key corner instead (`TARGET=192`, ~14 KB key / ~2.6
KB sig) or the intermediate `TARGET=68`, set `LESS_TARGET` when running the
build script — it is a one-flag change (see `BUILD_NOTES.md §c`).

## The wasm artifact is produced off-box

This Mac has no `wasi-sdk`, so **no `.wasm` ships in this package yet.** The
module is cross-compiled on a Linux VM by the build recipe at
**`~/.pca-vm-state/lessbuild.sh`**:

```bash
# on an x86_64 Linux VM (downloads wasi-sdk-25 into /opt):
~/.pca-vm-state/lessbuild.sh /tmp/less-work /tmp/less-out
# produces /tmp/less-out/less_cat1.wasm + runs a keypair→sign→open KAT
```

Then drop the result in here:

```bash
cp /tmp/less-out/less_cat1.wasm packages/pca-less-wasm/wasm/less_cat1.wasm
```

Until that file exists, every API call throws a `LessError` with this
instruction. The build script also emits `less_kat.mjs`, a Node WASI harness
that runs a full `autoseed → keypair → sign → open` round-trip plus a tamper
rejection check.

## ABI note (differs from `@atlasauth/pca-fndsa-wasm`)

FN-DSA uses an empty-imports, fixed-static-buffer ABI. LESS is a **WASI
reactor**: it imports `wasi_snapshot_preview1` (for `random_get`, which backs
the module's `getentropy` auto-seed) and allocates I/O buffers with the exported
`malloc`/`free`. This package instantiates it via Node's `node:wasi`.

## Usage

```ts
import { sizes, keygen, sign, open, signDetached, verify, VARIANT } from '@atlasauth/pca-less-wasm';

console.log(VARIANT);        // 'less-252-45'
console.log(sizes());        // { publicKey, secretKey, signatureMax, seed }

// keygen auto-seeds from WASI entropy; call seedWith(seed) for deterministic KATs.
const { publicKey, secretKey } = keygen();

const msg = new TextEncoder().encode('proof-carrying authority');

// attached (NIST) signed-message form:
const signedMessage = sign(secretKey, msg);
const { ok, message } = open(publicKey, signedMessage);   // ok === true

// detached form (the PCA verifier's shape):
const signature = signDetached(secretKey, msg);
const valid = verify(publicKey, msg, signature);           // true
```

### API

- `sizes(): LessSizes` — byte lengths read from the wasm.
- `seedFromEntropy()` / `seedWith(seed)` — seed the reference CSPRNG (WASI
  entropy, or an injected seed for determinism). `keygen`/`sign` auto-seed from
  entropy if you have not seeded.
- `keygen(): { publicKey, secretKey }`
- `sign(secretKey, message): Uint8Array` (attached) / `open(publicKey, signedMessage): { ok, message }`
- `signDetached(secretKey, message): Uint8Array` / `verify(publicKey, message, signature): boolean`

## License

The LESS reference implementation is public-domain (see upstream `LICENSE`).
This binding follows the repository's license.
