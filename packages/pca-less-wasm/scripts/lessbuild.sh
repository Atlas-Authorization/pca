#!/usr/bin/env bash
# lessbuild.sh — VM-side cross-compile of the LESS code-based signature
# (NIST additional-signatures candidate; code-equivalence / syndrome-decoding
# hardness) reference implementation to a wasm32-wasi reactor module.
#
# Produced by RECON in packages/pca-less-wasm/BUILD_NOTES.md. Run this on a
# Linux VM (x86_64) that is allowed to download wasi-sdk and compile. It does
# NOT compile on the authoring Mac (no wasi-sdk there).
#
# Usage:   lessbuild.sh <work_dir> <out_dir>
#   <work_dir>  scratch dir for the wasi-sdk install marker + LESS clone + objs
#   <out_dir>   where the .wasm, the KAT harness and logs are written
#
# Env overrides (optional):
#   LESS_CATEGORY   default 252  (NIST Category 1). Others: 400 (cat3), 548 (cat5)
#   LESS_TARGET     default 45   (short-sig corner for cat1). Others: 68, 192
#   WASI_SDK_VER    default 25   (wasi-sdk major release tag)
#   LESS_REPO       default https://github.com/less-sig/LESS
#   LESS_REPO_ALT   fallback   https://github.com/paolo-santini/LESS_project
#
# Everything is logged to <out_dir>/build.log and echoed.
set -euo pipefail

# ------------------------------------------------------------------ args/env
WORK="${1:?usage: lessbuild.sh <work_dir> <out_dir>}"
OUT="${2:?usage: lessbuild.sh <work_dir> <out_dir>}"
LESS_CATEGORY="${LESS_CATEGORY:-252}"
LESS_TARGET="${LESS_TARGET:-45}"
WASI_SDK_VER="${WASI_SDK_VER:-25}"
LESS_REPO="${LESS_REPO:-https://github.com/less-sig/LESS}"
LESS_REPO_ALT="${LESS_REPO_ALT:-https://github.com/paolo-santini/LESS_project}"

mkdir -p "$WORK" "$OUT"
WORK="$(cd "$WORK" && pwd)"
OUT="$(cd "$OUT" && pwd)"
LOG="$OUT/build.log"
: > "$LOG"

log() { echo "[lessbuild] $*" | tee -a "$LOG" ; }
run() { echo "+ $*" | tee -a "$LOG" ; "$@" 2>&1 | tee -a "$LOG" ; }

log "config: CATEGORY=$LESS_CATEGORY TARGET=$LESS_TARGET wasi-sdk=$WASI_SDK_VER"
log "work=$WORK out=$OUT"

# ------------------------------------------------------------ 1. wasi-sdk 25
# Download the x86_64-linux tarball to /opt and point at its clang + sysroot.
WASI_SDK_DIR="/opt/wasi-sdk-${WASI_SDK_VER}.0-x86_64-linux"
WASI_SDK_LINK="/opt/wasi-sdk"
if [ ! -x "${WASI_SDK_LINK}/bin/clang" ]; then
  log "installing wasi-sdk-${WASI_SDK_VER} into /opt ..."
  TARBALL="wasi-sdk-${WASI_SDK_VER}.0-x86_64-linux.tar.gz"
  URL="https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VER}/${TARBALL}"
  # own empty dir for the untrusted download
  DL="$WORK/wasi-sdk-dl"
  mkdir -p "$DL"
  run curl -fL --retry 3 -o "$DL/$TARBALL" "$URL"
  # requires write access to /opt (run as root or sudo). Fall back to sudo.
  if [ -w /opt ]; then
    run tar -xzf "$DL/$TARBALL" -C /opt
    ln -sfn "$WASI_SDK_DIR" "$WASI_SDK_LINK"
  else
    run sudo tar -xzf "$DL/$TARBALL" -C /opt
    sudo ln -sfn "$WASI_SDK_DIR" "$WASI_SDK_LINK"
  fi
else
  log "wasi-sdk already present at $WASI_SDK_LINK"
fi

CC="${WASI_SDK_LINK}/bin/clang"
SYSROOT="${WASI_SDK_LINK}/share/wasi-sysroot"
[ -x "$CC" ] || { log "FATAL: $CC not executable"; exit 1; }
[ -d "$SYSROOT" ] || { log "FATAL: sysroot $SYSROOT missing"; exit 1; }
run "$CC" --version

# ----------------------------------------------------------------- 2. clone
SRC="$WORK/LESS"
# PINNED upstream commit: the one whose official KATs the shipped wasm reproduces 100/100 (see README, 'Evidence'). A build at any
# other commit is a DIFFERENT artifact and must not be shipped under this package; the script refuses to build one.
LESS_PIN="${LESS_PIN:-6383430b9123e69d2ef6a6224f930972e3225610}"
if [ ! -d "$SRC/Reference_Implementation" ]; then
  rm -rf "$SRC"
  mkdir -p "$SRC"
  fetch_pin() {
    ( cd "$SRC" && git init -q && git remote add origin "$1" && git fetch -q --depth 1 origin "$LESS_PIN" && git checkout -q FETCH_HEAD )
  }
  if ! fetch_pin "$LESS_REPO" 2>>"$LOG"; then
    log "primary fetch of $LESS_PIN failed, trying fallback $LESS_REPO_ALT"
    rm -rf "$SRC"; mkdir -p "$SRC"
    fetch_pin "$LESS_REPO_ALT" || { log "FATAL: could not fetch pinned commit $LESS_PIN"; exit 1; }
  fi
fi
GOT="$(cd "$SRC" && git rev-parse HEAD 2>/dev/null || true)"
[ "$GOT" = "$LESS_PIN" ] || { log "FATAL: LESS source is at '$GOT', expected pinned $LESS_PIN"; exit 1; }
log "LESS source pinned at $GOT"
REF="$SRC/Reference_Implementation"
INC="$REF/include"
LIB="$REF/lib"
[ -f "$INC/api.h" ] || { log "FATAL: $INC/api.h not found — repo layout changed"; exit 1; }
log "LESS reference at $REF"

# ---------------------------------------------- 3. getentropy randomness glue
# The reference funnels ALL randomness through a single global SHAKE CSPRNG
# (rng.c: platform_csprng_state, seeded by init_randombytes). We add a ~40-line
# seam ONLY: autoseed via WASI getentropy (-> host random_get), inject-seed for
# KAT/determinism, and flat-buffer exports bound to the NIST wrappers + size
# queries. No LESS source is edited.
GLUE="$WORK/less_wasm_glue.c"
cat > "$GLUE" <<'CEOF'
/* less_wasm_glue.c — wasm seam for the LESS reference (NOT part of upstream).
 * Seeds the reference's global SHAKE CSPRNG and exposes flat-buffer entry
 * points + exact size queries. See packages/pca-less-wasm/BUILD_NOTES.md (e). */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>      /* wasi-libc */
#include <sys/random.h>  /* getentropy (wasi-libc declares it HERE, not unistd.h) */
#include "api.h"         /* CRYPTO_* sizes + crypto_sign_* wrappers */
#include "LESS.h"
#include "rng.h"         /* init_randombytes / platform_csprng_state */

/* --- exact sizes for the compiled parameter set (read by the TS wrapper) --- */
size_t less_public_key_bytes(void)    { return CRYPTO_PUBLICKEYBYTES; }
size_t less_secret_key_bytes(void)    { return CRYPTO_SECRETKEYBYTES; }
size_t less_signature_max_bytes(void) { return CRYPTO_BYTES; }        /* worst-case sig */
size_t less_seed_bytes(void)          { return CRYPTO_RANDOMBYTES; }  /* = SEED_LENGTH_BYTES */

/* --- randomness seam ------------------------------------------------------- */
/* Seed the global CSPRNG from WASI entropy. Returns 0 ok, -1 on getentropy err.
 * getentropy is capped at 256 bytes per call; our seed is 2*SEED_LENGTH_BYTES
 * (<=64), well under the cap. */
int less_autoseed(void) {
    uint8_t s[PRIVATE_KEY_SEED_LENGTH_BYTES]; /* 2*SEED_LENGTH_BYTES */
    if (getentropy(s, sizeof s) != 0) return -1;
    init_randombytes(s, sizeof s);
    return 0;
}
/* Inject a caller-provided seed (deterministic / KAT / BYO-RNG from JS). */
void less_seed(const uint8_t *seed, size_t seed_len) {
    init_randombytes(seed, (uint32_t)seed_len);
}

/* --- scheme entry points (NIST flat-buffer wrappers; attached signatures) -- */
/* keypair: pk >= less_public_key_bytes(), sk >= less_secret_key_bytes(). 0 ok.
 * REQUIRES a prior less_autoseed()/less_seed(). */
int less_keypair(uint8_t *pk, uint8_t *sk) {
    return crypto_sign_keypair(pk, sk);
}
/* sign (attached): sm >= mlen + less_signature_max_bytes(); *smlen set. 0 ok.
 * REQUIRES a prior less_autoseed()/less_seed(). */
int less_sign(uint8_t *sm, unsigned long long *smlen,
              const uint8_t *m, unsigned long long mlen,
              const uint8_t *sk) {
    return crypto_sign(sm, smlen, m, mlen, sk);
}
/* open/verify (attached): recovers m (>= smlen) and *mlen. 0 ok, nonzero fail.
 * No seeding required — verify consumes no randomness. */
int less_open(uint8_t *m, unsigned long long *mlen,
              const uint8_t *sm, unsigned long long smlen,
              const uint8_t *pk) {
    return crypto_sign_open(m, mlen, sm, smlen, pk);
}
CEOF
log "wrote glue seam -> $GLUE"

# ------------------------------------------------------------- 4. compile+link
CORE_SRCS=(
  "$LIB/codes.c" "$LIB/fips202.c" "$LIB/keccakf1600.c" "$LIB/LESS.c"
  "$LIB/monomial.c" "$LIB/rng.c" "$LIB/seedtree.c" "$LIB/sign.c"
  "$LIB/utils.c" "$LIB/sort.c" "$LIB/canonical.c" "$LIB/transpose.c"
)
for f in "${CORE_SRCS[@]}"; do
  [ -f "$f" ] || { log "FATAL: missing core source $f"; exit 1; }
done

CFLAGS=(
  --target=wasm32-wasi
  --sysroot="$SYSROOT"
  -O2 -std=c99 -fno-exceptions
  -DCATEGORY="$LESS_CATEGORY" -DTARGET="$LESS_TARGET"
  # NOTE: deliberately NO -mavx2/-march=native and NO -DUSE_AVX2/AVX512/NEON/
  # LESS_USE_CUSTOM_HISTOGRAM — those select the x86 paths in sort.c and the
  # 32-byte padding branch in parameters.h. Undefined => portable scalar C.
  -I "$INC"
  -Wno-unused-function -Wno-unused-parameter
)

WASM="$OUT/less_cat${LESS_CATEGORY}_${LESS_TARGET}.wasm"
# Canonical name the TS wrapper looks for (symlink/copy for cat1 default):
WASM_CANON="$OUT/less_cat1.wasm"

EXPORTS=(
  less_autoseed less_seed less_keypair less_sign less_open
  less_public_key_bytes less_secret_key_bytes less_signature_max_bytes
  less_seed_bytes malloc free
)
LDFLAGS=( -mexec-model=reactor -Wl,-z,stack-size=8388608 )
for e in "${EXPORTS[@]}"; do LDFLAGS+=( "-Wl,--export=$e" ); done

log "compiling + linking -> $WASM"
run "$CC" "${CFLAGS[@]}" "${LDFLAGS[@]}" \
    "${CORE_SRCS[@]}" "$GLUE" \
    -o "$WASM"

[ -f "$WASM" ] || { log "FATAL: wasm not produced"; exit 1; }
cp -f "$WASM" "$WASM_CANON"
log "wasm written: $WASM ($(wc -c < "$WASM") bytes)"
log "canonical copy: $WASM_CANON"

# --------------------------------------------------- 5. KAT round-trip (Node)
# Node has a built-in WASI + WebAssembly; cleanest way to drive a reactor module
# with pointer buffers. Harness is emitted regardless; run only if node exists.
KAT="$OUT/less_kat.mjs"
cat > "$KAT" <<'JEOF'
// less_kat.mjs — keypair -> sign -> open round-trip KAT for the LESS wasm.
// Usage: node less_kat.mjs <path-to.wasm>
import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';

const wasmPath = process.argv[2];
if (!wasmPath) { console.error('usage: node less_kat.mjs <wasm>'); process.exit(2); }

const wasi = new WASI({ version: 'preview1', args: [], env: {},
  // random_get is provided by the runtime; getentropy in the module uses it.
});
const bytes = await readFile(wasmPath);
const module = await WebAssembly.compile(bytes);
const instance = await WebAssembly.instantiate(module, {
  wasi_snapshot_preview1: wasi.wasiImport,
});
wasi.initialize(instance); // reactor: runs _initialize

const ex = instance.exports;
const mem = ex.memory;
const malloc = (n) => { const p = ex.malloc(n); if (!p) throw new Error('oom'); return p; };
const free = (p) => ex.free(p);
const u8 = () => new Uint8Array(mem.buffer);
const dv = () => new DataView(mem.buffer);

const PK = Number(ex.less_public_key_bytes());
const SK = Number(ex.less_secret_key_bytes());
const SIGMAX = Number(ex.less_signature_max_bytes());
const SEED = Number(ex.less_seed_bytes());
console.log(`sizes: pk=${PK} sk=${SK} sigmax=${SIGMAX} seed=${SEED}`);

// deterministic seed for a reproducible KAT
const seedLen = 2 * SEED;
const pSeed = malloc(seedLen);
for (let i = 0; i < seedLen; i++) u8()[pSeed + i] = (i * 7 + 1) & 0xff;
ex.less_seed(pSeed, seedLen);

const pPk = malloc(PK), pSk = malloc(SK);
let rc = ex.less_keypair(pPk, pSk);
if (rc !== 0) { console.error('FAIL keypair rc=' + rc); process.exit(1); }

const msg = new TextEncoder().encode('LESS wasm KAT: proof-carrying authority');
const pMsg = malloc(msg.length);
u8().set(msg, pMsg);
const pSm = malloc(msg.length + SIGMAX);
const pSmlen = malloc(8);
rc = ex.less_sign(pSm, pSmlen, pMsg, BigInt(msg.length), pSk);
if (rc !== 0) { console.error('FAIL sign rc=' + rc); process.exit(1); }
const smlen = Number(dv().getBigUint64(pSmlen, true));
console.log(`signed: smlen=${smlen} (sig=${smlen - msg.length} bytes)`);

// verify / open
const pOut = malloc(smlen);
const pMlen = malloc(8);
rc = ex.less_open(pOut, pMlen, pSm, BigInt(smlen), pPk);
if (rc !== 0) { console.error('FAIL open rc=' + rc); process.exit(1); }
const mlen = Number(dv().getBigUint64(pMlen, true));
const out = u8().slice(pOut, pOut + mlen);
const ok = mlen === msg.length && Buffer.compare(Buffer.from(out), Buffer.from(msg)) === 0;
if (!ok) { console.error('FAIL message mismatch'); process.exit(1); }

// negative test: flip a signature byte -> open must reject
u8()[pSm + msg.length] ^= 0x01;
const rcBad = ex.less_open(pOut, pMlen, pSm, BigInt(smlen), pPk);
if (rcBad === 0) { console.error('FAIL tamper accepted'); process.exit(1); }

console.log('KAT PASS: keypair+sign+open round-trip ok; tamper rejected');
JEOF
log "wrote KAT harness -> $KAT"

if command -v node >/dev/null 2>&1; then
  log "running KAT with node $(node --version)"
  if run node "$KAT" "$WASM_CANON"; then
    log "KAT: PASS"
  else
    log "KAT: FAILED (see log). wasm still emitted at $WASM_CANON"
    exit 1
  fi
else
  log "node not found — skipping KAT run. Run later: node $KAT $WASM_CANON"
fi

log "DONE. Deliverables in $OUT:"
log "  - $(basename "$WASM")   (and less_cat1.wasm)"
log "  - less_kat.mjs          (round-trip KAT harness)"
log "  - build.log"
log "Copy less_cat1.wasm into packages/pca-less-wasm/wasm/less_cat1.wasm"
