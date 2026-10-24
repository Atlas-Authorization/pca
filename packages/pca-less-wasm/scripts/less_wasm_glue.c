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
