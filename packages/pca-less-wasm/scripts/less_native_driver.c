/* less_native_driver.c -- native (non-wasm) line-oriented driver around the UNMODIFIED upstream
 * LESS reference NIST wrappers (crypto_sign_keypair / crypto_sign / crypto_sign_open).
 * It exists only to cross-check the wasm build; it contains no cryptography of its own.
 *
 *   gen  : stdin lines "<seedhex> <msghex|->"  -> stdout "<pkhex> <skhex> <smhex> <open_rc>"
 *          The seed is fed to the reference's own SHAKE CSPRNG exactly as the official KAT
 *          generator does (initialize_csprng(&platform_csprng_state, seed, seedlen)); keygen and
 *          sign then draw from that single stream, as in PQCgenKAT_sign.c.
 *   open : stdin lines "<pkhex> <smhex>" -> stdout "<rc> <mlen>"  (raw crypto_sign_open, NO guards)
 *   sweep: one stdin line "<pkhex> <smhex> <mlen>": flips EVERY bit of the signature part
 *          (bytes mlen..smlen-1) one at a time and prints "<byte> <bit>" for each flip that STILL
 *          opens successfully, then "done <flips_tried> <accepted>".
 *   sizes: prints "pk sk sigmax"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "rng.h"
#include "parameters.h"

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t unhex(const char *s, size_t slen, unsigned char *out) {
    size_t n = 0;
    if (slen == 1 && s[0] == '-') return 0;
    for (size_t i = 0; i + 1 < slen; i += 2) out[n++] = (unsigned char)((hexval(s[i]) << 4) | hexval(s[i + 1]));
    return n;
}
static void phex(const unsigned char *b, size_t n) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { putchar(H[b[i] >> 4]); putchar(H[b[i] & 15]); }
}
/* split line into two space-separated tokens */
static int two(char *line, char **a, size_t *al, char **b, size_t *bl) {
    char *sp = strchr(line, ' ');
    if (!sp) return 0;
    *a = line; *al = (size_t)(sp - line);
    *b = sp + 1;
    size_t n = strlen(*b);
    while (n && ((*b)[n - 1] == '\n' || (*b)[n - 1] == '\r')) n--;
    *bl = n;
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "sizes")) {
        printf("%zu %zu %zu\n", (size_t)CRYPTO_PUBLICKEYBYTES, (size_t)CRYPTO_SECRETKEYBYTES, (size_t)CRYPTO_BYTES);
        return 0;
    }
    char *line = NULL; size_t cap = 0; ssize_t got;
    setvbuf(stdout, NULL, _IONBF, 0);
    int gen = !strcmp(argv[1], "gen");
    int sweep = !strcmp(argv[1], "sweep");
    if (!gen && !sweep && strcmp(argv[1], "open")) return 2;
    while ((got = getline(&line, &cap, stdin)) > 0) {
        char *a, *b; size_t al, bl;
        if (!two(line, &a, &al, &b, &bl)) return 3;
        if (sweep) {
            /* line is "<pkhex> <smhex> <mlen>" : b holds "<smhex> <mlen>" */
            char *sp = strchr(b, ' ');
            if (!sp) return 3;
            size_t smhexlen = (size_t)(sp - b);
            size_t mlen_in = (size_t)strtoull(sp + 1, NULL, 10);
            unsigned char *pk = malloc(al / 2 + 1), *sm = malloc(smhexlen / 2 + 1), *m = malloc(smhexlen / 2 + 1);
            size_t pl = unhex(a, al, pk), sl = unhex(b, smhexlen, sm);
            if (pl != CRYPTO_PUBLICKEYBYTES) return 4;
            size_t tried = 0, acc = 0, unsafe = 0;
            const char *from_s = getenv("LESS_SWEEP_FROM");
            size_t from = from_s ? (size_t)strtoull(from_s, NULL, 10) : 0;
            for (size_t i = mlen_in + from; i < sl; i++) for (int bit = 0; bit < 8; bit++) {
                unsigned long long ml = 0;
                sm[i] ^= (unsigned char)(1u << bit);
                /* The raw reference crypto_sign_open has no smlen >= sig_len check (UPSTREAM DEFECT:
                 * it underflows mlen and memcpy's ~2^64 bytes). Flips of the trailing leaf-count
                 * byte can trigger it, so skip (and count) those instead of crashing the sweep. */
                { size_t lv = sm[sl - 1];
                  if (lv > MAX_PUBLISHED_SEEDS || sl < LESS_SIGNATURE_SIZE(lv)) { sm[i] ^= (unsigned char)(1u << bit); unsafe++; continue; } }
                if (getenv("LESS_SWEEP_TRACE")) fprintf(stderr, "T %zu %d\n", i - mlen_in, bit);
                int rc = crypto_sign_open(m, &ml, sm, sl, pk);
                sm[i] ^= (unsigned char)(1u << bit);
                tried++;
                if (rc == 0) { acc++; printf("%zu %d\n", i - mlen_in, bit); }
            }
            printf("done tried=%zu accepted=%zu skipped_unsafe=%zu\n", tried, acc, unsafe);
            free(pk); free(sm); free(m);
            continue;
        }
        if (gen) {
            unsigned char seed[256], *msg = malloc(bl / 2 + 1);
            size_t sl = unhex(a, al, seed), ml = unhex(b, bl, msg);
            unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES), *sk = malloc(CRYPTO_SECRETKEYBYTES);
            unsigned char *sm = malloc(ml + CRYPTO_BYTES), *m1 = malloc(ml + CRYPTO_BYTES);
            unsigned long long smlen = 0, mlen1 = 0;
            initialize_csprng(&platform_csprng_state, seed, (uint32_t)sl);
            crypto_sign_keypair(pk, sk);
            crypto_sign(sm, &smlen, msg, ml, sk);
            int rc = crypto_sign_open(m1, &mlen1, sm, smlen, pk);
            if (rc == 0 && (mlen1 != ml || memcmp(m1, msg, ml))) rc = 99;
            phex(pk, CRYPTO_PUBLICKEYBYTES); putchar(' ');
            phex(sk, CRYPTO_SECRETKEYBYTES); putchar(' ');
            phex(sm, smlen); printf(" %d\n", rc);
            free(msg); free(pk); free(sk); free(sm); free(m1);
        } else {
            /* LESS_PAD=1: allocate the signed-message buffer with CRYPTO_BYTES of trailing zeros, the
             * mitigation the wasm wrapper applies for upstream defect #3 (RebuildGGM over-read). */
            size_t pad = getenv("LESS_PAD") ? (size_t)CRYPTO_BYTES : 0;
            unsigned char *pk = malloc(al / 2 + 1), *sm = calloc(bl / 2 + 1 + pad, 1), *m = malloc(bl / 2 + 1);
            size_t pl = unhex(a, al, pk), sl = unhex(b, bl, sm);
            unsigned long long mlen = 0;
            if (pl != CRYPTO_PUBLICKEYBYTES) { printf("badpk 0\n"); }
            else { int rc = crypto_sign_open(m, &mlen, sm, sl, pk); printf("%d %llu\n", rc, mlen); }
            free(pk); free(sm); free(m);
        }
        fflush(stdout);
    }
    free(line);
    return 0;
}
