/* Minimal CLI over the independent C FN-DSA implementation (pornin/c-fn-dsa) used to cross-check
   the wasm backend. Hex in / hex out. Parameters: raw message, empty domain context (DOMAIN_NONE). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "fndsa.h"

static size_t unhex(const char *s, uint8_t *out, size_t max) {
	size_t n = strlen(s) / 2;
	if (n > max) { fprintf(stderr, "too long\n"); exit(2); }
	for (size_t i = 0; i < n; i++) { unsigned v; sscanf(s + 2 * i, "%2x", &v); out[i] = (uint8_t)v; }
	return n;
}
static void hex(const uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", b[i]); }

int main(int argc, char **argv) {
	static uint8_t a[8192], b[8192], c[8192], s[8192];
	if (argc >= 4 && !strcmp(argv[1], "keygen")) {
		unsigned logn = (unsigned)atoi(argv[2]);
		size_t sl = unhex(argv[3], s, sizeof s);
		fndsa_keygen_seeded(logn, s, sl, a, b);
		hex(a, FNDSA_SIGN_KEY_SIZE(logn)); printf(" "); hex(b, FNDSA_VRFY_KEY_SIZE(logn)); printf("\n");
		return 0;
	}
	if (argc >= 5 && !strcmp(argv[1], "sign")) { /* sign sk msg seed */
		size_t kl = unhex(argv[2], a, sizeof a), ml = unhex(argv[3], b, sizeof b), sl = unhex(argv[4], s, sizeof s);
		size_t n = fndsa_sign_seeded(a, kl, NULL, 0, FNDSA_HASH_ID_RAW, b, ml, s, sl, c, sizeof c);
		if (!n) { fprintf(stderr, "sign failed\n"); return 1; }
		hex(c, n); printf("\n");
		return 0;
	}
	if (argc >= 5 && !strcmp(argv[1], "verify")) { /* verify vk msg sig */
		size_t kl = unhex(argv[2], a, sizeof a), ml = unhex(argv[3], b, sizeof b), gl = unhex(argv[4], c, sizeof c);
		printf("%d\n", fndsa_verify(c, gl, a, kl, NULL, 0, FNDSA_HASH_ID_RAW, b, ml));
		return 0;
	}
	fprintf(stderr, "usage\n"); return 2;
}
