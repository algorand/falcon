#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "falcon.h"
#include "deterministic.h"
#include "test_deterministic_kat.h"

// enable in order to generate KATs (pipe output to test_deterministic_kat.h)
// #define GENERATE_KATS 1

// Copied from test_falcon.c
static size_t
hextobin(uint8_t *buf, size_t max_len, const char *src)
{
	size_t u;
	int acc, z;

	u = 0;
	acc = 0;
	z = 0;
	for (;;) {
		int c;

		c = *src ++;
		if (c == 0) {
			if (z) {
				fprintf(stderr, "Lone hex nibble\n");
				exit(EXIT_FAILURE);
			}
			return u;
		}
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else if (c >= 'A' && c <= 'F') {
			c -= 'A' - 10;
		} else if (c >= 'a' && c <= 'f') {
			c -= 'a' - 10;
		} else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			continue;
		} else {
			fprintf(stderr, "Not an hex digit: U+%04X\n",
				(unsigned)c);
			exit(EXIT_FAILURE);
		}
		if (z) {
			if (u >= max_len) {
				fprintf(stderr,
					"Hex string too long for buffer\n");
				exit(EXIT_FAILURE);
			}
			buf[u ++] = (unsigned char)((acc << 4) + c);
		} else {
			acc = c;
		}
		z = !z;
	}
}

void test_inner(size_t data_len) {
	uint8_t pubkey[FALCON_DET1024_PUBKEY_SIZE];
	uint8_t privkey[FALCON_DET1024_PRIVKEY_SIZE];
	uint8_t sig[FALCON_DET1024_SIG_SIZE];
	uint8_t expected_sig[FALCON_DET1024_SIG_SIZE];
	uint8_t data[data_len];

	memset(privkey, 0, FALCON_DET1024_PRIVKEY_SIZE);
	memset(pubkey, 0, FALCON_DET1024_PUBKEY_SIZE);

	shake256_context rng;
	shake256_init_prng_from_seed(&rng, "seed", 4);
	shake256_extract(&rng, data, data_len);

	int r = falcon_det1024_keygen(&rng, privkey, pubkey);
	if (r != 0) {
		fprintf(stderr, "keygen failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

	memset(sig, 0, FALCON_DET1024_SIG_SIZE);
	r = falcon_det1024_sign(sig, privkey, data, data_len);
	if (r != 0) {
		fprintf(stderr, "sign_det1024 failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_verify(sig, pubkey, data, data_len);
	if (r != 0) {
		fprintf(stderr, "verify failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

#ifdef GENERATE_KATS            /* print the KAT */
	printf("\t\"");
	for (unsigned int i = 0; i < FALCON_DET1024_SIG_SIZE; i++) {
		printf("%02x", sig[i]);
	}
	printf("\",\n");
#else  /* compare to the KAT */
	hextobin(expected_sig, FALCON_DET1024_SIG_SIZE, FALCON_DET1024_KAT[data_len]);
	if (memcmp(sig, expected_sig, FALCON_DET1024_SIG_SIZE) != 0) {
		fprintf(stderr, "sign_det1024 (data_len=%zu) does not match KAT\n", data_len);
		exit(EXIT_FAILURE);
	}
#endif
}

int main() {
#ifdef GENERATE_KATS
	printf("\nstatic const char *const FALCON_DET1024_KAT[] = {\n");
#endif

	for (int i = 0; i < 512; i++) {
		test_inner(i);
#ifndef GENERATE_KATS
		printf(".");
		fflush(stdout);
#endif
	}

#ifdef GENERATE_KATS
	printf("};\n");
#else
	printf("\nAll known-answer tests (KATs) pass.\n");
#endif
}
