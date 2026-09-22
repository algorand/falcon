// Cross-checks each deterministic Falcon family against an independent
// reimplementation of its keygen and sign_compressed built only on the
// generic falcon.h API (shake256_* and falcon_sign_dyn_finish with an
// explicit logn). There are no external KATs for deterministic Falcon, so
// this guards against the det sources and their self-generated KATs
// agreeing on a mistake: keygen, the det-RNG seeding, the salt layout and
// the salted-to-unsalted format transform are all rebuilt here from the
// spec rather than from deterministic*.c.
//
// The inputs are the same seeded keys and messages the KAT runners use, so
// the reference path is also checked against every committed KAT vector.
//
// deterministic.h is included only for the entry points under test; the
// reference path below uses nothing from it.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../falcon.h"
#include "../deterministic.h"
#include "test_deterministic1024_kat.h"
#include "test_deterministic512_kat.h"

// Buffers are sized for the largest supported family.
#define MAX_LOGN 10

// Matches NUM_KATS in the KAT runners.
#define NUM_MSGS 512

typedef int (*det_keygen_fn)(shake256_context *rng, void *privkey, void *pubkey);
typedef int (*det_sign_compressed_fn)(void *sig, size_t *sig_len,
	const void *privkey, const void *data, size_t data_len);

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
			fprintf(stderr, "Not a hex digit: U+%04X\n",
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

static void
fail(unsigned logn, size_t data_len, const char *what, int r)
{
	fprintf(stderr, "logn=%u data_len=%zu: %s (%d)\n", logn, data_len, what, r);
	exit(EXIT_FAILURE);
}

// The 40-byte salt: version, logn, then "FALCON_DET" zero-padded to 38 bytes.
static void
ref_salt(uint8_t salt[40], unsigned logn, uint8_t version)
{
	memset(salt, 0, 40);
	salt[0] = version;
	salt[1] = (uint8_t)logn;
	memcpy(salt + 2, "FALCON_DET", 10);
}

static int
ref_sign_compressed(unsigned logn, void *sig, size_t *sig_len,
	const void *privkey, const void *data, size_t data_len)
{
	size_t privkey_len = FALCON_PRIVKEY_SIZE(logn);
	uint8_t logn_byte = (uint8_t)logn;
	uint8_t salt[40];
	shake256_context detrng, hd;
	uint8_t tmp[FALCON_TMPSIZE_SIGNDYN(MAX_LOGN)];
	uint8_t salted[FALCON_SIG_COMPRESSED_MAXSIZE(MAX_LOGN)];
	size_t salted_len = FALCON_SIG_COMPRESSED_MAXSIZE(logn);
	uint8_t *out = sig;
	int r;

	shake256_init(&detrng);
	shake256_inject(&detrng, &logn_byte, 1);
	shake256_inject(&detrng, privkey, privkey_len);
	shake256_inject(&detrng, data, data_len);
	shake256_flip(&detrng);

	ref_salt(salt, logn, 0);
	shake256_init(&hd);
	shake256_inject(&hd, salt, 40);
	shake256_inject(&hd, data, data_len);

	r = falcon_sign_dyn_finish(&detrng, salted, &salted_len,
		FALCON_SIG_COMPRESSED, privkey, privkey_len,
		&hd, salt, tmp, FALCON_TMPSIZE_SIGNDYN(logn));
	if (r != 0) {
		return r;
	}

	// A standard compressed signature is header || 40-byte nonce || s2.
	// The deterministic form sets the header's MSB and replaces the nonce
	// with the one-byte salt version.
	if (salted[0] != (0x30 | logn)) {
		return FALCON_ERR_INTERNAL;
	}
	out[0] = salted[0] | 0x80;
	out[1] = 0;
	memcpy(out + 2, salted + 41, salted_len - 41);
	*sig_len = salted_len - 39;
	return 0;
}

static void
test_det_generic(unsigned logn, det_keygen_fn det_keygen,
	det_sign_compressed_fn det_sign_compressed, const char *const *kats)
{
	uint8_t tmpkg[FALCON_TMPSIZE_KEYGEN(MAX_LOGN)];
	uint8_t ref_priv[FALCON_PRIVKEY_SIZE(MAX_LOGN)];
	uint8_t ref_pub[FALCON_PUBKEY_SIZE(MAX_LOGN)];
	uint8_t det_priv[FALCON_PRIVKEY_SIZE(MAX_LOGN)];
	uint8_t det_pub[FALCON_PUBKEY_SIZE(MAX_LOGN)];
	uint8_t ref_sig[FALCON_SIG_COMPRESSED_MAXSIZE(MAX_LOGN)];
	uint8_t det_sig[FALCON_SIG_COMPRESSED_MAXSIZE(MAX_LOGN)];
	uint8_t kat_sig[FALCON_SIG_COMPRESSED_MAXSIZE(MAX_LOGN)];
	uint8_t data[NUM_MSGS];
	size_t privkey_len = FALCON_PRIVKEY_SIZE(logn);
	size_t pubkey_len = FALCON_PUBKEY_SIZE(logn);
	size_t data_len;

	if (logn > MAX_LOGN) {
		fail(logn, 0, "logn exceeds MAX_LOGN", 0);
	}

	printf("Deterministic logn=%u vs generic API: ", logn);
	fflush(stdout);

	for (data_len = 0; data_len < NUM_MSGS; data_len++) {
		shake256_context rng;
		char seed[16];
		size_t ref_len, det_len, kat_len;
		int r;

		// Both keygens draw from identically seeded RNGs, so any
		// divergence in how the family wraps falcon_keygen_make shows up
		// as a key mismatch.
		snprintf(seed, sizeof seed, "key-%04zu", data_len);
		shake256_init_prng_from_seed(&rng, seed, strlen(seed));
		r = falcon_keygen_make(&rng, logn, ref_priv, privkey_len,
			ref_pub, pubkey_len, tmpkg, FALCON_TMPSIZE_KEYGEN(logn));
		if (r != 0) {
			fail(logn, data_len, "falcon_keygen_make failed", r);
		}
		shake256_init_prng_from_seed(&rng, seed, strlen(seed));
		r = det_keygen(&rng, det_priv, det_pub);
		if (r != 0) {
			fail(logn, data_len, "det keygen failed", r);
		}
		if (memcmp(ref_priv, det_priv, privkey_len) != 0
			|| memcmp(ref_pub, det_pub, pubkey_len) != 0)
		{
			fail(logn, data_len, "det keygen differs from falcon_keygen_make", 0);
		}

		snprintf(seed, sizeof seed, "msg-%04zu", data_len);
		shake256_init_prng_from_seed(&rng, seed, strlen(seed));
		shake256_extract(&rng, data, data_len);

		r = ref_sign_compressed(logn, ref_sig, &ref_len,
			ref_priv, data, data_len);
		if (r != 0) {
			fail(logn, data_len, "reference sign failed", r);
		}
		r = det_sign_compressed(det_sig, &det_len,
			det_priv, data, data_len);
		if (r != 0) {
			fail(logn, data_len, "det sign_compressed failed", r);
		}
		if (ref_len != det_len) {
			fprintf(stderr, "logn=%u data_len=%zu: signature length %zu, reference %zu\n",
				logn, data_len, det_len, ref_len);
			exit(EXIT_FAILURE);
		}
		if (memcmp(ref_sig, det_sig, ref_len) != 0) {
			fail(logn, data_len, "det signature differs from reference", 0);
		}
		kat_len = hextobin(kat_sig, sizeof kat_sig, kats[data_len]);
		if (kat_len != ref_len || memcmp(kat_sig, ref_sig, ref_len) != 0) {
			fail(logn, data_len, "reference signature differs from KAT", 0);
		}

		if (data_len % 8 == 7) {
			printf(".");
			fflush(stdout);
		}
	}
	printf(" done.\n");
}

#define NUM_CROSS 16

// Relabels a signature from one family with the other family's compressed
// header so it passes the verifier's header check, then requires the verifier
// to reject it. Each signature is offered under both the verifier's own key
// and the actual signer's key (copied into a buffer of the verifier's key
// size, so nothing reads out of bounds).
//
// A det1024 signature is always longer than det512 allows, so det512 rejects
// it on length alone; it is also offered truncated to det512's maximum length
// so the verifier gets as far as decoding the body.
static void
test_cross_family(void)
{
	uint8_t tmpkg[FALCON_TMPSIZE_KEYGEN(10)];
	uint8_t priv512[FALCON_DET512_PRIVKEY_SIZE];
	uint8_t pub512[FALCON_DET512_PUBKEY_SIZE];
	uint8_t priv1024[FALCON_DET1024_PRIVKEY_SIZE];
	uint8_t pub1024[FALCON_DET1024_PUBKEY_SIZE];
	uint8_t pub512_as_1024[FALCON_DET1024_PUBKEY_SIZE];
	uint8_t sig512[FALCON_DET512_SIG_COMPRESSED_MAXSIZE];
	uint8_t sig1024[FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
	uint8_t data[NUM_CROSS];
	size_t data_len;

	printf("Cross-family verification is rejected: ");
	fflush(stdout);

	for (data_len = 0; data_len < NUM_CROSS; data_len++) {
		shake256_context rng;
		char seed[16];
		size_t len512, len1024;
		int r;

		snprintf(seed, sizeof seed, "xkey-%04zu", data_len);
		shake256_init_prng_from_seed(&rng, seed, strlen(seed));
		r = falcon_keygen_make(&rng, 9, priv512, sizeof priv512,
			pub512, sizeof pub512, tmpkg, FALCON_TMPSIZE_KEYGEN(9));
		if (r != 0) {
			fail(9, data_len, "falcon_keygen_make failed", r);
		}
		r = falcon_keygen_make(&rng, 10, priv1024, sizeof priv1024,
			pub1024, sizeof pub1024, tmpkg, FALCON_TMPSIZE_KEYGEN(10));
		if (r != 0) {
			fail(10, data_len, "falcon_keygen_make failed", r);
		}
		memset(pub512_as_1024, 0, sizeof pub512_as_1024);
		memcpy(pub512_as_1024, pub512, sizeof pub512);

		snprintf(seed, sizeof seed, "xmsg-%04zu", data_len);
		shake256_init_prng_from_seed(&rng, seed, strlen(seed));
		shake256_extract(&rng, data, data_len);

		r = falcon_det512_sign_compressed(sig512, &len512, priv512, data, data_len);
		if (r != 0) {
			fail(9, data_len, "det512 sign_compressed failed", r);
		}
		r = falcon_det1024_sign_compressed(sig1024, &len1024, priv1024, data, data_len);
		if (r != 0) {
			fail(10, data_len, "det1024 sign_compressed failed", r);
		}

		// Unmodified, each signature verifies in its own family, so the
		// rejections below are due to the relabeling alone.
		if (falcon_det512_verify_compressed(sig512, len512, pub512, data, data_len) != 0) {
			fail(9, data_len, "det512 signature does not verify", 0);
		}
		if (falcon_det1024_verify_compressed(sig1024, len1024, pub1024, data, data_len) != 0) {
			fail(10, data_len, "det1024 signature does not verify", 0);
		}

		sig512[0] = FALCON_DET1024_SIG_COMPRESSED_HEADER;
		if (falcon_det1024_verify_compressed(sig512, len512, pub1024, data, data_len) == 0) {
			fail(9, data_len, "relabeled det512 signature verified under det1024 key", 0);
		}
		if (falcon_det1024_verify_compressed(sig512, len512, pub512_as_1024, data, data_len) == 0) {
			fail(9, data_len, "relabeled det512 signature verified under det1024 with signer's key", 0);
		}

		sig1024[0] = FALCON_DET512_SIG_COMPRESSED_HEADER;
		if (falcon_det512_verify_compressed(sig1024, len1024, pub512, data, data_len) == 0) {
			fail(10, data_len, "relabeled det1024 signature verified under det512 key", 0);
		}
		// The signer's 1024 key is larger than a det512 key; det512 reads
		// only its own key size, which here is a prefix of it.
		if (falcon_det512_verify_compressed(sig1024, len1024, pub1024, data, data_len) == 0) {
			fail(10, data_len, "relabeled det1024 signature verified under det512 with signer's key", 0);
		}
		if (falcon_det512_verify_compressed(sig1024, FALCON_DET512_SIG_COMPRESSED_MAXSIZE,
			pub512, data, data_len) == 0)
		{
			fail(10, data_len, "truncated, relabeled det1024 signature verified under det512 key", 0);
		}

		printf(".");
		fflush(stdout);
	}
	printf(" done.\n");
}

int
main(void)
{
	test_det_generic(10,
		falcon_det1024_keygen, falcon_det1024_sign_compressed,
		FALCON_DET1024_KAT);
	test_det_generic(9,
		falcon_det512_keygen, falcon_det512_sign_compressed,
		FALCON_DET512_KAT);
	test_cross_family();
	printf("All generic-API cross-checks pass.\n");
	return 0;
}
