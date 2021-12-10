#include <stdint.h>
#include <string.h>

#include "falcon.h"
#include "inner.h"
#include "deterministic.h"

int falcon_det1024_keygen(shake256_context *rng, void *privkey, void *pubkey) {
	size_t tmpkg_len = FALCON_TMPSIZE_KEYGEN(FALCON_DET1024_LOGN);
	uint8_t tmpkg[tmpkg_len];

	return falcon_keygen_make(rng, FALCON_DET1024_LOGN,
		privkey, FALCON_DET1024_PRIVKEY_SIZE,
		pubkey, FALCON_DET1024_PUBKEY_SIZE,
		tmpkg, tmpkg_len);
}

// Domain separator used to construct the fixed versioned salt string.
uint8_t falcon_det1024_salt_rest[38] = {"FALCON_DET"};

// Construct the fixed salt for a given version.
void falcon_det1024_write_salt(uint8_t dst[40], uint8_t salt_version) {
	dst[0] = salt_version;
	dst[1] = FALCON_DET1024_LOGN;
	memcpy(dst+2, falcon_det1024_salt_rest, 38);
}

int falcon_det1024_sign_compressed(void *sig, size_t *sig_len,
        const void *privkey, const void *data, size_t data_len) {

	shake256_context detrng;
	shake256_context hd;
	size_t tmpsd_len = FALCON_TMPSIZE_SIGNDYN(FALCON_DET1024_LOGN);
	uint8_t tmpsd[tmpsd_len];
	uint8_t logn[1] = {FALCON_DET1024_LOGN};
	uint8_t salt[40];

	size_t saltedsig_len = FALCON_SIG_COMPRESSED_MAXSIZE(FALCON_DET1024_LOGN);
	uint8_t saltedsig[saltedsig_len];

	if (falcon_get_logn(privkey, FALCON_DET1024_PRIVKEY_SIZE) != FALCON_DET1024_LOGN) {
		return FALCON_ERR_FORMAT;
	}

	// SHAKE(logn || privkey || data), set to output mode.
	shake256_init(&detrng);
	shake256_inject(&detrng, logn, 1);
	shake256_inject(&detrng, privkey, FALCON_DET1024_PRIVKEY_SIZE);
	shake256_inject(&detrng, data, data_len);
	shake256_flip(&detrng);

	falcon_det1024_write_salt(salt, FALCON_DET1024_CURRENT_SALT_VERSION);

	// SHAKE(salt || data), still in input mode.
	shake256_init(&hd);
	shake256_inject(&hd, salt, 40);
	shake256_inject(&hd, data, data_len);

	int r = falcon_sign_dyn_finish(&detrng, saltedsig, &saltedsig_len,
		FALCON_SIG_COMPRESSED, privkey, FALCON_DET1024_PRIVKEY_SIZE,
		&hd, salt, tmpsd, tmpsd_len);
	if (r != 0) {
		return r;
	}

        // Transform the salted signature to unsalted format.
	uint8_t *sigbytes = sig;
	sigbytes[0] = saltedsig[0] | 0x80;
	sigbytes[1] = FALCON_DET1024_CURRENT_SALT_VERSION;
	memcpy(sigbytes+2, saltedsig+41, saltedsig_len-41);

	*sig_len = saltedsig_len-40+1;

	return 0;
}

int falcon_det1024_convert_compressed_to_ct(void *sig_ct,
        const void *sig_compressed, size_t sig_compressed_len) {

	int16_t coeffs[1 << FALCON_DET1024_LOGN];
	size_t v;

	if (((uint8_t*)sig_compressed)[0] != FALCON_DET1024_SIG_COMPRESSED_HEADER) {
		return FALCON_ERR_BADSIG;
	}

        // Decode signature's s_bytes into 1024 signed-integer coefficients.
	v = Zf(comp_decode)(coeffs, FALCON_DET1024_LOGN, sig_compressed+2, sig_compressed_len-2);
	if (v == 0) {
		return FALCON_ERR_SIZE;
	}

	uint8_t *sig = sig_ct;
	sig[0] = FALCON_DET1024_SIG_CT_HEADER;
	sig[1] = ((uint8_t*)sig_compressed)[1]; // Copy the salt_version byte.

        // Encode the signed-integer coefficients into CT format.
	v = Zf(trim_i16_encode)(sig+2, FALCON_DET1024_SIG_CT_SIZE-2, coeffs, FALCON_DET1024_LOGN,
		Zf(max_sig_bits)[FALCON_DET1024_LOGN]);
	if (v == 0) {
		return FALCON_ERR_SIZE;
	}

	return 0;
}

// Construct the corresponding salted signature from an unsalted one.
void falcon_det1024_resalt(uint8_t *salted_sig,
        const uint8_t *unsalted_sig, size_t unsalted_sig_len) {

	salted_sig[0] = unsalted_sig[0] & ~0x80; // Reset MSB to 0.
	falcon_det1024_write_salt(salted_sig+1, unsalted_sig[1]);
	memcpy(salted_sig+41, unsalted_sig+2, unsalted_sig_len-2);
}

int falcon_det1024_verify_compressed(const void *sig, size_t sig_len,
        const void *pubkey, const void *data, size_t data_len) {

	size_t tmpvv_len = FALCON_TMPSIZE_VERIFY(FALCON_DET1024_LOGN);
	uint8_t tmpvv[tmpvv_len];

        // Add back the salt; drop the version byte.
	size_t salted_sig_len = sig_len + 40 - 1;
	uint8_t salted_sig[salted_sig_len];

	if (((uint8_t*)sig)[0] != FALCON_DET1024_SIG_COMPRESSED_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	falcon_det1024_resalt(salted_sig, sig, sig_len);

	return falcon_verify(salted_sig, salted_sig_len, FALCON_SIG_COMPRESSED,
		pubkey, FALCON_DET1024_PUBKEY_SIZE, data, data_len,
		tmpvv, tmpvv_len);
}

int falcon_det1024_verify_ct(const void *sig,
        const void *pubkey, const void *data, size_t data_len) {

	size_t tmpvv_len = FALCON_TMPSIZE_VERIFY(FALCON_DET1024_LOGN);
	uint8_t tmpvv[tmpvv_len];

	size_t salted_sig_len = FALCON_SIG_CT_SIZE(FALCON_DET1024_LOGN);
	uint8_t salted_sig[salted_sig_len];

	if (((uint8_t*)sig)[0] != FALCON_DET1024_SIG_CT_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	falcon_det1024_resalt(salted_sig, sig, FALCON_DET1024_SIG_CT_SIZE);

	return falcon_verify(salted_sig, salted_sig_len, FALCON_SIG_CT,
		pubkey, FALCON_DET1024_PUBKEY_SIZE, data, data_len,
		tmpvv, tmpvv_len);
}

int falcon_det1024_get_salt_version(const void* sig) {
	return ((uint8_t*)sig)[1];
};