#include <stdint.h>
#include <string.h>

#include "falcon.h"
#include "deterministic.h"

int falcon_det1024_keygen(shake256_context *rng, void *privkey, void *pubkey) {
	size_t tmpkg_len = FALCON_TMPSIZE_KEYGEN(FALCON_DET1024_LOGN);
	uint8_t tmpkg[tmpkg_len];

	return falcon_keygen_make(rng, FALCON_DET1024_LOGN,
		privkey, FALCON_DET1024_PRIVKEY_SIZE,
		pubkey, FALCON_DET1024_PUBKEY_SIZE,
		tmpkg, tmpkg_len);
}

uint8_t falcon_det1024_nonce[40] = {"FALCON_DET1024"};

int falcon_det1024_sign(void *sig, const void *privkey, const void *data, size_t data_len) {
	shake256_context detrng;
	shake256_context hd;
	size_t tmpsd_len = FALCON_TMPSIZE_SIGNDYN(FALCON_DET1024_LOGN);
	uint8_t tmpsd[tmpsd_len];
	uint8_t domain[1], logn[1];

	size_t siglen = FALCON_SIG_PADDED_SIZE(FALCON_DET1024_LOGN);
	uint8_t fullsig[siglen];

	if (falcon_get_logn(privkey, FALCON_DET1024_PRIVKEY_SIZE) != FALCON_DET1024_LOGN) {
		return FALCON_ERR_FORMAT;
	}

	// SHAKE(0 || logn || sk || data)
	domain[0] = 0;
	shake256_init(&detrng);
	shake256_inject(&detrng, domain, 1);
	logn[0] = FALCON_DET1024_LOGN;
	shake256_inject(&detrng, logn, 1);
	shake256_inject(&detrng, privkey, FALCON_DET1024_PRIVKEY_SIZE);
	shake256_inject(&detrng, data, data_len);
	shake256_flip(&detrng);

	// SHAKE(nonce || data)
	shake256_init(&hd);
	shake256_inject(&hd, falcon_det1024_nonce, 40);
	shake256_inject(&hd, data, data_len);

	int r = falcon_sign_dyn_finish(&detrng, fullsig, &siglen,
		FALCON_SIG_PADDED, privkey, FALCON_DET1024_PRIVKEY_SIZE,
		&hd, falcon_det1024_nonce, tmpsd, tmpsd_len);
	if (r != 0) {
		return r;
	}

	uint8_t *sigbytes = sig;
	sigbytes[0] = FALCON_DET1024_SIG_PREFIX;
	sigbytes[1] = fullsig[0];
	memcpy(sigbytes+2, fullsig+41, siglen-41);

	return 0;
}

int falcon_det1024_verify(const void *sig, const void *pubkey, const void *data, size_t data_len) {
	size_t tmpvv_len = FALCON_TMPSIZE_VERIFY(FALCON_DET1024_LOGN);
	uint8_t tmpvv[tmpvv_len];

	size_t siglen = FALCON_SIG_PADDED_SIZE(FALCON_DET1024_LOGN);
	uint8_t fullsig[siglen];

	const uint8_t *sigbytes = sig;
	// det1024 signatures must start with the prefix byte:
	if (sigbytes[0] != FALCON_DET1024_SIG_PREFIX) {
		return FALCON_ERR_BADSIG;
	}
	// det1024 expects a padded signature with n=1024:
	if (sigbytes[1] != FALCON_DET1024_SIG_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	fullsig[0] = sigbytes[1];
	memcpy(fullsig+1, falcon_det1024_nonce, 40);
	memcpy(fullsig+41, sigbytes+2, siglen-41);

	return falcon_verify(fullsig, siglen, FALCON_SIG_PADDED,
		pubkey, FALCON_DET1024_PUBKEY_SIZE, data, data_len,
		tmpvv, tmpvv_len);
}