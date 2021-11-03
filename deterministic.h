#ifndef FALCON_DET1024_H__
#define FALCON_DET1024_H__

#include <stddef.h>
#include <stdint.h>
#include "falcon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FALCON_DET1024_LOGN 10
#define FALCON_DET1024_PUBKEY_SIZE FALCON_PUBKEY_SIZE(FALCON_DET1024_LOGN)
#define FALCON_DET1024_PRIVKEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_DET1024_LOGN)
// Drop the 40 byte nonce and add a prefix byte:
#define FALCON_DET1024_SIG_SIZE FALCON_SIG_PADDED_SIZE(FALCON_DET1024_LOGN)-40+1
#define FALCON_DET1024_SIG_PREFIX 0x80
// The header corresponds to a padded signature with n=1024:
#define FALCON_DET1024_SIG_HEADER 0x3A

/*
 * Fixed nonce used in deterministic signing (for n=1024).
 */
extern uint8_t falcon_det1024_nonce[40];

/*
 * Generate a keypair (for Falcon parameter n=1024).
 *
 * The source of randomness is the provided SHAKE256 context *rng,
 * which must have been already initialized, seeded, and set to output
 * mode (see shake256_init_prng_from_seed() and
 * shake256_init_prng_from_system()).
 *
 * The private key is written in the buffer pointed to by privkey.
 * The size of that buffer must be FALCON_DET1024_PRIVKEY_SIZE bytes.
 *
 * The public key is written in the buffer pointed to by pubkey.
 * The size of that buffer must be FALCON_DET1024_PUBKEY_SIZE bytes.
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det1024_keygen(shake256_context *rng, void *privkey, void *pubkey);

/*
 * Deterministically sign the data provided in buffer data[] (of
 * length data_len bytes), using the private key held in privkey[] (of
 * length FALCON_DET1024_PRIVKEY_SIZE bytes). The signature is written
 * in sig[] (of length FALCON_DET1024_SIG_SIZE).
 *
 * The resulting signature is incompatible with randomized ("salted")
 * Falcon signatures: it includes an additional prefix byte, and does
 * not include the salt (nonce). See the "Deterministic Falcon"
 * specification for further details.
 *
 * This function implements only the following subset of the
 * specification:
 *
 *   -- the parameter n is fixed to n=1024, and
 *   -- the signature format is fixed to "padded".
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det1024_sign(void *sig, const void *privkey,
                        const void *data, size_t data_len);

/*
 * Verify the deterministic (det1024) signature provided in sig[] (of
 * length FALCON_DET1024_SIG_SIZE bytes) with respect to the public
 * key provided in pubkey[] (of length FALCON_DET1024_PUBKEY_SIZE
 * bytes) and the data provided in data[] (of length data_len bytes).
 *
 * This function accepts a strict subset of valid deterministic Falcon
 * signatures, namely, only those having n=1024 and "padded" signature
 * format (thus matching the choices implemented by
 * falcon_det1024_sign).
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det1024_verify(const void *sig, const void *pubkey,
                          const void *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif
