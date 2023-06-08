// Copyright (C) 2019-2021 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

// Package falcon implements a deterministic variant of the Falcon
// signature scheme.
package falcon

// NOTE: cgo go code couldn't compile with the flags: -Wmissing-prototypes and -Wno-unused-paramete

//#cgo CFLAGS:  -Wall -Wextra -Wpedantic -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -Wno-unused-parameter -Wno-overlength-strings  -O3 -fomit-frame-pointer -Wno-strict-prototypes
// #include "falcon.h"
// #include "deterministic.h"
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Falcon cgo errors
var (
	ErrKeygenFail  = errors.New("falcon keygen failed")
	ErrSignFail    = errors.New("falcon sign failed")
	ErrVerifyFail  = errors.New("falcon verify failed")
	ErrConvertFail = errors.New("falcon convert to CT failed")

	ErrPubkeyCoefficientsFail = errors.New("falcon pubkey coefficients failed")
	ErrS1CoefficientsFail     = errors.New("falcon computing S1 coefficients failed")
	ErrS2CoefficientsFail     = errors.New("falcon computing S2 coefficients failed")
)

const (
	// PublicKeySize is the size of a Falcon public key.
	PublicKeySize = C.FALCON_DET1024_PUBKEY_SIZE
	// PrivateKeySize is the size of a Falcon private key.
	PrivateKeySize = C.FALCON_DET1024_PRIVKEY_SIZE
	// CurrentSaltVersion is the salt version number used to compute signatures.
	// The salt version is incremented when the signing procedure changes (rarely).
	CurrentSaltVersion = C.FALCON_DET1024_CURRENT_SALT_VERSION
	// CTSignatureSize is the size in bytes of a Falcon signature in CT format
	CTSignatureSize = C.FALCON_DET1024_SIG_CT_SIZE
	// SignatureMaxSize is the max possible size in bytes of a Falcon signature in compressed format.
	SignatureMaxSize = C.FALCON_DET1024_SIG_COMPRESSED_MAXSIZE
	// N=1024 is the degree of Falcon det1024 polynomials.
	N = 1 << C.FALCON_DET1024_LOGN
)

// PublicKey represents a falcon public key
type PublicKey [PublicKeySize]byte

// PrivateKey represents a falcon private key
type PrivateKey [PrivateKeySize]byte

// CompressedSignature is a deterministic Falcon signature in compressed
// format, which is variable-length.
type CompressedSignature []byte

// CTSignature is a deterministic Falcon signature in constant-time format,
// which is fixed-length.
type CTSignature [CTSignatureSize]byte

// GenerateKey generates a public/private key pair from the given seed.
func GenerateKey(seed []byte) (PublicKey, PrivateKey, error) {
	var rng C.shake256_context

	if len(seed) == 0 {
		C.shake256_init_prng_from_seed(&rng, C.NULL, 0)
	} else {
		C.shake256_init_prng_from_seed(&rng, unsafe.Pointer(&seed[0]), C.size_t(len(seed)))
	}

	publicKey := PublicKey{}
	privateKey := PrivateKey{}

	r := C.falcon_det1024_keygen(&rng, unsafe.Pointer(&privateKey[0]), unsafe.Pointer(&publicKey[0]))
	if r != 0 {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("error code is %d: %w", int(r), ErrKeygenFail)
	}

	runtime.KeepAlive(seed)
	return publicKey, privateKey, nil
}

// SignCompressed signs the message with privateKey and returns a compressed-format
// signature, or an error if signing fails (e.g., due to a malformed private key).
func (sk *PrivateKey) SignCompressed(msg []byte) (CompressedSignature, error) {
	var sigLen C.size_t
	var sig [SignatureMaxSize]byte
	var r C.int
	if len(msg) == 0 {
		r = C.falcon_det1024_sign_compressed(unsafe.Pointer(&sig[0]), &sigLen, unsafe.Pointer(&(*sk)), C.NULL, 0)
	} else {
		r = C.falcon_det1024_sign_compressed(unsafe.Pointer(&sig[0]), &sigLen, unsafe.Pointer(&(*sk)), unsafe.Pointer(&msg[0]), C.size_t(len(msg)))
	}
	if r != 0 {
		return nil, fmt.Errorf("error code %d: %w", int(r), ErrSignFail)
	}

	runtime.KeepAlive(msg)
	return sig[:sigLen], nil
}

// ConvertToCT converts a compressed-format signature to a CT-format signature.
func (sig *CompressedSignature) ConvertToCT() (CTSignature, error) {
	sigCT := CTSignature{}

	r := C.falcon_det1024_convert_compressed_to_ct(unsafe.Pointer(&sigCT[0]), unsafe.Pointer(&(*sig)[0]), C.size_t(len(*sig)))
	if r != 0 {
		return CTSignature{}, fmt.Errorf("error code %d: %w", int(r), ErrConvertFail)
	}
	return sigCT, nil
}

// Verify reports whether sig is a valid compressed-format signature of msg under publicKey.
// It outputs nil if so, and an error otherwise.
func (pk *PublicKey) Verify(signature CompressedSignature, msg []byte) error {
	if len(signature) == 0 {
		return fmt.Errorf("empty signature: %w", ErrVerifyFail)
	}

	var r C.int
	if len(msg) == 0 {
		r = C.falcon_det1024_verify_compressed(unsafe.Pointer(&signature[0]), C.size_t(len(signature)), unsafe.Pointer(&(*pk)), C.NULL, 0)
	} else {
		r = C.falcon_det1024_verify_compressed(unsafe.Pointer(&signature[0]), C.size_t(len(signature)), unsafe.Pointer(&(*pk)), unsafe.Pointer(&msg[0]), C.size_t(len(msg)))
	}
	if r != 0 {
		return fmt.Errorf("error code %d: %w", int(r), ErrVerifyFail)
	}

	runtime.KeepAlive(msg)
	runtime.KeepAlive(signature)
	return nil
}

// VerifyCTSignature reports whether sig is a valid CT-format signature of msg under publicKey.
// It outputs nil if so, and an error otherwise.
func (pk *PublicKey) VerifyCTSignature(signature CTSignature, msg []byte) error {
	var r C.int
	if len(msg) == 0 {
		r = C.falcon_det1024_verify_ct(unsafe.Pointer(&signature[0]), unsafe.Pointer(&(*pk)), C.NULL, 0)
	} else {
		r = C.falcon_det1024_verify_ct(unsafe.Pointer(&signature[0]), unsafe.Pointer(&(*pk)), unsafe.Pointer(&msg[0]), C.size_t(len(msg)))
	}
	if r != 0 {
		return fmt.Errorf("error code %d: %w", int(r), ErrVerifyFail)
	}

	runtime.KeepAlive(msg)
	runtime.KeepAlive(signature)
	return nil
}

// SaltVersion returns the salt version used in a compressed-format signature.
// By definition, the default salt version is 0, if the signature is too short to specify one.
// (Such a signature is malformed, and would not pass verification, but is still considered to have a salt version.)
func (sig CompressedSignature) SaltVersion() byte {
	if len(sig) < 2 {
		return 0
	}
	return sig[1]
}

// SaltVersion returns the salt version used in a CT-format signature.
// (It panics if the receiver pointer is nil.)
func (sig *CTSignature) SaltVersion() byte {
	return sig[1]
}

// Coefficients unpacks a public key representing a ring element h to its vector
// of polynomial coefficients, i.e.,
//
// h(x) = h[0] + h[1] * x + h[2] * x^2 + ... + h[1023] * x^1023.
//
// Returns an error if pubkey is invalid.
func (pub *PublicKey) Coefficients() (h [N]uint16, err error) {
	r := C.falcon_det1024_pubkey_coeffs((*C.uint16_t)(&h[0]), unsafe.Pointer(&(*pub)))
	if r != 0 {
		err = fmt.Errorf("error code %d: %w", int(r), ErrPubkeyCoefficientsFail)
	}
	return
}

// S2Coefficients unpacks a signature in CT format to the vector of polynomial
// coefficients of the associated ring element s_2. See Section 3.10 of the
// Falcon specification for details. Returns an error if sig cannot be properly
// unpacked.
func (sig *CTSignature) S2Coefficients() (s2 [N]int16, err error) {
	r := C.falcon_det1024_s2_coeffs((*C.int16_t)(&s2[0]), unsafe.Pointer(&(*sig)))
	if r != 0 {
		err = fmt.Errorf("error code %d: %w", int(r), ErrS2CoefficientsFail)
	}
	return
}

// S1Coefficients computes the vector of polynomial coefficients of
// s_1 = c - s_2 * h, given the unpacked values h, c, and s_2.
// See Section 3.10 of the Falcon specification for details. Returns an error if
// the aggregate (s_1,s_2) vector is not short enough to constitute a valid
// signature (for the public key corresponding to h, the hash digest
// corresponding to c, and the signature corresponding to s_2).
func S1Coefficients(h [N]uint16, c [N]uint16, s2 [N]int16) (s1 [N]int16, err error) {
	r := C.falcon_det1024_s1_coeffs((*C.int16_t)(&s1[0]), (*C.uint16_t)(&h[0]), (*C.uint16_t)(&c[0]), (*C.int16_t)(&s2[0]))
	if r != 0 {
		err = fmt.Errorf("error code %d: %w", int(r), ErrS1CoefficientsFail)
	}
	return
}

// HashToPointCoefficients hashes msg using the fixed 40-byte salt specified by
// saltVersion, to a ring element c, represented by its vector of polynomial
// coefficients. See Section 3.7 of the Falcon specification for the details of the
// hashing, and Section 2.3.2-3 of the Deterministic Falcon specification for
// the definition of the fixed salt.
func HashToPointCoefficients(msg []byte, saltVersion byte) (c [N]uint16) {
	if len(msg) == 0 {
		C.falcon_det1024_hash_to_point_coeffs((*C.uint16_t)(&c[0]), C.NULL, 0, C.uint8_t(saltVersion))
	} else {
		C.falcon_det1024_hash_to_point_coeffs((*C.uint16_t)(&c[0]), unsafe.Pointer(&msg[0]), C.size_t(len(msg)), C.uint8_t(saltVersion))
	}
	return
}
