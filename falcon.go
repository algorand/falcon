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

// #cgo CFLAGS: -O3
// #include "falcon.h"
// #include "deterministic.h"
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	// PublicKeySize is the size of a Falcon public key.
	PublicKeySize = C.FALCON_DET1024_PUBKEY_SIZE
	// PrivateKeySize is the size of a Falcon private key.
	PrivateKeySize = C.FALCON_DET1024_PRIVKEY_SIZE
	// CurrentSaltVersion is the salt version number used to compute signatures.
	// The salt version is incremented when the signing procedure changes (rarely).
	CurrentSaltVersion = C.FALCON_DET1024_CURRENT_SALT_VERSION
)

type PublicKey []byte
type PrivateKey []byte

// CompressedSignature is a deterministic Falcon signature in compressed
// form, which is variable-length.
type CompressedSignature []byte

// CTSignature is a deterministic Falcon signature in constant-time form,
// which is fixed-length.
type CTSignature []byte

// GenerateKey generates a public/private key pair from the given seed.
func GenerateKey(seed []byte) (PublicKey, PrivateKey, error) {
	var rng C.shake256_context
	C.shake256_init_prng_from_seed(&rng, unsafe.Pointer(&seed[0]), C.size_t(len(seed)))

	publicKey := make([]byte, PublicKeySize)
	privateKey := make([]byte, PrivateKeySize)

	r := C.falcon_det1024_keygen(&rng, unsafe.Pointer(&privateKey[0]), unsafe.Pointer(&publicKey[0]))
	if r != 0 {
		return nil, nil, fmt.Errorf("falcon keygen failed: %d", int(r))
	}

	return publicKey, privateKey, nil
}

// SignCompressed signs the message with privateKey and returns a compressed
// signature, or an error if signing fails (e.g., due to a malformed private key).
func SignCompressed(privateKey PrivateKey, msg []byte) (CompressedSignature, error) {
	data := C.NULL
	if len(msg) > 0 {
		data = unsafe.Pointer(&msg[0])
	}
	var sigLen C.size_t
	sig := make([]byte, C.FALCON_DET1024_SIG_COMPRESSED_MAXSIZE)
	r := C.falcon_det1024_sign_compressed(unsafe.Pointer(&sig[0]), &sigLen, unsafe.Pointer(&privateKey[0]), data, C.size_t(len(msg)))
	if r != 0 {
		return nil, fmt.Errorf("falcon sign failed: %d", int(r))
	}
	sig = sig[:sigLen]
	return sig, nil
}

// ConvertToCT converts a compressed signature to a CT signature.
func (sig CompressedSignature) ConvertToCT() (CTSignature, error) {
	sigCT := make([]byte, C.FALCON_DET1024_SIG_CT_SIZE)
	r := C.falcon_det1024_convert_compressed_to_ct(unsafe.Pointer(&sigCT[0]), unsafe.Pointer(&sig[0]), C.size_t(len(sig)))
	if r != 0 {
		return nil, fmt.Errorf("falcon convert failed: %d", int(r))
	}
	return sigCT, nil
}

// Verify reports whether sig is a valid compressed signature of msg under publicKey.
func (sig CompressedSignature) Verify(publicKey PublicKey, msg []byte) bool {
	data := C.NULL
	if len(msg) > 0 {
		data = unsafe.Pointer(&msg[0])
	}
	r := C.falcon_det1024_verify_compressed(unsafe.Pointer(&sig[0]), C.size_t(len(sig)), unsafe.Pointer(&publicKey[0]), data, C.size_t(len(msg)))
	return r == 0
}

// Verify reports whether sig is a valid CT signature of msg under publicKey.
func (sig CTSignature) Verify(publicKey PublicKey, msg []byte) bool {
	data := C.NULL
	if len(msg) > 0 {
		data = unsafe.Pointer(&msg[0])
	}
	r := C.falcon_det1024_verify_ct(unsafe.Pointer(&sig[0]), unsafe.Pointer(&publicKey[0]), data, C.size_t(len(msg)))
	return r == 0
}

// SaltVersion returns the salt version number used in the signature.
func (sig CompressedSignature) SaltVersion() int {
	return int(sig[1])
}

// SaltVersion returns the salt version number used in the signature.
func (sig CTSignature) SaltVersion() int {
	return int(sig[1])
}
