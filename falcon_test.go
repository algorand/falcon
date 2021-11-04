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

package cfalcon

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestFalconSignAndVerify(t *testing.T) {
	for i := 0; i < 100; i++ {
		sk, pk, err := GenerateKey([]byte("seed"))
		if err != nil {
			t.Error(err, "Generate Key failed")
		}

		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(i))
		bs := sha256.Sum256(b)

		sig, err := sk.SignBytes(bs[:])
		if err != nil {
			t.Error(err, "SignBytes failed")
		}

		err = pk.VerifyBytes(bs[:], sig[:])
		if err != nil {
			t.Error(err, "SignBytes failed")
		}

	}
}

func TestFalconWrongSignature(t *testing.T) {
	sk, pk, err := GenerateKey([]byte("seed"))
	if err != nil {
		t.Error(err, "GenerateKey failed")
	}

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(0))
	bs := sha256.Sum256(b)

	sig, err := sk.SignBytes(bs[:])
	if err != nil {
		t.Error(err, "SignBytes failed")
	}

	sig[0] = sig[0] + 1
	err = pk.VerifyBytes(bs[:], sig[:])
	if err == nil {
		t.Error(err, "VerifyBytes succeeded it should have failed")
	}
}

func TestFalconSignDifferentSeed(t *testing.T) {
	sk1, pk1, err := GenerateKey([]byte("seed"))
	if err != nil {
		t.Error(err, "GenerateKey failed")
	}

	sk, pk, err := GenerateKey([]byte("seed2"))
	if err != nil {
		t.Error(err, "GenerateKey failed")
	}

	if bytes.Equal(sk1[:], sk[:]) {
		t.Error(err, "secret key are the same")
	}

	if bytes.Equal(pk1[:], pk[:]) {
		t.Error(err, "secret key are the same")
	}

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(0))
	bs := sha256.Sum256(b)

	sig, err := sk.SignBytes(bs[:])
	if err != nil {
		t.Error(err, "SignBytes failed")
	}

	err = pk.VerifyBytes(bs[:], sig[:])
	if err != nil {
		t.Error(err, "VerifyBytes failed")
	}
}

func TestFalconSignEmptySeed(t *testing.T) {
	sk, pk, err := GenerateKey([]byte{})
	if err != nil {
		t.Error(err, "GenerateKey failed")
	}

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(0))
	bs := sha256.Sum256(b)

	sig, err := sk.SignBytes(bs[:])
	if err != nil {
		t.Error(err, "SignBytes failed")
	}

	err = pk.VerifyBytes(bs[:], sig[:])
	if err != nil {
		t.Error(err, "VerifyBytes failed")
	}
}

func TestFalconSignEmptyMessage(t *testing.T) {
	sk, pk, err := GenerateKey([]byte("seed"))
	if err != nil {
		t.Error(err, "GenerateKey failed")
	}

	var bs [0]byte

	sig, err := sk.SignBytes(bs[:])
	if err != nil {
		t.Error(err, "SignBytes failed")
	}

	err = pk.VerifyBytes(bs[:], sig[:])
	if err != nil {
		t.Error(err, "VerifyBytes failed")
	}
}

func TestFalconVerifySmallSignature(t *testing.T) {
	sk, pk, err := GenerateKey([]byte("seed"))
	if err != nil {
		t.Error(err, "GenerateKey failed")
	}

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(0))
	bs := sha256.Sum256(b)

	_, err = sk.SignBytes(bs[:])
	if err != nil {
		t.Error(err, "SignBytes failed")
	}

	var sig [4]byte
	err = pk.VerifyBytes(bs[:], sig[:])
	if err.Error() != ErrBadFalconSignatureTooSmall.Error() {
		t.Error(err, "Error expected")
	}
}

func BenchmarkFalconKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var seed [48]byte
		rand.Read(seed[:])
		GenerateKey(seed[:])
	}
}

func BenchmarkFalconSign(b *testing.B) {
	sk, _, err := GenerateKey([]byte("seed"))
	if err != nil {
		b.Error(err, "GenerateKey failed")
	}

	strs := make([][64]byte, b.N)

	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.SignBytes(strs[i][:])
	}

}

func BenchmarkFalconVerify(b *testing.B) {

	sk, pk, err := GenerateKey([]byte("seed"))
	if err != nil {
		b.Error(err, "GenerateKey failed")
	}

	strs := make([][64]byte, b.N)
	sigs := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
		sigs[i], _ = sk.SignBytes(msg[:])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pk.VerifyBytes(strs[i][:], sigs[i][:])
	}
}
