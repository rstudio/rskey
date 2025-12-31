// Copyright 2025 Posit Software, PBC
// SPDX-License-Identifier: Apache-2.0

package crypt

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// The overhead length plus the nonce length.
	minimumSecretboxLength = secretbox.Overhead + 24
)

func (k *Key) encryptSecretbox(bytes []byte) []byte {
	var nonce [24]byte
	// As of Go 1.24, rand.Read() aborts rather than returning an error.
	// See: https://go.dev/issue/66821
	_, _ = rand.Read(nonce[:])
	output := secretbox.Seal(nil, bytes, &nonce, k.key32())
	output = append(nonce[:], output...)
	return output
}

func (k *Key) decryptSecretbox(buf []byte) ([]byte, error) {
	if len(buf) < minimumSecretboxLength {
		return []byte{}, ErrPayLoadTooShort
	}

	var nonce [24]byte
	copy(nonce[0:24], buf[0:24])

	bytes, ok := secretbox.Open(nil, buf[24:], &nonce, k.key32())
	if !ok {
		return []byte{}, ErrFailedToDecrypt
	}
	return bytes, nil
}

// NACL Secretbox only uses 32 bytes, so we pass it the *first* 32 bytes of the
// key.
func (k *Key) key32() *[32]byte {
	var key [32]byte
	copy(key[:], k[0:32])
	return &key
}
