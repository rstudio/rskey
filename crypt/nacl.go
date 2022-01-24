// Copyright 2022 RStudio, PBC
// SPDX-License-Identifier: Apache-2.0

//go:build !fips
// +build !fips

package crypt

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/secretbox"
)

// When true, this package has been built in "FIPS mode". Attempts to use
// encryption algorithms not permissible under FIPS-140 regulations will always
// fail, and encryption will use AES-256-GCM by default.
const FIPSMode = false

const (
	// The overhead length plus the nonce length.
	minimumSecretboxLength = secretbox.Overhead + 24
)

func (k *Key) encryptSecretbox(bytes []byte) ([]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return []byte{}, err
	}
	output := secretbox.Seal(nil, bytes, &nonce, k.key32())
	output = append(nonce[:], output...)
	return output, nil
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
