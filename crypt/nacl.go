// Copyright 2022 RStudio, PBC
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

func (k *Key) encryptSecretbox(s string) ([]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return []byte{}, err
	}
	output := secretbox.Seal(nil, []byte(s), &nonce, k.key32())
	output = append(nonce[:], output...)
	return output, nil
}

func (k *Key) decryptSecretbox(buf []byte) (string, error) {
	if len(buf) < minimumSecretboxLength {
		return "", ErrPayLoadTooShort
	}

	var nonce [24]byte
	copy(nonce[0:24], buf[0:24])

	bytes, ok := secretbox.Open(nil, buf[24:], &nonce, k.key32())
	if !ok {
		return "", ErrFailedToDecrypt
	}
	return string(bytes[:]), nil
}

// NACL Secretbox only uses 32 bytes, so we pass it the *first* 32 bytes of the
// key.
func (k *Key) key32() *[32]byte {
	var key [32]byte
	copy(key[:], k[0:32])
	return &key
}
