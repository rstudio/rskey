// Copyright 2025 Posit Software, PBC
// SPDX-License-Identifier: Apache-2.0

package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
)

const (
	// The AEAD.Overhead() here is 16, plus 12 for the nonce, plus 1 for the
	// version.
	minimumAESLength = 16 + 12 + 1
)

// EncryptFIPS produces base64-encoded cipher text for the given payload and key
// using a FIPS-compatible algorithm, or an error if one cannot be created.
func (k *Key) EncryptFIPS(s string) (string, error) {
	return k.EncryptBytesFIPS([]byte(s))
}

// EncryptBytesFIPS produces base64-encoded cipher text for the given bytes and
// key using a FIPS-compatible algorithm, or an error if one cannot be created.
func (k *Key) EncryptBytesFIPS(bytes []byte) (string, error) {
	output, err := k.encryptAES(bytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(output), nil
}

func (k *Key) encryptAES(bytes []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil {
		return []byte{}, err
	}

	aead := k.newAESGCM()
	output := aead.Seal(nil, nonce, bytes, nil)
	output = append(nonce, output...)
	// Append a version prefix.
	output = append([]byte{2}, output...)
	return output, nil
}

func (k *Key) decryptAES(buf []byte) ([]byte, error) {
	if len(buf) < minimumAESLength {
		return []byte{}, ErrPayLoadTooShort
	}

	// Note: We're skipping the version prefix here.
	nonce := make([]byte, 12)
	copy(nonce, buf[1:13])

	aead := k.newAESGCM()
	bytes, err := aead.Open(nil, nonce, buf[13:], nil)
	if err != nil {
		return []byte{}, ErrFailedToDecrypt
	}
	return bytes, nil
}

func (k *Key) newAESGCM() cipher.AEAD {
	// The only way either of these can error is by having an incorrect byte
	// slice length or algorithm.
	block, _ := aes.NewCipher(k[0:32])
	aead, _ := cipher.NewGCM(block)
	return aead
}
