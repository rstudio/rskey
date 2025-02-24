// Copyright 2025 Posit Software, PBC
// SPDX-License-Identifier: Apache-2.0

// Package crypt implements the secret key-based encryption and decryption
// scheme used by Posit's Connect and Package Manager products.
package crypt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	// The fixed length of a Key, in bytes.
	KeyLength = 512
	// The length of unpadded base64, the shortest supported encoding.
	minEncodedLength = KeyLength * 6 / 8
)

var (
	// ErrInvalidKeyLength reports a malformed Key input.
	ErrInvalidKeyLength = errors.New("Encryption keys must be 512 bytes when decoded")
	// ErrPayLoadTooShort reports malformed cipher text.
	ErrPayLoadTooShort = errors.New("Payload is too short to be encrypted")
	// ErrFailedToDecrypt reports a failure to decrypt a given cipher text with a
	// given Key via Decrypt().
	ErrFailedToDecrypt = errors.New("Decryption failed")
	// ErrFIPS reports encryption or decryption failures caused by running
	// in FIPS mode.
	ErrFIPS = errors.New("Non-AES algorithms cannot be used when running in FIPS mode")
)

// Key is a securely-generated, opaque byte array that can be used as a persistent
// secret when encrypting data.
type Key [KeyLength]byte

// NewKey returns a newly-generated key, or an error if one cannot be generated.
func NewKey() (*Key, error) {
	var key Key
	_, err := rand.Read(key[:])
	return &key, err
}

// NewKeyFromBytes returns the key read from the given byte slice, or an error.
func NewKeyFromBytes(src []byte) (*Key, error) {
	size := len(src)
	if size < minEncodedLength {
		// The input is too short, no matter the encoding.
		return nil, ErrInvalidKeyLength
	}
	data := make([]byte, hex.DecodedLen(size))
	decoded := len(data)
	if _, err := hex.Decode(data, src); err != nil {
		// Try base64 encoding instead.
		data = make([]byte, base64.StdEncoding.DecodedLen(size))
		var b64err error
		decoded, b64err = base64.StdEncoding.Decode(data, src)
		if b64err != nil {
			// Return the original hex-encoding error.
			return nil, fmt.Errorf("failed to decode secret: %v", err)
		}
	}
	if decoded != KeyLength {
		return nil, ErrInvalidKeyLength
	}

	// For historical reasons, we always rotate incoming data.
	data = rotate(data)

	var key Key
	copy(key[:], data[0:512])
	return &key, nil
}

// NewKeyFromReader returns the key read from an io.Reader, or an error.
func NewKeyFromReader(src io.Reader) (*Key, error) {
	bytes, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}
	return NewKeyFromBytes(bytes)
}

// HexString produces a hex-encoded version of the key suitable for writing to
// disk.
func (k *Key) HexString() string {
	// For historical reasons, we always rotate outgoing data.
	data := rotate(k[:])
	return hex.EncodeToString(data)
}

// Internal base64 encoding utility, the equivalent of HexString().
func (k *Key) base64String() string {
	// For historical reasons, we always rotate outgoing data.
	data := rotate(k[:])
	return base64.StdEncoding.EncodeToString(data)
}

// Encrypt produces base64-encoded cipher text for the given payload and key, or
// an error if one cannot be created.
func (k *Key) Encrypt(s string) (string, error) {
	return k.EncryptBytes([]byte(s))
}

// EncryptBytes produces base64-encoded cipher text for the given bytes and key,
// or an error if one cannot be created.
func (k *Key) EncryptBytes(bytes []byte) (string, error) {
	var output []byte
	var err error
	if FIPSMode {
		output, err = k.encryptAES(bytes)
	} else {
		output, err = k.encryptSecretbox(bytes)
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(output), nil
}

// encryptVersioned produces a base64-encoded cipher text with an embedded
// version for the given payload and key, or an error if one cannot be created.
// This emulates the format used by some implementations.
func (k *Key) encryptVersioned(s string) (string, error) {
	output, err := k.encryptSecretbox([]byte(s))
	if err != nil {
		return "", err
	}
	output = append([]byte{1}, output...)
	return base64.StdEncoding.EncodeToString(output), nil
}

// Decrypt takes base64-encoded cipher text encrypted with the given key and
// returns the original clear text, or an error.
func (k *Key) Decrypt(s string) (string, error) {
	bytes, err := k.DecryptBytes(s)
	return string(bytes), err
}

// DecryptBytes takes base64-encoded cipher text encrypted with the given key
// and returns the original bytes, or an error.
func (k *Key) DecryptBytes(s string) ([]byte, error) {
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []byte{}, fmt.Errorf("invalid decryption payload: %v", err)
	}
	if len(buf) < 1 {
		return []byte{}, ErrPayLoadTooShort
	}
	// Some implementations use a version-prefixed cipher text. In order to
	// handle the (unlikely but possible) case where a versionless payload
	// *just happens* to start with a valid version byte, we must also try
	// the fallback on error.
	switch buf[0] {
	case byte(1):
		str, err := k.decryptSecretbox(buf[1:])
		if err == nil || FIPSMode {
			return str, err
		}
	case byte(2):
		str, err := k.decryptAES(buf)
		if err == nil || FIPSMode {
			return str, err
		}
	}
	return k.decryptSecretbox(buf)
}

// Fingerprint returns a string that can be used to identify this key.
//
// The fingerprint is not appropriate for cryptographic use. It is used as a
// convenient identifier in logs and API responses to aid in key rotation.
func (k *Key) Fingerprint() string {
	// note: the fingerprint is a hash of the rotated, not original, key data
	return fmt.Sprintf("%x", sha256.Sum256(k[:]))
}

func rotate(data []byte) []byte {
	xor := []byte{223, 99, 111, 160, 122, 212, 223, 105, 37, 190}
	newData := make([]byte, len(data))
	copy(newData, data)
	for i := range newData {
		newData[i] = newData[i] ^ xor[i%len(xor)]
	}
	return newData
}
