// Package crypt implements the secret key-based encryption and decryption
// scheme used by RStudio's Connect and Package Manager products.
package crypt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
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
	ErrPayLoadTooShort = errors.New(fmt.Sprintf("Encrypted payloads must be at least %d bytes", 24+secretbox.Overhead))
	// ErrFailedToDecrypt reports a failure to decrypt a given cipher text with a
	// given Key via Decrypt().
	ErrFailedToDecrypt = errors.New("Decryption failed")
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
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return "", err
	}

	output := secretbox.Seal(nil, []byte(s), &nonce, k.key32())
	output = append(nonce[:], output...)

	return base64.StdEncoding.EncodeToString(output), nil
}

// Decrypt takes base64-encoded cipher text encrypted with the given key and
// returns the original clear text, or an error.
func (k *Key) Decrypt(s string) (string, error) {
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("invalid decryption payload: %v", err)
	}
	if len(buf) < 24+secretbox.Overhead {
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

func rotate(data []byte) []byte {
	xor := []byte{223, 99, 111, 160, 122, 212, 223, 105, 37, 190}
	newData := make([]byte, len(data))
	copy(newData, data)
	for i := range newData {
		newData[i] = newData[i] ^ xor[i%len(xor)]
	}
	return newData
}
