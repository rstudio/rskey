// Copyright 2022 RStudio, PBC
// SPDX-License-Identifier: Apache-2.0

package workbench

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/rstudio/rskey/crypt"
)

const (
	minKeyLength     = 32
	minPayloadLength = 8*2 + 32
)

var ErrMissingChecksum = errors.New("payload missing embedded checksums")

type Key struct {
	// A key in Workbench is just a string, traditionally a UUID literal
	// with a trailing newline. I don't think there is any guarantee that
	// std::string is UTF-8, so this is byte string for now.
	data []byte
	// The "hash" or checksum of the key is computed before we rotate the
	// key, so we just store it once when reading.
	hash string
}

// NewKeyFromBytes returns the key read from the given byte slice, or an error.
func NewKeyFromBytes(src []byte) (*Key, error) {
	size := len(src)
	if size < minKeyLength {
		// This is enforced by rstudio-server, as well.
		return nil, crypt.ErrInvalidKeyLength
	}

	// For historical reasons, we always rotate incoming data.
	xor := []byte{223, 99, 111, 160, 122, 212, 223, 105, 37, 190}
	data := make([]byte, size)
	copy(data, src)
	for i := range data {
		data[i] = data[i] ^ xor[i%len(xor)]
	}

	// This is equivalent to rstudio-server's crc32HexHash().
	checksum := fmt.Sprintf("%08X", crc32.ChecksumIEEE(src))
	return &Key{data, checksum}, nil
}

// NewKeyFromReader returns the key read from an io.Reader, or an error.
func NewKeyFromReader(src io.Reader) (*Key, error) {
	bytes, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}
	return NewKeyFromBytes(bytes)
}

func (k *Key) Encrypt(s string) (string, error) {
	// This is AES-128-CBC.
	out := make([]byte, len(s))
	copy(out, []byte(s))
	// rstudio-server actually generates an IV of length 32, which is
	// incorrect for this algorithm, but works with OpenSSL. We generate
	// only 16 bytes but match the length for use as a prefix later.
	iv := make([]byte, 32)
	if _, err := rand.Read(iv[:16]); err != nil {
		return "", err
	}
	// CBC requires that the input have a length divisible by the block size
	// (which is 16) or be padded to that length using PKCS#7 padding. This
	// padding uses the padding length itself as the padding byte, so e.g.
	// if three padding bytes need to be added the padding will be []byte{3,
	// 3, 3}.
	pad := (aes.BlockSize - len(out)%aes.BlockSize)
	if pad != 0 {
		out = append(out, bytes.Repeat([]byte{byte(pad)}, pad)...)
	}
	block, _ := aes.NewCipher(k.data[:16])
	mode := cipher.NewCBCEncrypter(block, iv[:16])
	mode.CryptBlocks(out, out)
	// The actual encrypted payload is AES-128-CBC with the IV as a prefix,
	// base64-encoded.
	encoded := base64.StdEncoding.EncodeToString(append(iv, out...))
	return k.hash + encoded + k.hash, nil
}

func (k *Key) Decrypt(s string) (string, error) {
	if len(s) < minPayloadLength {
		return "", crypt.ErrPayLoadTooShort
	}
	// The checksum is embedded in the payload -- twice.
	if s[:8] != s[len(s)-8:] {
		return "", ErrMissingChecksum
	}
	// AES-128-CBC doesn't really have a way to know if the decryption
	// failed due to an incorrect key, but we can try to guard against this
	// by verifying the checksum in the payload.
	if s[:8] != k.hash {
		return "", crypt.ErrFailedToDecrypt
	}
	buf, err := base64.StdEncoding.DecodeString(s[8 : len(s)-8])
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %v", err)
	}
	// Check that the payload seems to have survived with its padding
	// intact.
	if len(buf)%aes.BlockSize != 0 {
		return "", crypt.ErrPayLoadTooShort
	}
	// The actual encrypted payload is AES-128-CBC with the IV as a prefix.
	//
	// The original rstudio-server implementation misunderstands the
	// expected IV length as 32, not 16. It seems that OpenSSL ignores this.
	// So we have an IV of length 16, but must skip the "full length" IV
	// written by rstudio-server.
	iv := make([]byte, 16)
	copy(iv, buf[:16])
	out := make([]byte, len(buf)-32)
	copy(out, buf[32:])
	block, _ := aes.NewCipher(k.data[:16])
	mode := cipher.NewCBCDecrypter(block, iv)
	// Due to poor choices and the need to retain backwards compatibility,
	// this standard library function has no way to signal an error.
	mode.CryptBlocks(out, out)
	// Now we need to truncate the PKCS#7 padding bytes. Padding can never
	// be larger that aes.Blocksize, so we're safe to skip the length check
	// here.
	pad := int(out[len(out)-1])
	return string(out[:len(out)-pad]), nil
}
