// Copyright 2025 Posit Software, PBC
// SPDX-License-Identifier: Apache-2.0

//go:build fips
// +build fips

package crypt

// When true, this package has been built in "FIPS mode". Attempts to use
// encryption algorithms not permissible under FIPS-140 regulations will always
// fail, and encryption will use AES-256-GCM by default.
const FIPSMode = true

func (k *Key) encryptSecretbox(bytes []byte) ([]byte, error) {
	return []byte{}, ErrFIPS
}

func (k *Key) decryptSecretbox(buf []byte) ([]byte, error) {
	return []byte{}, ErrFIPS
}
