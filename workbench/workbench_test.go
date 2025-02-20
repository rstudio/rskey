// Copyright 2022 RStudio, PBC
// SPDX-License-Identifier: Apache-2.0

package workbench

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/check.v1"
)

const (
	sampleKey  = "d3161166-e89b-4158-af3b-5980e3056cc6\n"
	sampleHash = "BFA25145"
)

// An io.Reader that always returns an error.
type errReader struct{}

// Read implements io.Reader.
func (e *errReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("cannot read")
}

type WorkbenchSuite struct{}

func (s *WorkbenchSuite) TestNewKey(c *check.C) {
	// Too short.
	_, err := NewKeyFromBytes([]byte{0x0, 0x0})
	c.Check(err, check.ErrorMatches, `Encryption keys must be.+`)

	k1, err := NewKeyFromBytes([]byte(sampleKey))
	c.Check(err, check.IsNil)
	c.Check(k1.hash, check.Equals, sampleHash)

	k2, err := NewKeyFromReader(strings.NewReader(sampleKey))
	c.Check(err, check.IsNil)
	c.Check(k2.hash, check.Equals, k1.hash)

	// Not a real UUID kids. It just looks like one.
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x\n", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])

	k3, err := NewKeyFromBytes([]byte(uuid))
	c.Check(err, check.IsNil)
	c.Check(k3.hash, check.Not(check.Equals), k1.hash)

	_, err = NewKeyFromReader(&errReader{})
	c.Check(err, check.Not(check.IsNil))
	c.Check(err, check.ErrorMatches, `cannot read`)
}

func (s *WorkbenchSuite) TestEncryption(c *check.C) {
	k, _ := NewKeyFromBytes([]byte(sampleKey))

	// A known payload.
	text, err := k.Decrypt("BFA25145OoPWwVZMdN/K7eDJUD5gLg916yildo6m+XG0+Sld7r+SuKXS3Rsi/TC0qbVZ5uCMBFA25145")
	c.Check(err, check.IsNil)
	c.Check(text, check.Equals, "success")

	// Too short.
	_, err = k.Decrypt("x")
	c.Check(err, check.ErrorMatches, `Payload is too short to be encrypted`)

	// No embedded checksum.
	_, err = k.Decrypt("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxo")
	c.Check(err, check.ErrorMatches, `payload missing embedded checksums`)

	// Wrong embedded checksum.
	_, err = k.Decrypt("BFA25146xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBFA25146")
	c.Check(err, check.ErrorMatches, `Decryption failed`)

	// Not base64.
	_, err = k.Decrypt("BFA25145xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBFA25145")
	c.Check(err, check.ErrorMatches, `failed to decode secret.+`)

	// Too short but still valid base64.
	_, err = k.Decrypt("BFA25145D75Xreg+vkkVgaFW3GOQvwzKHXUI5pOX4+2yJ5ZNJqZz7h4WEOxbeovH3GINg1E=BFA25145")
	c.Check(err, check.ErrorMatches, `Payload is too short to be encrypted`)

	// Roundtrip encryption test.
	c1, err := k.Encrypt("some secret")
	c.Check(err, check.IsNil)
	c.Check(c1, check.Not(check.Equals), "some secret") // Just checking.
	text, err = k.Decrypt(c1)
	c.Check(text, check.Equals, "some secret")

	// Check that the IVs actually work.
	c2, err := k.Encrypt("some secret")
	c.Check(err, check.IsNil)
	c.Check(c2, check.Not(check.Equals), c1)

	// A secret that's just under the block size -- i.e. the padding is
	// []byte{0x1} -- should have the same length as shorter ones.
	c2, err = k.Encrypt("some big secret")
	c.Check(err, check.IsNil)
	c.Check(len(c2), check.Equals, len(c1))

	// A longer secret should yield a longer output.
	c2, err = k.Encrypt("some very, very long secret")
	c.Check(err, check.IsNil)
	c.Check(len(c2), check.Not(check.Equals), len(c1))
}

func (s *WorkbenchSuite) TestEntropyFailure(c *check.C) {
	// Swap out the standard library's crypto reader so we can simulate a
	// failure to generate random bits.
	randReader := rand.Reader
	rand.Reader = &errReader{}
	defer func() { rand.Reader = randReader }()

	k, _ := NewKeyFromBytes([]byte(sampleKey))
	_, err := k.Encrypt("some secret")
	c.Check(err, check.Not(check.IsNil))
	c.Check(err, check.ErrorMatches, `cannot read`)
}

func (s *WorkbenchSuite) TestFingerprint(c *check.C) {
	key, err := NewKeyFromBytes([]byte(sampleKey))
	c.Check(err, check.IsNil)
	c.Check(key.Fingerprint(), check.Equals, sampleHash)
}

func Test(t *testing.T) {
	_ = check.Suite(&WorkbenchSuite{})
	check.TestingT(t)
}
