package crypt

import (
	"encoding/hex"
	"strings"
	"testing"

	"gopkg.in/check.v1"
)

const (
	sampleKey      = "e9cc6376f72e4556b51b0a2c9627a87a847cdae52133021531e99aa9d2dedd532aed45c82b2b191d6e8cdb88c125740db3bac3ac79f7bfbe0f1885846254f8fd4322baa52085a26111fbf546cb52502e9f160209db0134674b02ed6373d56885fc75ecb5115077799c26f21960c68968b25310a792e5fb4a7405ed217da5927e21348605f11d71466d1ef31c66c7a86fa7eed0f5e40b9e7898e3adf7c784de79d5aea324ad01ba1c67d0279ba80860878631bf1bac74761e9ebb816d2010cb669143084fe0aaabdb3893f13f335cfa585aa3abc774cbcfa5e3de4d030a9162f533ec04cd3a9e02f09c8dec5ffdae5eafdb55d13882d9d03bda4c61aea22eaf75c1ea9f8600e128427e8187df0f42cb55b07aae4669bf53f8b5e8a0d6180902d58d9fba34261b0cabbfd53f5f4c4936814726b5d853a4d888b6b3abc8b49ba1c6f662a61bcb0fb0b3daa2065ffca839d56887532ff8b2a8441a2daaf8ff7f84e29f485d69f3643ef2c68540bb16ea2fa5e332845da42e154d5556ebc9629d531c9314bf8fc8c59682386c39b6249f1cc74f8254b2dfd45717d9658a2ac69c39daf1c24188b713c49f83b32ddf76e1f47ecd2aee3f37bb1ea28ebe4a5e0254785735eb2ef2ce64abde61c348df7849f00526d973b8b26c9161aca39ea177f6c02dc382d56126f83bb10b3fcab6fc8863f28465e41188609335788a7901aeeb2d1d"
	sampleKeyBytes = "36af0cd68dfa9a3f90a5d54ff987d2ae5b15ff5bfe506db54b3d45c0f7600230454d3f1cf4423ca3b1efb428bbf1ab6496041ccf1657c56ad071a03abd37975d39f665cc053b7d027e5b8f92143b759040756da9a1d5eb0e6ebc32001c751251231cc90bce3318d9e6f22d704578560bddf36a734d8cdef4ab66828107714d17048a59669ebd0b92b277d6a2b9a4c7cfdd3a0f9cc1b5411bf743d72318edfbc70acdcc84d7d56575426ef8f8c7a81a5359589aa5731719bee46f5e0405ae1405fee3729b3fc38e65e7f09e9f498825317f1d74a41b6bb5713cb768bdd5f20d554938dba41f20dd93f32d968b22c77b110436be98f80d0f52fff2becdcd8ed5a11e83ba38df8247e2045558b62afc1436dfdad492b6d676466a8bcf7662ddddbca821655749bb767f60bc1ae1932a59213df26ab1761a07ebd913d11c6bf284782901c9bbb1db6fdaff1cd93c93084301b7ee769127d1c7e460f97591dac15b81f0e827bd2c0d1b4c19e62f1b6c3ef0ccc68c5b3ecb8e6f998a3fce77bdfe3cbce9c060e6ed7b49e157cc4362fbf6397990e13b12a500887efcdb5549a93c430e2eab64366870ab3ff967f2b6535f2b1da28a94ebe8d23b1c51dd25fe7880a73e1055f191a1c4d10abeaa6d61a72a9fa55c0dacd197d24e02c303e475a89fe5931ce1bac15c2ce4d82e8115d5932819265b0cc1af5703fc95025ea6688b55f27e"
)

type KeySuite struct{}

func (s *KeySuite) TestNewKey(c *check.C) {
	_, err := NewKeyFromBytes([]byte("not hex"))
	c.Check(err, check.Not(check.IsNil))
	c.Check(err, check.ErrorMatches, `failed to decode secret: encoding\/hex.+`)

	_, err = NewKeyFromBytes([]byte(sampleKey[0:32]))
	c.Check(err, check.Equals, ErrInvalidKeyLength)

	key, err := NewKeyFromBytes([]byte(sampleKey))
	c.Check(err, check.IsNil)
	c.Check(key, check.Not(check.IsNil))

	newKey, err := NewKey()
	c.Check(err, check.IsNil)
	c.Check(newKey, check.Not(check.IsNil))
	// A new key should actually be different.
	c.Check(newKey, check.Not(check.DeepEquals), key)

	newKey, err = NewKeyFromReader(strings.NewReader(sampleKey))
	c.Check(err, check.IsNil)
	c.Check(key, check.Not(check.IsNil))
	// The io.Reader implementation should match the byte one.
	c.Check(newKey, check.DeepEquals, key)
}

func (s *KeySuite) TestKeyRotation(c *check.C) {
	key, _ := NewKeyFromBytes([]byte(sampleKey))
	// Writing out the key should yield the original sample.
	c.Check(key.HexString(), check.DeepEquals, sampleKey)

	// Construct the Key byte array manually.
	var rawKey Key
	raw, _ := hex.DecodeString(sampleKeyBytes)
	copy(rawKey[0:KeyLength], raw[:])
	c.Check(&rawKey, check.DeepEquals, key)

	// Writing out the raw key should yield the original (unrotated) sample.
	c.Check(rawKey.HexString(), check.DeepEquals, sampleKey)
}

func (s *KeySuite) TestEncryption(c *check.C) {
	// Don't use a preset key; treat it as a black box.
	key, _ := NewKey()

	_, err := key.Decrypt("not base64")
	c.Check(err, check.ErrorMatches, `invalid decryption payload.+`)

	_, err = key.Decrypt("ycKfTfYlVaOnsypb")
	c.Check(err, check.Equals, ErrPayLoadTooShort)

	// A payload encrypted with some other key should always fail.
	_, err = key.Decrypt("xzWzNpN3o5cMv9WYeHQSGt9ZPMrV5UzONRHDuM2v4gXp4/Q2BH5jugWZDmuHJdUVkrY8")
	c.Check(err, check.Equals, ErrFailedToDecrypt)

	// Roundtrip encryption test.
	cipher, err := key.Encrypt("some secret")
	c.Check(err, check.IsNil)
	text, err := key.Decrypt(cipher)
	c.Check(text, check.Equals, "some secret")
}

func Test(t *testing.T) {
	_ = check.Suite(&KeySuite{})
	check.TestingT(t)
}
