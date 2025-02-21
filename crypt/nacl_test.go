// Copyright 2025 Posit Software, PBC
// SPDX-License-Identifier: Apache-2.0

//go:build !fips
// +build !fips

package crypt

import "gopkg.in/check.v1"

func (s *KeySuite) TestFIPSMode(c *check.C) {
	c.Check(FIPSMode, check.Equals, false)
}
