// Copyright 2022 RStudio, PBC
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	Version = "???"
)

var rootCmd = &cobra.Command{
	Use:     "rskey",
	Short:   "Manage keys and secrets for RStudio Connect and Package Manager",
	Version: Version,
}

// Execute runs the rskey command. On error it will call os.Exit.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
