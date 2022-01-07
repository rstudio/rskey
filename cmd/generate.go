// Copyright 2022 RStudio, PBC
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rstudio/rskey/crypt"
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate new keys",
	Long: `Write a newly-generated RStudio Connect/Package Manager key to
standard output, or a given output file.

Examples:
  rskey generate > /var/lib/rstudio-pm/rstudio-pm.key
  rskey generate -o /var/lib/rstudio-pm/rstudio-pm.key
`,
	RunE: runGenerate,
}

func runGenerate(cmd *cobra.Command, args []string) error {
	key, err := crypt.NewKey()
	if err != nil {
		return err
	}
	s := key.HexString()
	outfile := cmd.Flag("output").Value.String()
	if outfile == "" {
		fmt.Fprintf(cmd.OutOrStdout(), s)
		return nil
	}
	err = os.WriteFile(outfile, []byte(s), 0600)
	return err
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringP("output", "o", "",
		"Write the key to this file instead")
}
