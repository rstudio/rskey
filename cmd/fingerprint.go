// Copyright 2025 Posit Software, PBC
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rstudio/rskey/crypt"
	"github.com/rstudio/rskey/workbench"
)

var fingerprintCmd = &cobra.Command{
	Use:     "fingerprint",
	Aliases: []string{"fp"},
	Short:   "Print fingerprint for a key",
	Long: `Print a short fingerprint for a Posit Connect/Package Manager/Workbench key.

The fingerprint is a short, consistent identifier and is useful for
identifying keys (e.g. to track which keys are currently in use on a Posit
Connect/Package Manager server), but is not secure or appropriate for
cryptographic use.

Examples:
  rskey fingerprint -f /var/lib/rstudio-pm/rstudio-pm.key
  rskey fingerprint --mode=workbench -f /etc/rstudio/secure-cookie-key
`,
	RunE: runFingerprint,
}

func runFingerprint(cmd *cobra.Command, args []string) error {
	keyfile := cmd.Flag("keyfile").Value.String()
	if keyfile == "" {
		return fmt.Errorf("keyfile is missing but must be provided")
	}
	f, err := os.Open(keyfile)
	if err != nil {
		return err
	}
	defer f.Close()
	var fingerprint func() string
	switch cmd.Flag("mode").Value.String() {
	case "workbench":
		key, err := workbench.NewKeyFromReader(f)
		if err != nil {
			return err
		}
		fingerprint = key.Fingerprint
	default:
		key, err := crypt.NewKeyFromReader(f)
		if err != nil {
			return err
		}
		fingerprint = key.Fingerprint
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", fingerprint())
	return err
}

func init() {
	rootCmd.AddCommand(fingerprintCmd)
	fingerprintCmd.Flags().StringP("keyfile", "f", "", "Use the given key file")
	fingerprintCmd.Flags().StringP("mode", "", "default",
		`"default" or "workbench"`)
}
