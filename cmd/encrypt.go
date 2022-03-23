// Copyright 2022 RStudio, PBC
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bufio"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/rstudio/rskey/crypt"
	"github.com/rstudio/rskey/workbench"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt sensitive data",
	Long: `Use a RStudio Connect/Package Manager key to encrypt data
interactively. Line-separated data can also be passed on standard input.

Examples:
  rskey encrypt -f /var/lib/rstudio-pm/rstudio-pm.key
  cat passwords.txt | rskey encrypt -f /var/lib/rstudio-pm/rstudio-pm.key
`,
	RunE: runEncrypt,
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	keyfile := cmd.Flag("keyfile").Value.String()
	if keyfile == "" {
		return fmt.Errorf("keyfile is missing but must be provided")
	}
	f, err := os.Open(keyfile)
	if err != nil {
		return err
	}
	defer f.Close()
	var encrypt func(string) (string, error)
	switch cmd.Flag("mode").Value.String() {
	case "workbench":
		key, err := workbench.NewKeyFromReader(f)
		if err != nil {
			return err
		}
		encrypt = key.Encrypt
	default:
		key, err := crypt.NewKeyFromReader(f)
		if err != nil {
			return err
		}
		encrypt = key.Encrypt
	}
	// Check if there's actually data in standard input.
	info, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	// Accept line-separated entries on standard input.
	if info.Mode()&os.ModeNamedPipe != 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			cipher, err := encrypt(scanner.Text())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", cipher)
			if err != nil {
				return err
			}
		}
		return nil
	}
	// Temporarily put the terminal into raw mode so we can read data
	// without echo.
	data, err := func() (string, error) {
		s, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		defer term.Restore(int(os.Stdin.Fd()), s)
		return term.NewTerminal(os.Stdin, "").ReadPassword(
			"Type the sensitive data to encrypt, then press Enter: ")
	}()
	if err != nil {
		return err
	}
	cipher, err := encrypt(data)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", cipher)
	return err
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringP("keyfile", "f", "", "Use the given key file")
	encryptCmd.Flags().StringP("mode", "", "default",
		`One of "default" or "workbench"`)
}
