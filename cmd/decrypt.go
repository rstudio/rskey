// Copyright 2025 Posit Software, PBC
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

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt previously-decrypted data",
	Long: `Use a Posit Connect/Package Manager key to decrypt data passed on
standard input.

Examples:
  echo "G8QSoVOR936MjjMdjFqvXYqM+m1zwH0H/aX0fO5RGg0logwPOhME0Wz0sp9g4fMtYdw=" | \
    rskey decrypt -f /var/lib/rstudio-pm/rstudio-pm.key
`,
	RunE: runDecrypt,
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	keyfile := cmd.Flag("keyfile").Value.String()
	if keyfile == "" {
		return fmt.Errorf("keyfile is missing but must be provided")
	}
	f, err := os.Open(keyfile)
	if err != nil {
		return err
	}
	defer f.Close()
	var decrypt func(string) (string, error)
	switch cmd.Flag("mode").Value.String() {
	case "workbench":
		key, err := workbench.NewKeyFromReader(f)
		if err != nil {
			return err
		}
		decrypt = key.Decrypt
	default:
		key, err := crypt.NewKeyFromReader(f)
		if err != nil {
			return err
		}
		decrypt = key.Decrypt
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
			cipher, err := decrypt(scanner.Text())
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
		return term.NewTerminal(
			os.Stdin,
			"Type the sensitive data to decrypt, then press Enter: ",
		).ReadLine()
	}()
	if err != nil {
		return err
	}
	cipher, err := decrypt(data)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", cipher)
	return err
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringP("keyfile", "f", "", "Use the given key file")
	decryptCmd.Flags().StringP("mode", "", "default",
		`One of "default" or "workbench"`)
}
