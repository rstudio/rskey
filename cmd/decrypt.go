/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"bufio"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rstudio/rskey/crypt"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt previously-decrypted data",
	Long: `Use a RStudio Connect/Package Manager key to decrypt data passed on
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
	key, err := crypt.NewKeyFromReader(f)
	if err != nil {
		return err
	}
	// Check if there's actually data in standard input.
	info, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return fmt.Errorf("No input")
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cipher, err := key.Decrypt(scanner.Text())
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", cipher)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringP("keyfile", "f", "", "Use the given key file")
}
