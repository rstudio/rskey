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

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt sensitive data",
	Long: `Use a RStudio Connect/Package Manager key to encrypt data passed on
standard input.

Examples:
  echo "mypassword" | rskey encrypt -f /var/lib/rstudio-pm/rstudio-pm.key
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
		cipher, err := key.Encrypt(scanner.Text())
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", cipher)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringP("keyfile", "f", "", "Use the given key file")
}
