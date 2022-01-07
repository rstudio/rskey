/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "rskey",
	Short: "Manage keys and secrets for RStudio Connect and Package Manager",
}

// Execute runs the rskey command. On error it will call os.Exit.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
