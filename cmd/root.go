package cmd

import (
    "fmt"
    "os"

    "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
    Use:   "gebrun",
    Short: "Gebrun is your arithmetic flow detective",
    Long:  "Scan Go code, trace arithmetic operations, and build call graphs.",
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

func init() {
    rootCmd.AddCommand(analyzeCmd)
    rootCmd.AddCommand(versionCmd)
    rootCmd.AddCommand(explainCmd)
}
