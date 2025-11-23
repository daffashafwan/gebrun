package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/daffashafwan/gebrun/internal/analyzer"

	"github.com/spf13/cobra"
)

var (
    dir    string
    format string
)

var analyzeCmd = &cobra.Command{
    Use:   "analyze",
    Short: "Analyze Go code and print arithmetic operations + call graph",
    Run: func(cmd *cobra.Command, args []string) {
        res, err := analyzer.ParseAndCollectGreedy(dir)
        if err != nil {
            log.Fatal(err)
        }

        switch strings.ToLower(format) {
        case "table":
            analyzer.PrintTable(res)
        case "json":
            analyzer.PrintJSON(res)
        case "plantuml":
            analyzer.PrintPlantUML(res)
        default:
            fmt.Printf("Unknown format: %s\n", format)
        }
    },
}

func init() {
    analyzeCmd.Flags().StringVarP(&dir, "dir", "d", ".", "Root directory to scan")
    analyzeCmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table|json|plantuml")
}
