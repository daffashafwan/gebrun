package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/daffashafwan/gebrun/internal/analyzer"

	"github.com/spf13/cobra"
)

var (
    dir          string
    format       string
    fileExclusion string
)

var analyzeCmd = &cobra.Command{
    Use:   "analyze",
    Short: "Analyze Go code and print arithmetic operations + call graph",
    Run: func(cmd *cobra.Command, args []string) {
        fileExclusionSuffixes := parseFileExclustionSuffixes(fileExclusion)
        res, err := analyzer.ParseAndCollect(dir, fileExclusionSuffixes)
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
        case "groupedtable":
            analyzer.PrintTableChained(res)
        case "html":
            analyzer.PrintTableHTMLGrouped(res, "gebrun_report.html")
        default:
            fmt.Printf("Unknown format: %s\n", format)
        }
    },
}

func init() {
    analyzeCmd.Flags().StringVarP(&dir, "dir", "d", ".", "Root directory to scan")
    analyzeCmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table|groupedtable|json|plantuml|html")
    analyzeCmd.Flags().StringVarP(&fileExclusion, "exclude", "e", "", "File patterns to exclude from analysis, separated by comma (e.g., _test.go,generated.go)")
}

func parseFileExclustionSuffixes(exclusion string) []string {
    if exclusion == "" {
        return []string{}
    }
    return strings.Split(exclusion, ",")
}