package cmd

import (
	"fmt"
	"strings"

	"github.com/daffashafwan/gebrun/internal/explain"
	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
    Use:   "explain",
    Short: "Explain Go code and print detailed analysis with storytelling",
    Run: func(cmd *cobra.Command, args []string) {
        fileExclusionSuffixes := ParseFileExclustionSuffixes(fileExclusion)
        res := explain.QuickParseAndPrint(dir, fileExclusionSuffixes)

        switch strings.ToLower(format) {
        case "text":
            explain.PrintStoryText(res)
        case "json":
            explain.PrintStoryJSON(res)
        case "plantuml":
            explain.PrintStoryPlantUML(res)
        case "html":
            explain.PrintStoryHTML(res, "gebrun_explain_report.html")
        default:
            fmt.Printf("Unknown format: %s\n", format)
        }
    },
}

func init() {
    explainCmd.Flags().StringVarP(&dir, "expDir", "expD", ".", "Root directory to scan")
    explainCmd.Flags().StringVarP(&format, "expformat", "expF", "text", "Output format: text|json|plantuml|html")
    explainCmd.Flags().StringVarP(&fileExclusion, "expExclude", "expE", "", "File patterns to exclude from analysis, separated by comma (e.g., _test.go,generated.go)")
}