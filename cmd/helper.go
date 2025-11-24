package cmd

import "strings"

var (
    dir          string
    format       string
    fileExclusion string
)

func ParseFileExclustionSuffixes(exclusion string) []string {
    if exclusion == "" {
        return []string{}
    }
    return strings.Split(exclusion, ",")
}