package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/uncover/internal/testutils"
)

var (
	customTest = os.Getenv("TEST")
	protocol   = os.Getenv("PROTO")

	errored = false
)

func main() {
	success := aurora.Green("[✓]").String()
	failed := aurora.Red("[✘]").String()

	tests := map[string]map[string]testutils.TestCase{
		"uncover": uncoverTestcases,
	}
	for proto, tests := range tests {
		if protocol == "" || protocol == proto {
			fmt.Printf("Running test cases for \"%s\"\n", aurora.Blue(proto))

			for name, test := range tests {
				if customTest != "" && !strings.Contains(name, customTest) {
					continue // only run tests user asked
				}
				err := test.Execute()
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, name, err)
					errored = true
				} else {
					fmt.Printf("%s Test \"%s\" passed!\n", success, name)
				}
			}
		}
	}
	if errored {
		os.Exit(1)
	}
}
