package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/uncover/testutils"
)

var (
	debug        = os.Getenv("DEBUG") == "true"
	githubAction = os.Getenv("GH_ACTION") == "true"
	customTests  = os.Getenv("TESTS")

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	tests = map[string]testutils.TestCase{
		// source tests
		"censys":  censysTestcases{},
		"shodan":  shodanTestcases{},
		"zoomeye": zoomeyeTestcases{},
		"fofa":    fofaTestcases{},
		//"hunter":  hunterTestcases{},
		"quake":      quakeTestcases{},
		"netlas":     netlasTestcases{},
		"criminalip": criminalipTestcases{},
		"hunterhow":  hunterhowTestcases{},
		// feature tests
		"output": outputTestcases{},
	}
)

func main() {
	failedTestCases := runTests(toSlice(customTests))

	if len(failedTestCases) > 0 {
		if githubAction {
			debug = true
			fmt.Println("\n::group::Failed integration tests in debug mode")
			_ = runTests(failedTestCases)
			fmt.Println("::endgroup::")
		}
		os.Exit(1)
	}
}

func runTests(customTests []string) []string {
	if len(customTests) == 0 {
		customTests = make([]string, 0, len(tests))
		for test := range tests {
			customTests = append(customTests, test)
		}
	}

	failedTestCases := []string{}
	for _, test := range customTests {
		fmt.Printf("Running test cases for \"%s\"\n", aurora.Blue(test))
		if failedTest, err := execute(test, tests[test]); err != nil {
			failedTestCases = append(failedTestCases, failedTest)
		}
	}
	return failedTestCases
}

func execute(test string, testCase testutils.TestCase) (string, error) {
	if err := testCase.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, test, err)
		return test, err
	}

	fmt.Printf("%s Test \"%s\" passed!\n", success, test)
	return "", nil
}

func expectResultsGreaterThanCount(results []string, expectedNumber int) error {
	if len(results) > expectedNumber {
		return nil
	}
	return fmt.Errorf("incorrect number of results: expected a result greater than %d,but got %d", expectedNumber, len(results))
}

func toSlice(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}

	return strings.Split(value, ",")
}
