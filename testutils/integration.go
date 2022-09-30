package testutils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func RunUncoverAndGetResults(debug bool, agent string, extra ...string) ([]string, error) {
	cmd := exec.Command("bash", "-c")
	cmdLine := fmt.Sprintf("%s %s ", "./uncover", agent)
	cmdLine += strings.Join(extra, " ")
	cmd.Args = append(cmd.Args, cmdLine)
	fmt.Println(cmd.Args)
	if debug {
		cmd.Args = append(cmd.Args, "-v")
		cmd.Stderr = os.Stderr
		fmt.Println(cmd.String())
	} else {
		cmd.Args = append(cmd.Args, "-silent")
	}
	data, err := cmd.Output()
	if debug {
		fmt.Println(string(data))
	}
	if err != nil {
		return nil, err
	}
	var parts []string
	items := strings.Split(string(data), "\n")
	for _, i := range items {
		if i != "" {
			parts = append(parts, i)
		}
	}
	return parts, nil
}

// TestCase is a single integration test case
type TestCase interface {
	Execute() error
}
