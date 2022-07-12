package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/projectdiscovery/uncover/internal/testutils"
)

var uncoverTestcases = map[string]testutils.TestCase{
	"Standard HTTP GET Request with retries": &standardHttpGet{retries: 3},
}

type standardHttpGet struct {
	retries int
}

func (h *standardHttpGet) Execute() error {
	var extra []string
	if h.retries > 0 {
		extra = append(extra, "-retries", " ", fmt.Sprint(h.retries))
	}
	URL := "https://scanme.sh/unresponsive"
	_, err := testutils.RunUncoverAndGetResults(URL, debug, extra...)
	if err != nil && strings.Contains(err.Error(), "giving up after") {
		return nil
	}
	return errors.New("expecting a timeout error")
}
