package main

import (
	"fmt"

	"github.com/projectdiscovery/uncover/testutils"
)

type censysTestcases struct{}

func (h censysTestcases) Execute() error {
	// token := os.Getenv("DNSREPO_API_KEY")
	// if token == "" {
	// 	return errors.New("missing dns repo api key")
	// }
	// dnsToken := fmt.Sprintf(`dnsrepo: [%s]`, token)
	// file, err := os.CreateTemp("", "provider.yaml")
	// if err != nil {
	// 	return err
	// }
	// defer os.RemoveAll(file.Name())
	// _, err = file.WriteString(dnsToken)
	// if err != nil {
	// 	return err
	// }
	results, err := testutils.RunUncoverAndGetResults(debug, "-censys", "'services.software.vendor=Grafana'")
	if err != nil {
		return err
	}
	return expectResultsGreaterThanCount(results, 0)
}

type shodanTestcases struct{}

func (h shodanTestcases) Execute() error {
	results, err := testutils.RunUncoverAndGetResults(debug, "-shodan", "'title:\"Grafana\"'")
	if err != nil {
		return err
	}
	return expectResultsGreaterThanCount(results, 0)
}

type zoomeyeTestcases struct{}

func (h zoomeyeTestcases) Execute() error {
	results, err := testutils.RunUncoverAndGetResults(debug, "-zoomeye", "'title:\"gogs\"'")
	if err != nil {
		return err
	}
	fmt.Println(results)
	return expectResultsGreaterThanCount(results, 0)
}

type fofaTestcases struct{}

func (h fofaTestcases) Execute() error {
	results, err := testutils.RunUncoverAndGetResults(debug, "-fofa", "'app=Grafana'")
	if err != nil {
		return err
	}
	return expectResultsGreaterThanCount(results, 0)
}

type hunterTestcases struct{}

func (h hunterTestcases) Execute() error {
	results, err := testutils.RunUncoverAndGetResults(debug, "-hunter", "'Grafana'")
	if err != nil {
		return err
	}
	return expectResultsGreaterThanCount(results, 0)
}

type quakeTestcases struct{}

func (h quakeTestcases) Execute() error {
	results, err := testutils.RunUncoverAndGetResults(debug, "-quake", "'Grafana'")
	if err != nil {
		return err
	}
	return expectResultsGreaterThanCount(results, 0)
}
