package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/folderutil"
	"github.com/projectdiscovery/uncover/testutils"
)

var (
	ConfigFile = filepath.Join(folderutil.HomeDirOrDefault("."), ".config/uncover/provider-config.yaml")
)

type censysTestcases struct{}

func (h censysTestcases) Execute() error {
	token := os.Getenv("CENSYS_API_KEY")
	if token == "" {
		return errors.New("missing censys api key")
	}
	censysToken := fmt.Sprintf(`censys: [%s]`, token)
	fmt.Println(censysToken)
	_ =ioutil.WriteFile(ConfigFile, []byte(censysToken), 0644)
	defer os.RemoveAll(ConfigFile)
	results, err := testutils.RunUncoverAndGetResults(debug, "-censys", "'services.software.vendor=Grafana'")
	if err != nil {
		return err
	}
	return expectResultsGreaterThanCount(results, 0)
}

type shodanTestcases struct{}

func (h shodanTestcases) Execute() error {
	token := os.Getenv("SHODAN_API_KEY")
	if token == "" {
		return errors.New("missing shodan api key")
	}
	shodanToken := fmt.Sprintf(`shodan: [%s]`, token)
	_ =ioutil.WriteFile(ConfigFile, []byte(shodanToken), 0644)
	defer os.RemoveAll(ConfigFile)
	results, err := testutils.RunUncoverAndGetResults(debug, "-shodan", "'title:\"Grafana\"'")
	if err != nil {
		return err
	}
	return expectResultsGreaterThanCount(results, 0)
}

type zoomeyeTestcases struct{}

func (h zoomeyeTestcases) Execute() error {
	token := os.Getenv("ZOOMEYE_API_KEY")
	if token == "" {
		return errors.New("missing shodan api key")
	}
	zoomeyeToken := fmt.Sprintf(`zoomeye: [%s]`, token)
	_ =ioutil.WriteFile(ConfigFile, []byte(zoomeyeToken), 0644)
	defer os.RemoveAll(ConfigFile)
	results, err := testutils.RunUncoverAndGetResults(debug, "-zoomeye", "'title:\"gogs\"'")
	if err != nil {
		return err
	}
	fmt.Println(results)
	return expectResultsGreaterThanCount(results, 0)
}

type fofaTestcases struct{}

func (h fofaTestcases) Execute() error {
	token := os.Getenv("FOFA_API_KEY")
	if token == "" {
		return errors.New("missing fofa api key")
	}
	fofaToken := fmt.Sprintf(`fofa: [%s]`, token)
	_ =ioutil.WriteFile(ConfigFile, []byte(fofaToken), 0644)
	defer os.RemoveAll(ConfigFile)
	results, err := testutils.RunUncoverAndGetResults(debug, "-fofa", "'app=Grafana'")
	if err != nil {
		return err
	}
	return expectResultsGreaterThanCount(results, 0)
}

// type hunterTestcases struct{}

// func (h hunterTestcases) Execute() error {
// 	results, err := testutils.RunUncoverAndGetResults(debug, "-hunter", "'Grafana'")
// 	if err != nil {
// 		return err
// 	}
// 	return expectResultsGreaterThanCount(results, 0)
// }

type quakeTestcases struct{}

func (h quakeTestcases) Execute() error {
	token := os.Getenv("QUAKE_API_KEY")
	if token == "" {
		return errors.New("missing quake api key")
	}
	quakeToken := fmt.Sprintf(`quake: [%s]`, token)
	_ =ioutil.WriteFile(ConfigFile, []byte(quakeToken), 0644)
	defer os.RemoveAll(ConfigFile)
	results, err := testutils.RunUncoverAndGetResults(debug, "-quake", "'Grafana'")
	if err != nil {
		return err
	}
	return expectResultsGreaterThanCount(results, 0)
}
