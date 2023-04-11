package shodan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"errors"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL = "https://api.shodan.io/shodan/host/search?key=%s&query=%s&page=%d"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "shodan"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.Shodan == "" {
		return nil, errors.New("empty shodan keys")
	}
	results := make(chan sources.Result)

	go func() {
		defer close(results)

		currentPage := 1
		var numberOfResults, totalResults int
		for {
			shodanRequest := &ShodanRequest{
				Query: query.Query,
				Page:  currentPage,
			}

			shodanResponse := agent.query(URL, session, shodanRequest, results)
			if shodanResponse == nil {
				break
			}
			currentPage++
			numberOfResults += len(shodanResponse.Results)
			if totalResults == 0 {
				totalResults = shodanResponse.Total
			}

			// query certificates
			if numberOfResults > query.Limit || numberOfResults > totalResults || len(shodanResponse.Results) == 0 {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, shodanRequest *ShodanRequest) (*http.Response, error) {
	shodanURL := fmt.Sprintf(URL, session.Keys.Shodan, url.QueryEscape(shodanRequest.Query), shodanRequest.Page)
	request, err := sources.NewHTTPRequest(http.MethodGet, shodanURL, nil)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, shodanRequest *ShodanRequest, results chan sources.Result) *ShodanResponse {
	// query certificates
	resp, err := agent.queryURL(session, URL, shodanRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	shodanResponse := &ShodanResponse{}
	if err := json.NewDecoder(resp.Body).Decode(shodanResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	for _, shodanResult := range shodanResponse.Results {
		result := sources.Result{Source: agent.Name()}
		if port, ok := shodanResult["port"]; ok {
			result.Port = int(port.(float64))
		}
		if ip, ok := shodanResult["ip_str"]; ok {
			result.IP = ip.(string)
		}
		// has hostnames?
		if hostnames, ok := shodanResult["hostnames"]; ok {
			if _, ok := hostnames.([]interface{}); ok {
				for _, hostname := range hostnames.([]interface{}) {
					result.Host = fmt.Sprint(hostname)
				}
			}
			raw, _ := json.Marshal(shodanResult)
			result.Raw = raw
			results <- result
		} else {
			raw, _ := json.Marshal(shodanResult)
			result.Raw = raw
			// only ip
			results <- result
		}
	}

	return shodanResponse
}

type ShodanRequest struct {
	Query string
	Page  int
}
