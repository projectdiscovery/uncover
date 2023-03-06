package hunterhow

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/projectdiscovery/uncover/uncover"
)

const (
	baseURL      = "https://api.hunter.how/"
	baseEndpoint = "search"
	Size         = 100
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "hunterhow"
}

func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	if session.Keys.HunterHowToken == "" {
		return nil, errors.New("empty hunterhow keys")
	}

	results := make(chan uncover.Result)

	go func() {
		defer close(results)

		numberOfResults := 0

		pageQuery := 1

		for {
			hunterhowRequest := &Request{
				Query:    query.Query,
				PageSize: query.Limit,
				Page:     pageQuery,
			}

			if numberOfResults > query.Limit {
				break
			}

			hunterhowResponse := agent.query(hunterhowRequest.buildURL(session.Keys.HunterHowToken), session, results)
			if hunterhowResponse == nil {
				break
			}

			if len(hunterhowResponse) == 0 {
				break
			}

			numberOfResults += len(hunterhowResponse)
			pageQuery += 1
		}
	}()

	return results, nil
}

func (agent *Agent) query(URL string, session *uncover.Session, results chan uncover.Result) []string {
	resp, err := agent.queryURL(session, URL)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}

	var apiResponse Response
	err = json.NewDecoder(resp.Body).Decode(&apiResponse)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	if apiResponse.Code != 200 {
		results <- uncover.Result{Source: agent.Name(), Error: errors.New(apiResponse.Message)}
		return nil
	}

	var lines []string
	for _, data := range apiResponse.Data.List {
		result := uncover.Result{Source: agent.Name()}
		result.Host = data.Domain
		result.IP = data.IP
		result.Port = data.Port
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
		lines = append(lines, data.Domain)
	}

	return lines
}

func (agent *Agent) queryURL(session *uncover.Session, URL string) (*http.Response, error) {
	request, err := uncover.NewHTTPRequest(
		http.MethodGet,
		URL,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}
