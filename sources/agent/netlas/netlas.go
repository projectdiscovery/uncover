package netlas

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	baseURL      = "https://app.netlas.io/"
	baseEndpoint = "api/responses/"
	contentType  = "application/json"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "netlas"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.NetlasToken == "" {
		return nil, errors.New("empty netlas keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		numberOfResults := 0

		for {
			netlasRequest := &Request{
				Query: query.Query,
				Start: numberOfResults,
			}

			netlasResponse := agent.query(netlasRequest.buildURL(), session, results)
			if netlasResponse == nil {
				break
			}

			if numberOfResults > query.Limit || len(netlasResponse.Items) == 0 {
				break
			}

			numberOfResults += len(netlasResponse.Items)
		}
	}()

	return results, nil
}

func (agent *Agent) query(URL string, session *sources.Session, results chan sources.Result) *Response {
	resp, err := agent.queryURL(session, URL)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	netlasResponse := &Response{}
	if err := json.NewDecoder(resp.Body).Decode(netlasResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	for _, netlasResult := range netlasResponse.Items {
		result := sources.Result{Source: agent.Name()}
		result.IP = netlasResult.Data.IP
		result.Port = netlasResult.Data.Port
		result.Host = netlasResult.Data.Host
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}

	return netlasResponse
}

func (agent *Agent) queryURL(session *sources.Session, URL string) (*http.Response, error) {
	request, err := sources.NewHTTPRequest(
		http.MethodGet,
		URL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-API-Key", session.Keys.NetlasToken)
	return session.Do(request, agent.Name())
}
