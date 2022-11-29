package netlas

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/projectdiscovery/uncover/uncover"
)

const (
	baseURL      = "https://app.netlas.io/"
	baseEndpoint = "api/responses/"
	contentType  = "application/json"
)

type Agent struct {
	options *uncover.AgentOptions
}

func New() (uncover.Agent, error) {
	return &Agent{}, nil
}

func NewWithOptions(options *uncover.AgentOptions) (uncover.Agent, error) {
	return &Agent{options: options}, nil
}

func (agent *Agent) Name() string {
	return "netlas"
}

func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	if session.Keys.NetlasToken == "" {
		return nil, errors.New("empty netlas keys")
	}

	results := make(chan uncover.Result)

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

func (agent *Agent) query(URL string, session *uncover.Session, results chan uncover.Result) *Response {
	resp, err := agent.queryURL(session, URL)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}

	netlasResponse := &Response{}
	if err := json.NewDecoder(resp.Body).Decode(netlasResponse); err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}

	for _, netlasResult := range netlasResponse.Items {
		result := uncover.Result{Source: agent.Name()}
		result.IP = netlasResult.Data.IP
		result.Port = netlasResult.Data.Port
		result.Host = netlasResult.Data.Host
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}

	return netlasResponse
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

	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-API-Key", session.Keys.NetlasToken)

	agent.options.RateLimiter.Take()
	return session.Do(request)
}
