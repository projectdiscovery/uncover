package binaryedge

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL  = "https://api.binaryedge.io/v2/query/ip/%s"
	Size = 100
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "binaryedge"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.BinaryEdgeToken == "" {
		return nil, errors.New("empty binaryedge keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		binaryedgeURL := fmt.Sprintf(URL, query.Query)
		request, err := sources.NewHTTPRequest(http.MethodGet, binaryedgeURL, nil)
		if err != nil {
			results <- sources.Result{Source: agent.Name(), Error: err}
			return
		}
		request.Header.Set("X-Key", session.Keys.BinaryEdgeToken)

		resp, err := session.Do(request, agent.Name())
		if err != nil {
			results <- sources.Result{Source: agent.Name(), Error: err}
			return
		}
		defer resp.Body.Close()

		var apiResponse BinaryedgeResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
			results <- sources.Result{Source: agent.Name(), Error: err}
			return
		}

		for _, event := range apiResponse.Events {
			for _, result := range event.Results {
				output := sources.Result{Source: agent.Name()}
				output.IP = result.Target.IP
				output.Port = result.Target.Port

				// Include raw JSON data
				raw, err := json.Marshal(result)
				if err == nil {
					output.Raw = raw
				}

				results <- output
			}
		}
	}()

	return results, nil
}

func (agent *Agent) query(URL string, session *sources.Session, query string, results chan sources.Result) {
	resp, err := agent.queryURL(session, URL, query)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return
	}
	defer resp.Body.Close()

	var apiResponse BinaryedgeResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return
	}

	for _, event := range apiResponse.Events {
		for _, result := range event.Results {
			output := sources.Result{Source: agent.Name()}
			output.IP = result.Target.IP
			output.Port = result.Target.Port

			if raw, err := json.Marshal(result); err == nil {
				output.Raw = raw
			}

			results <- output
		}
	}
}

func (agent *Agent) queryURL(session *sources.Session, URL string, query string) (*http.Response, error) {
	binaryedgeURL := fmt.Sprintf(URL, url.QueryEscape(query))
	request, err := sources.NewHTTPRequest(http.MethodGet, binaryedgeURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Key", session.Keys.BinaryEdgeToken)
	return session.Do(request, agent.Name())
}
