package binaryedge

import (
	"context"
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

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.BinaryEdgeToken == "" {
		return nil, errors.New("empty binaryedge token")
	}

	results := make(chan sources.Result)
	go func() {
		defer close(results)
		agent.query(ctx, session, query.Query, results)
	}()

	return results, nil
}

func (agent *Agent) query(ctx context.Context, session *sources.Session, searchQuery string, results chan sources.Result) {
	resp, err := agent.queryURL(ctx, session, URL, searchQuery)
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var apiResponse BinaryedgeResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return
	}

	for _, event := range apiResponse.Events {
		for _, item := range event.Results {
			output := sources.Result{
				Source: agent.Name(),
				IP:     item.Target.IP,
				Port:   item.Target.Port,
			}
			if raw, err := json.Marshal(item); err == nil {
				output.Raw = raw
			}
			if !sources.SendResult(ctx, results, output) {
				return
			}
		}
	}
}

func (agent *Agent) queryURL(ctx context.Context, session *sources.Session, baseURL, searchQuery string) (*http.Response, error) {
	urlWithQuery := fmt.Sprintf(baseURL, url.QueryEscape(searchQuery))
	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, urlWithQuery, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Key", session.Keys.BinaryEdgeToken)
	return session.Do(request, agent.Name())
}
