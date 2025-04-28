package onyphe

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL  = "https://www.onyphe.io/api/v2/search/?q=%s"
	Size = 100
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "onyphe"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.OnypheKey == "" {
		return nil, errors.New("empty onyphe key")
	}

	results := make(chan sources.Result)
	go func() {
		defer close(results)
		agent.query(session, query.Query, results)
	}()
	return results, nil
}

func (agent *Agent) query(session *sources.Session, searchQuery string, results chan sources.Result) {
	resp, err := agent.queryURL(session, URL, searchQuery)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return
	}
	defer resp.Body.Close()

	var apiResponse OnypheResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return
	}

	for _, result := range apiResponse.Results {
		output := sources.Result{
			Source: agent.Name(),
			IP:     result.IP,
			Port:   result.Port,
		}
		results <- output
	}
}

func (agent *Agent) queryURL(session *sources.Session, baseURL, searchQuery string) (*http.Response, error) {
	urlWithQuery := fmt.Sprintf(baseURL, url.QueryEscape(searchQuery))
	request, err := sources.NewHTTPRequest(http.MethodGet, urlWithQuery, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "bearer "+session.Keys.OnypheKey)
	return session.Do(request, agent.Name())
}
