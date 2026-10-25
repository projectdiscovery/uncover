package onyphe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URLTemplate = "https://www.onyphe.io/api/v2/search/?q=%s&page=%d&size=10"
)

type OnypheRequest struct {
	Query string
	Page  int
}

type Agent struct{}

func (agent *Agent) Name() string {
	return "onyphe"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.OnypheKey == "" {
		return nil, errors.New("empty Onyphe API key")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		currentPage := 1
		totalResults := 0
		maxResults := query.Limit

		for {
			if ctx.Err() != nil {
				return
			}
			onypheRequest := &OnypheRequest{
				Query: query.Query,
				Page:  currentPage,
			}

			apiResponse := agent.query(ctx, session, *onypheRequest, results)
			if apiResponse == nil {
				break
			}

			totalResults += len(apiResponse.Results)
			if totalResults >= apiResponse.Total ||
				len(apiResponse.Results) == 0 ||
				(maxResults > 0 && totalResults >= maxResults) {
				break
			}
			currentPage++
		}
	}()

	return results, nil
}

func (agent *Agent) query(ctx context.Context, session *sources.Session, onypheRequest OnypheRequest, results chan sources.Result) *OnypheResponse {
	resp, err := agent.queryURL(ctx, session, &onypheRequest)
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}

	var apiResponse OnypheResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}

	if apiResponse.Error != 0 {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: fmt.Errorf("API error code: %d", apiResponse.Error)})
		return nil
	}

	for _, result := range apiResponse.Results {
		if !sources.SendResult(ctx, results, sources.Result{
			Source: agent.Name(),
			IP:     result.IP,
			Port:   result.Port,
		}) {
			return &apiResponse
		}
	}
	return &apiResponse
}

func (agent *Agent) queryURL(ctx context.Context, session *sources.Session, onypheRequest *OnypheRequest) (*http.Response, error) {
	escapedQuery := url.QueryEscape(onypheRequest.Query)
	escapedQuery = strings.ReplaceAll(escapedQuery, "%22", "\"")
	urlWithQuery := fmt.Sprintf(URLTemplate, escapedQuery, onypheRequest.Page)

	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, urlWithQuery, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "bearer "+session.Keys.OnypheKey)

	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return resp, nil
}
