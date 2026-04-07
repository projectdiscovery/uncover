package nerdydata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/projectdiscovery/uncover/sources"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "nerdydata"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.NerdyDataToken == "" {
		return nil, errors.New("empty NerdyData keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		ctx := context.Background()
		const maxRetries = 5
		const baseBackoff = 30 * time.Second
		const maxBackoff = 960 * time.Second
		numberOfResults := 0
		nextPage := ""

		for {
			nerdydataRequest := &Request{
				Query: query.Query,
				Page:  nextPage,
			}

			var resp *http.Response
			var err error
			for attempt := 0; attempt < maxRetries; attempt++ {
				resp, err = agent.queryURL(session, nerdydataRequest.buildURL(), session.Keys.NerdyDataToken)
				if err != nil {
					results <- sources.Result{Source: agent.Name(), Error: err}
					return
				}
				if resp.StatusCode != http.StatusAccepted {
					break
				}
				// 202 = server-side timeout; back off and retry with same cursor
				resp.Body.Close()
				backoff := baseBackoff * (1 << attempt)
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					results <- sources.Result{Source: agent.Name(), Error: ctx.Err()}
					return
				}
			}
			if resp.StatusCode == http.StatusAccepted {
				resp.Body.Close()
				results <- sources.Result{
					Source: agent.Name(),
					Error:  fmt.Errorf("server returned 202 after %d retries", maxRetries),
				}
				return
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				results <- sources.Result{
					Source: agent.Name(),
					Error:  fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body),
				}
				return
			}

			var apiResponse Response
			if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
				resp.Body.Close()
				results <- sources.Result{Source: agent.Name(), Error: err}
				return
			}
			resp.Body.Close()

			if len(apiResponse.Sites) == 0 {
				break
			}

			for _, s := range apiResponse.Sites {
				if numberOfResults >= query.Limit {
					return
				}
				result := sources.Result{Source: agent.Name()}
				result.Host = s.Domain
				if result.Host == "" {
					result.Host = s.URL
				}
				result.Url = s.URL
				raw, _ := json.Marshal(s)
				result.Raw = raw
				results <- result
				numberOfResults++
			}

			if apiResponse.NextPage == "" {
				break
			}
			nextPage = apiResponse.NextPage
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, token string) (*http.Response, error) {
	request, err := sources.NewHTTPRequest(http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("api_key", token)
	request.Header.Set("x-uncover", "1")
	// Bypass session.Do (which errors on non-200) to handle 202 retry ourselves.
	if err := session.RateLimits.Take(agent.Name()); err != nil {
		return nil, err
	}
	request.Close = true
	return session.Client.Do(request)
}
