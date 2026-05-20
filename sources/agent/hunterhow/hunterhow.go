package hunterhow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/projectdiscovery/uncover/sources"
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

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.HunterHowToken == "" {
		return nil, errors.New("empty hunterhow keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		numberOfResults := 0
		pageQuery := 1

		for {
			if ctx.Err() != nil {
				return
			}
			hunterhowRequest := &Request{
				Query:    query.Query,
				PageSize: Size,
				Page:     pageQuery,
			}

			if numberOfResults > query.Limit {
				break
			}

			hunterhowResponse := agent.query(ctx, hunterhowRequest.buildURL(session.Keys.HunterHowToken), session, results)
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

func (agent *Agent) query(ctx context.Context, URL string, session *sources.Session, results chan sources.Result) []string {
	resp, err := agent.queryURL(ctx, session, URL)
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}

	var apiResponse Response
	err = json.NewDecoder(resp.Body).Decode(&apiResponse)
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}
	if apiResponse.Code != http.StatusOK {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: errors.New(apiResponse.Message)})
		return nil
	}

	var lines []string
	for _, data := range apiResponse.Data.List {
		result := sources.Result{Source: agent.Name()}
		result.Host = data.Domain
		result.IP = data.IP
		result.Port = data.Port
		raw, _ := json.Marshal(data)
		result.Raw = raw
		if !sources.SendResult(ctx, results, result) {
			return lines
		}
		lines = append(lines, data.Domain)
	}

	return lines
}

func (agent *Agent) queryURL(ctx context.Context, session *sources.Session, URL string) (*http.Response, error) {
	request, err := sources.NewHTTPRequest(
		ctx,
		http.MethodGet,
		URL,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}
