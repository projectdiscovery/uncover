package daydaymap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"errors"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL     = "https://www.daydaymap.com/api/v1/raymap/search/all"
	MaxSize = 10000
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "daydaymap"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.Daydaymap == "" {
		return nil, errors.New("empty daydaymap keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		encodedQuery := base64.StdEncoding.EncodeToString([]byte(query.Query))

		currentPage := 1
		var numberOfResults, totalResults int

		pageSize := MaxSize
		if query.Limit > 0 && query.Limit < MaxSize {
			pageSize = query.Limit
		}

		for {
			if ctx.Err() != nil {
				return
			}
			daydaymapRequest := &DaydaymapRequest{
				Page:     currentPage,
				PageSize: pageSize,
				Keyword:  encodedQuery,
			}

			daydaymapResponse := agent.query(ctx, URL, session, daydaymapRequest, results)
			if daydaymapResponse == nil {
				break
			}

			currentPage++
			numberOfResults += len(daydaymapResponse.Data.List)

			if totalResults == 0 {
				totalResults = daydaymapResponse.Data.Total
			}

			if numberOfResults >= query.Limit || numberOfResults >= totalResults || len(daydaymapResponse.Data.List) == 0 {
				break
			}

			if numberOfResults >= MaxSize {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(ctx context.Context, session *sources.Session, URL string, daydaymapRequest *DaydaymapRequest) (*http.Response, error) {
	jsonBody, err := json.Marshal(daydaymapRequest)
	if err != nil {
		return nil, err
	}

	request, err := sources.NewHTTPRequest(ctx, http.MethodPost, URL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("api-key", session.Keys.Daydaymap)

	return session.Do(request, agent.Name())
}

func (agent *Agent) query(ctx context.Context, URL string, session *sources.Session, daydaymapRequest *DaydaymapRequest, results chan sources.Result) *DaydaymapResponse {
	resp, err := agent.queryURL(ctx, session, URL, daydaymapRequest)
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}

	daydaymapResponse := &DaydaymapResponse{}
	if err := json.NewDecoder(resp.Body).Decode(daydaymapResponse); err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}

	if daydaymapResponse.Code != http.StatusOK {
		sources.SendResult(ctx, results, sources.Result{
			Source: agent.Name(),
			Error:  fmt.Errorf("API error (code %d): %s", daydaymapResponse.Code, daydaymapResponse.Msg),
		})
		return nil
	}

	for _, daydaymapResult := range daydaymapResponse.Data.List {
		result := sources.Result{Source: agent.Name()}

		if ip, ok := daydaymapResult["ip"]; ok {
			result.IP = fmt.Sprint(ip)
		}

		if port, ok := daydaymapResult["port"]; ok {
			switch v := port.(type) {
			case float64:
				result.Port = int(v)
			case int:
				result.Port = v
			}
		}

		if domain, ok := daydaymapResult["domain"]; ok && domain != nil {
			result.Host = fmt.Sprint(domain)
		}

		if service, ok := daydaymapResult["service"]; ok && service != nil {
			serviceStr := fmt.Sprint(service)
			if serviceStr == "https" || serviceStr == "http" {
				result.Url = fmt.Sprintf("%s://%s", serviceStr, result.IP)
				if result.Port > 0 && result.Port != 80 && result.Port != 443 {
					result.Url = fmt.Sprintf("%s:%d", result.Url, result.Port)
				}
			}
		}

		raw, _ := json.Marshal(daydaymapResult)
		result.Raw = raw

		if !sources.SendResult(ctx, results, result) {
			return daydaymapResponse
		}
	}

	return daydaymapResponse
}
