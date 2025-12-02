package daydaymap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"errors"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL     = "https://www.daydaymap.com/api/v1/raymap/search/all"
	MaxSize = 10000 // API max page size
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "daydaymap"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.Daydaymap == "" {
		return nil, errors.New("empty daydaymap keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		// Encode query to base64
		encodedQuery := base64.StdEncoding.EncodeToString([]byte(query.Query))

		currentPage := 1
		var numberOfResults, totalResults int

		// Set page size (max 10000 or user limit)
		pageSize := MaxSize
		if query.Limit > 0 && query.Limit < MaxSize {
			pageSize = query.Limit
		}

		for {
			daydaymapRequest := &DaydaymapRequest{
				Page:     currentPage,
				PageSize: pageSize,
				Keyword:  encodedQuery,
			}

			daydaymapResponse := agent.query(URL, session, daydaymapRequest, results)
			if daydaymapResponse == nil {
				break
			}

			currentPage++
			numberOfResults += len(daydaymapResponse.Data.List)

			if totalResults == 0 {
				totalResults = daydaymapResponse.Data.Total
			}

			// Check if we should stop
			if numberOfResults >= query.Limit || numberOfResults >= totalResults || len(daydaymapResponse.Data.List) == 0 {
				break
			}

			// API maximum is 10000 results
			if numberOfResults >= 10000 {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, daydaymapRequest *DaydaymapRequest) (*http.Response, error) {
	// Prepare JSON body
	jsonBody, err := json.Marshal(daydaymapRequest)
	if err != nil {
		return nil, err
	}

	request, err := sources.NewHTTPRequest(http.MethodPost, URL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	// Set headers
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("api-key", session.Keys.Daydaymap)

	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, daydaymapRequest *DaydaymapRequest, results chan sources.Result) *DaydaymapResponse {
	resp, err := agent.queryURL(session, URL, daydaymapRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	daydaymapResponse := &DaydaymapResponse{}
	if err := json.NewDecoder(resp.Body).Decode(daydaymapResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	// Check response code
	if daydaymapResponse.Code != 200 {
		results <- sources.Result{
			Source: agent.Name(),
			Error:  fmt.Errorf("API error (code %d): %s", daydaymapResponse.Code, daydaymapResponse.Msg),
		}
		return nil
	}

	// Parse results
	for _, daydaymapResult := range daydaymapResponse.Data.List {
		result := sources.Result{Source: agent.Name()}

		// Extract IP
		if ip, ok := daydaymapResult["ip"]; ok {
			result.IP = fmt.Sprint(ip)
		}

		// Extract port
		if port, ok := daydaymapResult["port"]; ok {
			switch v := port.(type) {
			case float64:
				result.Port = int(v)
			case int:
				result.Port = v
			}
		}

		// Extract domain
		if domain, ok := daydaymapResult["domain"]; ok && domain != nil {
			result.Host = fmt.Sprint(domain)
		}

		// Extract title for URL construction
		if service, ok := daydaymapResult["service"]; ok && service != nil {
			serviceStr := fmt.Sprint(service)
			if serviceStr == "https" || serviceStr == "http" {
				result.Url = fmt.Sprintf("%s://%s", serviceStr, result.IP)
				if result.Port > 0 && result.Port != 80 && result.Port != 443 {
					result.Url = fmt.Sprintf("%s:%d", result.Url, result.Port)
				}
			}
		}

		// Store raw data
		raw, _ := json.Marshal(daydaymapResult)
		result.Raw = raw

		results <- result
	}

	return daydaymapResponse
}
