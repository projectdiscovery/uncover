package zoomeye

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"errors"

	"github.com/projectdiscovery/uncover/sources"
)

var (
	URL = "https://api.zoomeye.ai/v2/search"
)

type Agent struct{}

type ZoomEyeRequest struct {
	Query    string
	Page     int
	PageSize int
}

func (agent *Agent) Name() string {
	return "zoomeye"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.ZoomEyeToken == "" {
		return nil, errors.New("empty zoomeye keys")
	}
	results := make(chan sources.Result)

	go func() {
		defer close(results)

		currentPage := 1
		var numberOfResults, totalResults int
		for {
			zoomeyeRequest := &ZoomEyeRequest{
				Query:    query.Query,
				Page:     currentPage,
				PageSize: 100,
			}

			zoomeyeResponse := agent.query(URL, session, zoomeyeRequest, results)
			if zoomeyeResponse == nil {
				break
			}
			currentPage++
			numberOfResults += len(zoomeyeResponse.Results)
			if totalResults == 0 {
				totalResults = zoomeyeResponse.Total
			}

			if numberOfResults >= query.Limit || numberOfResults >= totalResults || len(zoomeyeResponse.Results) == 0 {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, zoomeyeRequest *ZoomEyeRequest) (*http.Response, error) {
	// Encode query to base64
	queryBase64 := base64.StdEncoding.EncodeToString([]byte(zoomeyeRequest.Query))

	requestBody := map[string]interface{}{
		"qbase64":  queryBase64,
		"page":     zoomeyeRequest.Page,
		"pagesize": zoomeyeRequest.PageSize,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	request, err := sources.NewHTTPRequest(http.MethodPost, URL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	request.Header.Set("API-KEY", session.Keys.ZoomEyeToken)
	request.Header.Set("Content-Type", "application/json")
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, zoomeyeRequest *ZoomEyeRequest, results chan sources.Result) *ZoomEyeResponse {
	resp, err := agent.queryURL(session, URL, zoomeyeRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	zoomeyeResponse := &ZoomEyeResponse{}
	if err := json.NewDecoder(resp.Body).Decode(zoomeyeResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	for _, result := range zoomeyeResponse.Results {
		sourceResult := sources.Result{Source: agent.Name()}

		sourceResult.IP = result.IP
		sourceResult.Port = result.Port
		sourceResult.Host = result.Hostname

		raw, _ := json.Marshal(result)
		sourceResult.Raw = raw
		results <- sourceResult
	}

	return zoomeyeResponse
}
