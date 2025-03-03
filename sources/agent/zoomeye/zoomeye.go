package zoomeye

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/projectdiscovery/uncover/sources"
)

var (
	URL = "https://api.zoomeye.org/v2/search"
)

type Agent struct{}

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
		pageSize := 10000
		if query.Limit < pageSize {
			pageSize = query.Limit
		}
		var numberOfResults, totalResults int
		for {
			zoomeyeRequest := &ZoomEyeRequest{
				Query:    base64.StdEncoding.EncodeToString([]byte(query.Query)),
				Page:     currentPage,
				PageSize: pageSize,
			}

			zoomeyeResponse := agent.query(URL, session, zoomeyeRequest, results)
			if zoomeyeResponse == nil {
				break
			}
			currentPage++
			numberOfResults += len(zoomeyeResponse.Data)
			if totalResults == 0 {
				totalResults = zoomeyeResponse.Total
			}

			// query certificates
			if numberOfResults >= query.Limit || numberOfResults >= totalResults || len(zoomeyeResponse.Data) == 0 {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, zoomeyeRequest *ZoomEyeRequest) (*http.Response, error) {
	reqBody := &bytes.Buffer{}
	if err := json.NewEncoder(reqBody).Encode(zoomeyeRequest); err != nil {
		return nil, fmt.Errorf("could not encode zoomeye request: %s", err)
	}
	request, err := sources.NewHTTPRequest(http.MethodPost, URL, reqBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set("API-KEY", session.Keys.ZoomEyeToken)
	request.Header.Set("Content-Type", "application/json")
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, zoomeyeRequest *ZoomEyeRequest, results chan sources.Result) *ZoomEyeResponse {
	// query certificates
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

	for _, zoomeyeResult := range zoomeyeResponse.Data {
		result := sources.Result{Source: agent.Name()}
		result.IP = zoomeyeResult.Ip
		result.Host = zoomeyeResult.Hostname
		result.Port = zoomeyeResult.Port
		raw, _ := json.Marshal(zoomeyeResult)
		result.Raw = raw
		results <- result
	}

	return zoomeyeResponse
}

type ZoomEyeRequest struct {
	Query    string `json:"qbase64"`
	Page     int    `json:"page"`
	PageSize int    `json:"pagesize"`
}

func convertPortFromValue(value interface{}) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case string:
		parsed, _ := strconv.Atoi(v)
		return parsed
	default:
		return 0
	}
}
