package zoomeye

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"errors"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL = "https://api.zoomeye.org/host/search?query=%s&page=%d"
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
		var numberOfResults, totalResults int
		for {
			zoomeyeRequest := &ZoomEyeRequest{
				Query: query.Query,
				Page:  currentPage,
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

			// query certificates
			if numberOfResults > query.Limit || numberOfResults > totalResults || len(zoomeyeResponse.Results) == 0 {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, zoomeyeRequest *ZoomEyeRequest) (*http.Response, error) {
	zoomeyeURL := fmt.Sprintf(URL, url.QueryEscape(zoomeyeRequest.Query), zoomeyeRequest.Page)

	request, err := sources.NewHTTPRequest(http.MethodGet, zoomeyeURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("API-KEY", session.Keys.ZoomEyeToken)
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

	for _, zoomeyeResult := range zoomeyeResponse.Results {
		result := sources.Result{Source: agent.Name()}
		if ip, ok := zoomeyeResult["ip"]; ok {
			result.IP = ip.(string)
		}
		if portinfo, ok := zoomeyeResult["portinfo"]; ok {
			if port, ok := portinfo.(map[string]interface{}); ok {
				result.Port = convertPortFromValue(port["port"])
				if result.Port == 0 {
					continue
				}
				result.Host = port["hostname"].(string)
				raw, _ := json.Marshal(zoomeyeResult)
				result.Raw = raw
				results <- result
			}
		} else {
			raw, _ := json.Marshal(zoomeyeResult)
			result.Raw = raw
			results <- result
		}
	}

	return zoomeyeResponse
}

type ZoomEyeRequest struct {
	Query string
	Page  int
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
