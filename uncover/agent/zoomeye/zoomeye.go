package zoomeye

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/uncover/uncover"
)

const (
	URL = "https://api.zoomeye.org/host/search?query=%s&page=%d"
)

type Agent struct {
	options *uncover.AgentOptions
}

func New() (uncover.Agent, error) {
	return &Agent{}, nil
}

func NewWithOptions(options *uncover.AgentOptions) (uncover.Agent, error) {
	return &Agent{options: options}, nil
}

func (agent *Agent) Name() string {
	return "zoomeye"
}

func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	if session.Keys.ZoomEyeToken == "" {
		return nil, errors.New("empty zoomeye keys")
	}
	results := make(chan uncover.Result)

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

func (agent *Agent) queryURL(session *uncover.Session, URL string, zoomeyeRequest *ZoomEyeRequest) (*http.Response, error) {
	zoomeyeURL := fmt.Sprintf(URL, url.QueryEscape(zoomeyeRequest.Query), zoomeyeRequest.Page)

	request, err := uncover.NewHTTPRequest(http.MethodGet, zoomeyeURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("API-KEY", session.Keys.ZoomEyeToken)
	agent.options.RateLimiter.Take()
	return session.Do(request)
}

func (agent *Agent) query(URL string, session *uncover.Session, zoomeyeRequest *ZoomEyeRequest, results chan uncover.Result) *ZoomEyeResponse {
	// query certificates
	resp, err := agent.queryURL(session, URL, zoomeyeRequest)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}

	zoomeyeResponse := &ZoomEyeResponse{}
	if err := json.NewDecoder(resp.Body).Decode(zoomeyeResponse); err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}

	for _, zoomeyeResult := range zoomeyeResponse.Results {
		result := uncover.Result{Source: agent.Name()}
		if ip, ok := zoomeyeResult["ip"]; ok {
			result.IP = ip.(string)
		}
		if portinfo, ok := zoomeyeResult["portinfo"]; ok {
			if port, ok := portinfo.(map[string]interface{}); ok {
				result.Port = convertPortFromValue(port["port"].(float64))
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
