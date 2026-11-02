package zoomeye

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/projectdiscovery/uncover/sources"
)

var (
	URL = "https://api.zoomeye.ai/v2/search"
)

// ResolveURL returns the resolved URL for ZoomEye given a host override, fallback default URL and path.
func ResolveURL(host, defaultURL, defaultPath string) string {
	if host == "" {
		return defaultURL
	}
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		u, err := url.Parse(host)
		if err == nil {
			if u.Path == "" || u.Path == "/" {
				u.Path = defaultPath
			}
			return u.String()
		}
	}
	cleanHost := strings.TrimRight(host, "/")
	if !strings.HasPrefix(cleanHost, "api.") && !strings.Contains(cleanHost, "/") {
		cleanHost = "api." + cleanHost
	}
	return fmt.Sprintf("https://%s%s", cleanHost, defaultPath)
}

type Agent struct{}

type ZoomEyeRequest struct {
	Query    string
	Page     int
	PageSize int
}

func (agent *Agent) Name() string {
	return "zoomeye"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.ZoomEyeToken == "" {
		return nil, errors.New("empty zoomeye keys")
	}
	results := make(chan sources.Result)

	apiURL := ResolveURL(session.Keys.ZoomEyeHost, URL, "/v2/search")

	go func() {
		defer close(results)

		currentPage := 1
		var numberOfResults, totalResults int
		for {
			if ctx.Err() != nil {
				return
			}
			zoomeyeRequest := &ZoomEyeRequest{
				Query:    query.Query,
				Page:     currentPage,
				PageSize: 100,
			}

			zoomeyeResponse := agent.query(ctx, apiURL, session, zoomeyeRequest, results)
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

func (agent *Agent) queryURL(ctx context.Context, session *sources.Session, URL string, zoomeyeRequest *ZoomEyeRequest) (*http.Response, error) {
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

	request, err := sources.NewHTTPRequest(ctx, http.MethodPost, URL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	request.Header.Set("API-KEY", session.Keys.ZoomEyeToken)
	request.Header.Set("Content-Type", "application/json")
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(ctx context.Context, URL string, session *sources.Session, zoomeyeRequest *ZoomEyeRequest, results chan sources.Result) *ZoomEyeResponse {
	resp, err := agent.queryURL(ctx, session, URL, zoomeyeRequest)
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	zoomeyeResponse := &ZoomEyeResponse{}
	if err := json.NewDecoder(resp.Body).Decode(zoomeyeResponse); err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}

	for _, result := range zoomeyeResponse.Results {
		sourceResult := sources.Result{Source: agent.Name()}

		sourceResult.IP = result.IP
		sourceResult.Port = result.Port
		sourceResult.Host = result.Hostname

		raw, _ := json.Marshal(result)
		sourceResult.Raw = raw
		if !sources.SendResult(ctx, results, sourceResult) {
			return zoomeyeResponse
		}
	}

	return zoomeyeResponse
}
