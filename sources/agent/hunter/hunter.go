package hunter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL = "https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=%d&is_web=%d&start_time=%s&end_time=%s"
)

var (
	Size       = 100
	StatusCode = ""
	PortFilter = false
	IsWeb      = 0
	StartTime  = ""
	EndTime    = ""
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "hunter"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.HunterToken == "" {
		return nil, errors.New("empty hunter keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		numberOfResults := 0
		page := 1
		for {
			if ctx.Err() != nil {
				return
			}
			hunterRequest := &Request{
				ApiKey:     session.Keys.HunterToken,
				Search:     query.Query,
				Page:       page,
				PageSize:   Size,
				StatusCode: StatusCode,
				PortFilter: PortFilter,
				IsWeb:      IsWeb,
				StartTime:  StartTime,
				EndTime:    EndTime,
			}
			hunterResponse := agent.query(ctx, URL, session, hunterRequest, results)
			if hunterResponse == nil {
				break
			}

			numberOfResults += len(hunterResponse.Data.Arr)
			page++

			if numberOfResults >= query.Limit || hunterResponse.Data.Total == 0 || len(hunterResponse.Data.Arr) == 0 {
				break
			}

		}
	}()

	return results, nil
}

func (agent *Agent) query(ctx context.Context, URL string, session *sources.Session, hunterRequest *Request, results chan sources.Result) *Response {
	resp, err := agent.queryURL(ctx, session, URL, hunterRequest)
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}
	defer func(Body io.ReadCloser) {
		if bodyCloseErr := Body.Close(); bodyCloseErr != nil {
			gologger.Info().Msgf("response body close error : %v", bodyCloseErr)
		}
	}(resp.Body)

	hunterResponse := &Response{}
	if err := json.NewDecoder(resp.Body).Decode(hunterResponse); err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}
	if hunterResponse.Code == http.StatusOK && hunterResponse.Data.Total > 0 {
		for _, hunterResult := range hunterResponse.Data.Arr {
			result := sources.Result{Source: agent.Name()}
			result.IP = hunterResult.IP
			result.Port = hunterResult.Port
			result.Host = hunterResult.Domain
			raw, _ := json.Marshal(hunterResult)
			result.Raw = raw
			if !sources.SendResult(ctx, results, result) {
				return hunterResponse
			}
		}
	}

	return hunterResponse
}

func (agent *Agent) queryURL(ctx context.Context, session *sources.Session, URL string, hunterRequest *Request) (*http.Response, error) {
	base64Query := base64.URLEncoding.EncodeToString([]byte(hunterRequest.Search))
	hunterURL := fmt.Sprintf(URL, hunterRequest.ApiKey, base64Query, hunterRequest.Page, hunterRequest.PageSize, hunterRequest.IsWeb, hunterRequest.StartTime, hunterRequest.EndTime)
	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, hunterURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	return session.Do(request, agent.Name())
}
