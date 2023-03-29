package hunter

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL  = "https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=%d"
	Size = 100
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "hunter"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.HunterToken == "" {
		return nil, errors.New("empty hunter keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		numberOfResults := 0
		page := 1
		for {
			hunterRequest := &Request{
				ApiKey:   session.Keys.HunterToken,
				Search:   query.Query,
				Page:     page,
				PageSize: Size,
			}
			hunterResponse := agent.query(URL, session, hunterRequest, results)
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

func (agent *Agent) query(URL string, session *sources.Session, hunterRequest *Request, results chan sources.Result) *Response {
	resp, err := agent.queryURL(session, URL, hunterRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	hunterResponse := &Response{}
	if err := json.NewDecoder(resp.Body).Decode(hunterResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	if hunterResponse.Code == http.StatusOK && hunterResponse.Data.Total > 0 {
		for _, hunterResult := range hunterResponse.Data.Arr {
			result := sources.Result{Source: agent.Name()}
			result.IP = hunterResult.IP
			result.Port = hunterResult.Port
			result.Host = hunterResult.Domain
			raw, _ := json.Marshal(result)
			result.Raw = raw
			results <- result
		}
	}

	return hunterResponse
}

func (agent *Agent) queryURL(session *sources.Session, URL string, hunterRequest *Request) (*http.Response, error) {
	base64Query := base64.URLEncoding.EncodeToString([]byte(hunterRequest.Search))
	hunterURL := fmt.Sprintf(URL, hunterRequest.ApiKey, base64Query, hunterRequest.Page, hunterRequest.PageSize)
	request, err := sources.NewHTTPRequest(http.MethodGet, hunterURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	return session.Do(request, agent.Name())
}
