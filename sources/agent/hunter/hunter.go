package hunter

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL = "https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=%d&is_web=3"
)

var pageSize = 100

type Agent struct{}

func (agent *Agent) Name() string {
	return "hunter"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.HunterToken == "" {
		return nil, errors.New("empty hunter keys")
	}

	results := make(chan sources.Result)
	if query.Limit < pageSize {
		pageSize = query.Limit
	}
	go func(pageSize int) {
		defer close(results)
		numberOfResults := 0
		page := 1
		for {
			hunterRequest := &Request{
				ApiKey:   session.Keys.HunterToken,
				Search:   query.Query,
				Page:     page,
				PageSize: pageSize,
			}
			hunterResponse := agent.query(URL, session, hunterRequest, results)
			if hunterResponse == nil {
				break
			}
			numberOfResults += len(hunterResponse.Data.Arr)
			page++
			gologger.Debug().Msgf("Querying hunter for %s, numberOfResults:%d", query.Query, numberOfResults)

			if numberOfResults >= query.Limit || hunterResponse.Data.Total == 0 ||
				len(hunterResponse.Data.Arr) == 0 || hunterResponse.Data.Total <= pageSize {
				break
			}
			time.Sleep(time.Second * 2)
		}
	}(pageSize)

	return results, nil
}

func (agent *Agent) query(URL string, session *sources.Session, hunterRequest *Request, results chan sources.Result) *Response {
	resp, err := agent.queryURL(session, URL, hunterRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	defer resp.Body.Close()

	hunterResponse := &Response{}
	if err := json.NewDecoder(resp.Body).Decode(hunterResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	if hunterResponse.Code == http.StatusOK && hunterResponse.Data.Total > 0 {
		for _, hunterResult := range hunterResponse.Data.Arr {
			raw, _ := json.Marshal(hunterResult)
			var appNames []string
			for _, app := range hunterResult.Component {
				appNames = append(appNames, app.Name)
			}
			result := sources.Result{
				Source:          agent.Name(),
				IP:              hunterResult.Ip,
				Port:            hunterResult.Port,
				Host:            hunterResult.Domain,
				Url:             hunterResult.Url,
				Raw:             raw,
				HtmlTitle:       hunterResult.WebTitle,
				Domain:          hunterResult.Domain,
				Province:        hunterResult.Province,
				ConfirmHttps:    false,
				City:            hunterResult.City,
				Country:         hunterResult.Country,
				Asn:             "",
				Location:        "",
				ServiceProvider: "",
				Fingerprints:    strings.Join(appNames, ","),
				Banner:          hunterResult.Banner,
				ServiceName:     hunterResult.Protocol,
				StatusCode:      hunterResult.StatusCode,
				Honeypot:        0,
			}
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
