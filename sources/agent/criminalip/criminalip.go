package criminalip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"errors"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL = "https://api.criminalip.io/v1/banner/search?query=%s&offset=%d"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "criminalip"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.CriminalIPToken == "" {
		return nil, errors.New("empty criminalip keys")
	}
	results := make(chan sources.Result)

	go func() {
		defer close(results)

		numberOfResults := 0
		currentPage := 1
		for {
			criminalipRequest := &CriminalIPRequest{
				Query:  query.Query,
				Offset: currentPage,
			}

			criminalipResponse := agent.query(URL, session, criminalipRequest, results)
			if criminalipResponse == nil {
				break
			}

			numberOfResults += len(criminalipResponse.Data.Result)
			currentPage++

			if numberOfResults > query.Limit || criminalipResponse.Data.Count == 0 || len(criminalipResponse.Data.Result) == 0 {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, criminalipRequest *CriminalIPRequest) (*http.Response, error) {
	criminalipURL := fmt.Sprintf(URL, url.QueryEscape(criminalipRequest.Query), criminalipRequest.Offset)

	request, err := sources.NewHTTPRequest(http.MethodGet, criminalipURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("x-api-key", session.Keys.CriminalIPToken)
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, criminalipRequest *CriminalIPRequest, results chan sources.Result) *CriminalIPResponse {
	// query certificates
	resp, err := agent.queryURL(session, URL, criminalipRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	criminalipResponse := &CriminalIPResponse{}
	if err := json.NewDecoder(resp.Body).Decode(criminalipResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	if criminalipResponse.Status == http.StatusOK && criminalipResponse.Data.Count > 0 {
		for _, criminalipResult := range criminalipResponse.Data.Result {
			result := sources.Result{Source: agent.Name()}
			result.IP = criminalipResult.IP
			result.Port = criminalipResult.Port
			result.Host = criminalipResult.Domain
			raw, _ := json.Marshal(result)
			result.Raw = raw
			results <- result
		}
	}

	return criminalipResponse
}

type CriminalIPRequest struct {
	Query  string
	Offset int
}
