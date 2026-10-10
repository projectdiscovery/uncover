package criminalip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/projectdiscovery/uncover/sources"
)

var (
	URL        = "https://api.criminalip.io/v1/banner/search?query=%s&offset=%d"
	offsetStep = 10
	maxOffset  = 9900
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "criminalip"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.CriminalIPToken == "" {
		return nil, errors.New("empty criminalip keys")
	}
	if query == nil || strings.TrimSpace(query.Query) == "" {
		return nil, errors.New("empty criminalip query")
	}
	results := make(chan sources.Result)

	go func() {
		defer close(results)

		trimmedQuery := strings.TrimSpace(query.Query)
		numberOfResults := 0
		currentPage := 0

		for {
			if ctx.Err() != nil {
				return
			}
			criminalipRequest := &CriminalIPRequest{
				Query:  trimmedQuery,
				Offset: currentPage,
			}

			criminalipResponse := agent.query(ctx, URL, session, criminalipRequest, results)
			if criminalipResponse == nil {
				break
			}

			numberOfResults += len(criminalipResponse.Data.Result)

			if (query.Limit > 0 && numberOfResults >= query.Limit) || numberOfResults >= criminalipResponse.Data.Count || len(criminalipResponse.Data.Result) == 0 {
				break
			}

			nextOffset := currentPage + offsetStep

			if nextOffset > maxOffset {
				break
			}

			currentPage = nextOffset
		}
	}()

	return results, nil
}

func (agent *Agent) buildURL(endpoint string, req *CriminalIPRequest) (string, error) {
	return req.buildURL(endpoint)
}

func (agent *Agent) queryURL(ctx context.Context, session *sources.Session, URL string, criminalipRequest *CriminalIPRequest) (*http.Response, error) {
	criminalipURL, err := criminalipRequest.buildURL(URL)
	if err != nil {
		return nil, err
	}

	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, criminalipURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("x-api-key", session.Keys.CriminalIPToken)
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(ctx context.Context, URL string, session *sources.Session, criminalipRequest *CriminalIPRequest, results chan sources.Result) *CriminalIPResponse {
	resp, err := agent.queryURL(ctx, session, URL, criminalipRequest)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}

	criminalipResponse := &CriminalIPResponse{}
	if err := json.NewDecoder(resp.Body).Decode(criminalipResponse); err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}
	if criminalipResponse.Status != 0 && criminalipResponse.Status != http.StatusOK {
		errMsg := criminalipResponse.Msg
		if errMsg == "" {
			errMsg = fmt.Sprintf("criminalip error status code %d", criminalipResponse.Status)
		}
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: errors.New(errMsg)})
		return nil
	}
	if criminalipResponse.Status == http.StatusOK && criminalipResponse.Data.Count > 0 {
		for _, criminalipResult := range criminalipResponse.Data.Result {
			result := sources.Result{Source: agent.Name()}
			result.IP = criminalipResult.IP
			result.Port = criminalipResult.Port
			result.Host = criminalipResult.Domain
			raw, _ := json.Marshal(criminalipResult)
			result.Raw = raw
			if !sources.SendResult(ctx, results, result) {
				return criminalipResponse
			}
		}
	}

	return criminalipResponse
}

type CriminalIPRequest struct {
	Query  string
	Offset int
}

func (r *CriminalIPRequest) buildURL(endpoint string) (string, error) {
	if r == nil || strings.TrimSpace(r.Query) == "" {
		return "", errors.New("empty criminalip query")
	}
	trimmedQuery := strings.TrimSpace(r.Query)
	escapedQuery := url.QueryEscape(trimmedQuery)

	offset := r.Offset
	if offset < 0 {
		offset = 0
	}

	if strings.Contains(endpoint, "%s") && strings.Contains(endpoint, "%d") {
		return fmt.Sprintf(endpoint, escapedQuery, offset), nil
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("query", trimmedQuery)
	q.Set("offset", fmt.Sprintf("%d", offset))
	u.RawQuery = q.Encode()
	return u.String(), nil
}
