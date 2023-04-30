package quake

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/projectdiscovery/uncover/sources"
	errorutil "github.com/projectdiscovery/utils/errors"
)

const (
	URL  = "https://quake.360.net/api/v3/search/quake_service"
	Size = 100
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "quake"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.QuakeToken == "" {
		return nil, errors.New("empty quake keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		numberOfResults := 0

		for {
			quakeRequest := &Request{
				Query:       query.Query,
				Size:        Size,
				Start:       numberOfResults,
				IgnoreCache: true,
				Include:     []string{"ip", "port", "hostname"},
			}
			quakeResponse := agent.query(URL, session, quakeRequest, results)
			if quakeResponse == nil {
				break
			}

			if numberOfResults > query.Limit || len(quakeResponse.Data) == 0 {
				break
			}

			numberOfResults += len(quakeResponse.Data)

			// early exit without more results
			if quakeResponse.Meta.Pagination.Count > 0 && numberOfResults >= quakeResponse.Meta.Pagination.Total {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) query(URL string, session *sources.Session, quakeRequest *Request, results chan sources.Result) *Response {
	resp, err := agent.queryURL(session, URL, quakeRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	quakeResponse := &Response{}
	respdata, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: fmt.Errorf("%v: %v", err, string(respdata))}
		return nil
	}
	if err := json.NewDecoder(bytes.NewReader(respdata)).Decode(quakeResponse); err != nil {
		errx := errorutil.NewWithErr(err)
		// quake has different json format for error messages try to unmarshal it in map and print map
		var errMap map[string]interface{}
		if err := json.NewDecoder(bytes.NewReader(respdata)).Decode(&errMap); err == nil {
			errx = errx.Msgf("failed to decode quake response: %v", errMap)
		} else {
			errx = errx.Msgf("failed to decode quake response: %s", string(respdata))
		}
		results <- sources.Result{Source: agent.Name(), Error: errx}
		return nil
	}

	for _, quakeResult := range quakeResponse.Data {
		result := sources.Result{Source: agent.Name()}
		result.IP = quakeResult.IP
		result.Port = quakeResult.Port
		result.Host = quakeResult.Hostname
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}

	return quakeResponse
}

func (agent *Agent) queryURL(session *sources.Session, URL string, quakeRequest *Request) (*http.Response, error) {
	body, err := json.Marshal(quakeRequest)
	if err != nil {
		return nil, err
	}

	request, err := sources.NewHTTPRequest(
		http.MethodPost,
		URL,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-QuakeToken", session.Keys.QuakeToken)
	return session.Do(request, agent.Name())
}
