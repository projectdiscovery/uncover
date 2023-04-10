package fofa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"errors"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL    = "https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&fields=%s&page=%d&size=%d"
	Fields = "ip,port,host"
	Size   = 100
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "fofa"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.FofaEmail == "" || session.Keys.FofaKey == "" {
		return nil, errors.New("empty fofa keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		var numberOfResults int
		page := 1
		for {
			fofaRequest := &FofaRequest{
				Query:  query.Query,
				Fields: Fields,
				Size:   Size,
				Page:   page,
			}
			fofaResponse := agent.query(URL, session, fofaRequest, results)
			if fofaResponse == nil {
				break
			}
			size := fofaResponse.Size
			if size == 0 || numberOfResults > query.Limit || len(fofaResponse.Results) == 0 || numberOfResults > size {
				break
			}
			numberOfResults += len(fofaResponse.Results)
			page++
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, fofaRequest *FofaRequest) (*http.Response, error) {
	base64Query := base64.StdEncoding.EncodeToString([]byte(fofaRequest.Query))
	fofaURL := fmt.Sprintf(URL, session.Keys.FofaEmail, session.Keys.FofaKey, base64Query, Fields, fofaRequest.Page, fofaRequest.Size)
	request, err := sources.NewHTTPRequest(http.MethodGet, fofaURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, fofaRequest *FofaRequest, results chan sources.Result) *FofaResponse {
	resp, err := agent.queryURL(session, URL, fofaRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	fofaResponse := &FofaResponse{}

	if err := json.NewDecoder(resp.Body).Decode(fofaResponse); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	if fofaResponse.Error {
		results <- sources.Result{Source: agent.Name(), Error: fmt.Errorf(fofaResponse.ErrMsg)}
		return nil
	}

	for _, fofaResult := range fofaResponse.Results {
		result := sources.Result{Source: agent.Name()}
		result.IP = fofaResult[0]
		result.Port, _ = strconv.Atoi(fofaResult[1])
		result.Host = fofaResult[2]
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	return fofaResponse
}

type FofaRequest struct {
	Query  string
	Fields string
	Page   int
	Size   int
	Full   string
}
