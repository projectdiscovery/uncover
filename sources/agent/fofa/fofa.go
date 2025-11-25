package fofa

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/projectdiscovery/gologger"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL = "https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&fields=%s&page=%d&size=%d&full=%t"
)

var (
	// Size is the number of results to return per page
	Size = 100
	// Fields is the fields to return in the results
	Fields = "ip,port,host"

	// if Full is true results from more than one year will be returned
	Full = false
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
				Full:   Full,
			}
			fofaResponse := agent.query(URL, session, fofaRequest, results)
			if fofaResponse == nil {
				break
			}
			numberOfResults += len(fofaResponse.Results)
			page++
			size := fofaResponse.Size
			if size == 0 || numberOfResults >= query.Limit || len(fofaResponse.Results) == 0 || numberOfResults > size {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, fofaRequest *FofaRequest) (*http.Response, error) {
	base64Query := base64.StdEncoding.EncodeToString([]byte(fofaRequest.Query))
	fofaURL := fmt.Sprintf(URL, session.Keys.FofaKey, base64Query, Fields, fofaRequest.Page, fofaRequest.Size, fofaRequest.Full)
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
	RespBodyByBodyBytes, _ := io.ReadAll(resp.Body)
	if err := json.NewDecoder(resp.Body).Decode(fofaResponse); err != nil {
		result := sources.Result{Source: agent.Name()}
		defer func(Body io.ReadCloser) {
			if bodyCloseErr := Body.Close(); bodyCloseErr != nil {
				gologger.Info().Msgf("response body close error : %v", bodyCloseErr)
			}
		}(resp.Body)
		raw, _ := json.Marshal(RespBodyByBodyBytes)
		result.Raw = raw
		results <- result
		return nil
	}
	if fofaResponse.Error {
		results <- sources.Result{Source: agent.Name(), Error: fmt.Errorf("%s", fofaResponse.ErrMsg)}
		return nil
	}

	for _, fofaResult := range fofaResponse.Results {
		result := sources.Result{Source: agent.Name()}
		result.IP = fofaResult[0]
		result.Port, _ = strconv.Atoi(fofaResult[1])
		result.Host = fofaResult[2]
		raw, _ := json.Marshal(fofaResult)
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
	Full   bool
}
