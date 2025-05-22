package fofa

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/projectdiscovery/gologger"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL    = "https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&fields=%s&page=%d&size=%d"
	Fields = "host,title,ip,domain,port,country,city,asn,org,link,product,banner,protocol"
)

var pageSize = 10000

type Agent struct{}

func (agent *Agent) Name() string {
	return "fofa"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.FofaKey == "" {
		return nil, errors.New("empty fofa keys")
	}

	results := make(chan sources.Result)
	if query.Limit < pageSize {
		pageSize = query.Limit
	}
	go func(pageSize int) {
		defer close(results)

		var numberOfResults int
		page := 1
		for {
			fofaRequest := &FofaRequest{
				Query:  query.Query,
				Fields: Fields,
				Size:   pageSize,
				Page:   page,
			}
			fofaResponse := agent.query(URL, session, fofaRequest, results)
			if fofaResponse == nil {
				results <- sources.Result{Source: agent.Name(), Error: fmt.Errorf("fofa response is nil")}
				break
			}

			numberOfResults += len(fofaResponse.Results)
			gologger.Debug().Msgf("Querying fofa for %s,numberOfResults:%d", query.Query, numberOfResults)
			if fofaResponse.Size == 0 || numberOfResults >= query.Limit || len(fofaResponse.Results) >= query.Limit ||
				len(fofaResponse.Results) == 0 || len(fofaResponse.Results) <= pageSize {
				break
			}
			time.Sleep(time.Second * 1)
			page++
		}
	}(pageSize)

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, fofaRequest *FofaRequest) (*http.Response, error) {
	base64Query := base64.StdEncoding.EncodeToString([]byte(fofaRequest.Query))
	fofaURL := fmt.Sprintf(URL, session.Keys.FofaKey, base64Query, Fields, fofaRequest.Page, fofaRequest.Size)
	// gologger.Debug().Msgf("Fofa URL: %s", fofaURL)
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
		results <- sources.Result{Source: agent.Name(), Error: fmt.Errorf("%s", fofaResponse.ErrMsg)}
		return nil
	}

	for _, fofaResult := range fofaResponse.Results {
		port, _ := strconv.Atoi(fofaResult[4])
		raw, _ := json.Marshal(fofaResult)

		results <- sources.Result{
			Source:          agent.Name(),
			IP:              fofaResult[2],
			Port:            port,
			Host:            fofaResult[0],
			Url:             fofaResult[9],
			Raw:             raw,
			HtmlTitle:       fofaResult[1],
			Domain:          fofaResult[3],
			Province:        "",
			ConfirmHttps:    false,
			City:            fofaResult[6],
			Country:         fofaResult[5],
			Asn:             fofaResult[7],
			Location:        "",
			ServiceProvider: fofaResult[8],
			Fingerprints:    fofaResult[10],
			Banner:          fofaResult[11],
			ServiceName:     fofaResult[12],
		}
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
