package quake

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/sources"
	errorutil "github.com/projectdiscovery/utils/errors"
)

const (
	URL = "https://quake.360.net/api/v3/search/quake_service"
)

var pageSize = 1000

type Agent struct{}

func (agent *Agent) Name() string {
	return "quake"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.QuakeToken == "" {
		return nil, errors.New("empty quake keys")
	}

	results := make(chan sources.Result)
	if query.Limit < pageSize {
		pageSize = query.Limit
	}
	go func(pageSize int) {
		defer close(results)
		numberOfResults := 0
		for {
			quakeRequest := &Request{
				Query:       query.Query,
				Size:        pageSize,
				Start:       numberOfResults,
				IgnoreCache: true,
				Latest:      true,
				Exclude: []string{
					"service.cert",
					"service.response",
					"service.http.body",
					"service.http.favicon.data",
				},
			}
			quakeResponse := agent.query(URL, session, quakeRequest, results)
			if quakeResponse == nil {
				break
			}

			numberOfResults += len(quakeResponse.Data)
			gologger.Debug().Msgf("Querying quake for %s,numberOfResults:%d", query.Query, numberOfResults)
			if numberOfResults >= query.Limit || len(quakeResponse.Data) == 0 {
				break
			}
			// early exit without more results
			if quakeResponse.Meta.Pagination.Count > 0 && numberOfResults >= quakeResponse.Meta.Pagination.Total {
				break
			}
			time.Sleep(time.Second * 1)
		}
	}(pageSize)

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
		fmt.Println(errx)
		results <- sources.Result{Source: agent.Name(), Error: errx}
		return nil
	}

	for _, quakeResult := range quakeResponse.Data {
		raw, _ := json.Marshal(quakeResult)
		var appNames []string
		for _, app := range quakeResult.Components {
			appNames = append(appNames, app.ProductNameCn)
		}
		var urlStr string
		if len(quakeResult.Service.Http.HttpLoadUrl) > 0 {
			urlStr = quakeResult.Service.Http.HttpLoadUrl[0]
		}
		result := sources.Result{
			Source:          agent.Name(),
			IP:              quakeResult.Ip,
			Port:            quakeResult.Port,
			Host:            quakeResult.Hostname,
			Url:             urlStr,
			Raw:             raw,
			HtmlTitle:       quakeResult.Service.Http.Title,
			Domain:          quakeResult.Domain,
			Province:        quakeResult.Location.ProvinceCn,
			ConfirmHttps:    false,
			City:            quakeResult.Location.CityCn,
			Country:         quakeResult.Location.CountryCn,
			Asn:             strconv.Itoa(quakeResult.Asn),
			Location:        "",
			ServiceProvider: "",
			Fingerprints:    strings.Join(appNames, ","),
			Banner:          "",
			ServiceName:     quakeResult.Service.Name,
			StatusCode:      quakeResult.Service.Http.StatusCode,
		}

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
