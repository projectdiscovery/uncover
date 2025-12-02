package zone0

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	util "github.com/projectdiscovery/uncover/utils"
	errorutil "github.com/projectdiscovery/utils/errors"
	"net/http"
	"strconv"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL    = "https://0.zone/api/data/"
	Size   = 100
	Source = "zone0"
	Type   = "site"
)

type request struct {
	Query     string `json:"query"`
	QueryType string `json:"query_type"`
	Page      int    `json:"page"`
	PageSize  int    `json:"page_size"`
	ZoneKeyId string `json:"zone_key_id"`
}

type Agent struct{}

func (agent *Agent) Name() string {
	return Source
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.Zone0Token == "" {
		return nil, errors.New(fmt.Sprintf("empty %s keys please read docs %s on how to add keys ", Source, "https://github.com/projectdiscovery/uncover?tab=readme-ov-file#provider-configuration"))
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		var numberOfResults int

		page := 1
		for {
			zone0Request := &request{
				Query:     query.Query,
				PageSize:  Size,
				QueryType: Type,
				Page:      page,
			}
			zone0Response := agent.query(URL, session, zone0Request, results)
			if zone0Response == nil {
				break
			}
			size := len(zone0Response.Data)
			numberOfResults += size
			total, _ := strconv.Atoi(zone0Response.Total)

			if size == 0 || numberOfResults > query.Limit || len(zone0Response.Data) == 0 || numberOfResults > size || total > query.Limit {
				break
			}

			page++
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, zone0Request *request) (*http.Response, error) {
	zone0Request.ZoneKeyId = session.Keys.Zone0Token
	jsonData, err := json.Marshal(zone0Request)
	if err != nil {
		return nil, errorutil.New("zone0").Msgf("failed to marshal json data: %s", err)
	}
	request, err := sources.NewHTTPRequest(http.MethodPost, URL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, URL)
	}
	return resp, nil
}

func (agent *Agent) query(URL string, session *sources.Session, zone0Request *request, results chan sources.Result) *response {
	resp, err := agent.queryURL(session, URL, zone0Request)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	zone0Response := &response{}

	if err := json.NewDecoder(resp.Body).Decode(zone0Response); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	if zone0Response.Msg != "success" {
		results <- sources.Result{Source: agent.Name(), Error: fmt.Errorf(zone0Response.Msg)}
		return nil
	}

	for _, zoneResult := range zone0Response.Data {
		result := sources.Result{Source: agent.Name()}
		result.IP = zoneResult.Ip

		_, host, port := util.GetProtocolHostAndPort(zoneResult.Url)
		result.Host = host
		if result.Port, _ = strconv.Atoi(zoneResult.Port); result.Port == 0 {
			result.Port = port
		}
		result.Url = zoneResult.Url
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	return zone0Response
}
