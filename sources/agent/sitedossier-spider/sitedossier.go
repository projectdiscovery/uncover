package sitedossier_spider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/uncover/sources"
	util "github.com/projectdiscovery/uncover/utils"
	"io"
	"net/http"
	"strings"
)

const (
	URL    = "http://www.sitedossier.com/parentdomain/%s/%d"
	Source = "sitedossier-spider"
)

type Agent struct {
	options *sources.Agent
}
type siteDossierRequest struct {
	Domain string `json:"domain"`
	Size   int    `json:"size"`
}

func (agent *Agent) Name() string {
	return Source
}
func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {

	results := make(chan sources.Result)

	go func() {
		defer close(results)
		var (
			Results         map[string]struct{}
			numberOfResults int
			size            int
		)

		Results = make(map[string]struct{})
		size = 1
		for {

			request := &siteDossierRequest{
				Domain: query.Query,
				Size:   size,
			}
			response := agent.query(session, URL, request, Results, results)
			if len(response) == 0 || numberOfResults > query.Limit {
				break
			}
			numberOfResults += len(response)

			for i := 0; i < len(response); i++ {
				Results[response[i]] = struct{}{}
			}
			size += 100
		}

	}()

	return results, nil
}
func (agent *Agent) query(session *sources.Session, URL string, request *siteDossierRequest, Results map[string]struct{}, results chan sources.Result) []string {
	var (
		shouldIgnoreErrors bool
	)
	resp, err := agent.queryURL(session, URL, request)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: errors.Wrap(err, "request error")}
		return nil
	}
	defer resp.Body.Close()
	body := bytes.Buffer{}
	_, err = io.Copy(&body, resp.Body)
	if err != nil {
		if strings.ContainsAny(err.Error(), "tls: user canceled") {
			shouldIgnoreErrors = true
		}
		if !shouldIgnoreErrors {
			results <- sources.Result{Source: agent.Name(), Error: err}
			return nil
		}
	}
	sub := sources.MatchSubdomains(request.Domain, body.String(), false)

	for _, site := range sub {
		if _, ok := Results[site]; ok {
			continue
		}
		result := sources.Result{Source: agent.Name()}
		_, host, port := util.GetProtocolHostAndPort(site)

		result.Host = host
		result.Port = port
		result.Url = site
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	if !strings.ContainsAny(body.String(), "Show next 100 items") && len(sub) == 0 {
		return nil
	}
	return sub
}
func (agent *Agent) queryURL(session *sources.Session, URL string, site *siteDossierRequest) (*http.Response, error) {

	requestURL := fmt.Sprintf(URL, site.Domain, site.Size)
	request, err := sources.NewHTTPRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}
