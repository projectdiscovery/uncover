package ip138_spider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/uncover/sources"
	"io"
	"net/http"
	"strings"
)

const (
	URL    = "https://site.ip138.com/%s/domain.htm"
	Source = "ip138-spider"
)

type Agent struct {
	options *sources.Agent
}
type ip138Request struct {
	Domain string
}

func (agent *Agent) Name() string {
	return Source
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {

	results := make(chan sources.Result)

	go func() {
		defer close(results)
		ip138Query := &ip138Request{Domain: query.Query}
		agent.query(URL, session, ip138Query, results)
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, query *ip138Request) (*http.Response, error) {
	ip138URL := fmt.Sprintf(URL, query.Domain)
	request, err := sources.NewHTTPRequest(http.MethodGet, ip138URL, nil)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, request *ip138Request, results chan sources.Result) (sub []string) {
	var shouldIgnoreErrors bool
	resp, err := agent.queryURL(session, URL, request)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return
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
			return
		}
	}
	sub = sources.MatchSubdomains(request.Domain, body.String(), true)
	for _, ip138 := range sub {
		result := sources.Result{Source: agent.Name()}
		result.Host = ip138
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	return
}
