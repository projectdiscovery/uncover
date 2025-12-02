package rapiddns_spider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/uncover/sources"
	util "github.com/projectdiscovery/uncover/utils"
	"io"
	"net/http"
	"strings"
)

const (
	URL    = "https://rapiddns.io/subdomain/%s?full=1"
	Source = "rapiddns-spider"
)

type Agent struct {
	options *sources.Agent
}
type rapidDNS struct {
	Domain string `json:"domain"`
}

func (agent *Agent) Name() string {
	return Source
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {

	results := make(chan sources.Result)

	go func() {
		defer close(results)
		request := &rapidDNS{Domain: query.Query}
		agent.query(URL, session, request, results)
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, rapid *rapidDNS) (*http.Response, error) {
	rapidURL := fmt.Sprintf(URL, rapid.Domain)
	request, err := sources.NewHTTPRequest(http.MethodGet, rapidURL, nil)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}

func (agent *Agent) query(URL string, session *sources.Session, rapid *rapidDNS, results chan sources.Result) (sub []string) {
	var shouldIgnoreErrors bool
	resp, err := agent.queryURL(session, URL, rapid)
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
	sub = sources.MatchSubdomains(rapid.Domain, body.String(), true)
	for _, ra := range sub {
		result := sources.Result{Source: agent.Name()}
		_, result.Host, result.Port = util.GetProtocolHostAndPort(ra)
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	return
}
