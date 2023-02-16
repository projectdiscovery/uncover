package publicwww

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/projectdiscovery/uncover/uncover"
)

const (
	baseURL      = "https://publicwww.com/"
	baseEndpoint = "websites/"
)

type Agent struct {
	options *uncover.AgentOptions
}

func New() (uncover.Agent, error) {
	return &Agent{}, nil
}

func NewWithOptions(options *uncover.AgentOptions) (uncover.Agent, error) {
	return &Agent{options: options}, nil
}

func (agent *Agent) Name() string {
	return "publicwww"
}

func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {

	if session.Keys.PublicwwwToken == "" {
		return nil, errors.New("empty publicwww keys")
	}

	results := make(chan uncover.Result)

	go func() {
		defer close(results)

		numberOfResults := 0

		for {
			publicwwwRequest := &Request{
				Query: query.Query,
				Start: numberOfResults,
			}

			publicwwwResponse := agent.query(publicwwwRequest.buildURL(session.Keys.PublicwwwToken), session, results)
			if publicwwwResponse == nil {
				break
			}

			if numberOfResults > query.Limit || len(publicwwwResponse) == 0 {
				break
			}

			numberOfResults += len(publicwwwResponse)
		}
	}()

	return results, nil
}

func (agent *Agent) query(URL string, session *uncover.Session, results chan uncover.Result) []string {
	resp, err := agent.queryURL(session, URL)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	content := string(body)
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		result := uncover.Result{Source: agent.Name()}
		result.Host = line
		results <- result
		trimmedLine := strings.TrimRight(line, " \r\n\t")
		if trimmedLine != "" {
			lines = append(lines, trimmedLine)
		}
	}

	return lines
}

func (agent *Agent) queryURL(session *uncover.Session, URL string) (*http.Response, error) {
	request, err := uncover.NewHTTPRequest(
		http.MethodGet,
		URL,
		nil,
	)
	if err != nil {
		return nil, err
	}

	agent.options.RateLimiter.Take()
	return session.Do(request)
}
