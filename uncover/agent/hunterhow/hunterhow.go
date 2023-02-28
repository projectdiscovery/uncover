package hunterhow

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/projectdiscovery/uncover/uncover"
)

const (
	baseURL      = "https://api.hunter.how/"
	baseEndpoint = "search/"
	Size         = 100
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
	return "hunterhow"
}

func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	if session.Keys.HunterHowToken == "" {
		return nil, errors.New("empty hunterhow keys")
	}

	results := make(chan uncover.Result)

	go func() {
		defer close(results)

		numberOfResults := 0

		pageQuery := 1

		for {
			hunterhowRequest := &Request{
				Query:    query.Query,
				PageSize: query.Limit,
				Page:     pageQuery,
			}

			if numberOfResults > query.Limit {
				break
			}

			hunterhowResponse := agent.query(hunterhowRequest.buildURL(session.Keys.HunterHowToken), session, results)
			if hunterhowResponse == nil {
				break
			}

			if len(hunterhowResponse) == 0 {
				break
			}

			numberOfResults += len(hunterhowResponse)
			pageQuery += 1
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- uncover.Result{Source: agent.Name(), Error: err}
		return nil
	}
	content := string(body)
	reader := csv.NewReader(strings.NewReader(content))
	reader.Comma = ';'

	var lines []string
	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			results <- uncover.Result{Source: agent.Name(), Error: err}
		}

		result := uncover.Result{Source: agent.Name()}
		if len(record) > 0 {
			trimmedLine := strings.TrimRight(record[0], " \r\n\t")
			if trimmedLine != "" {
				hostname, err := uncover.GetHostname(record[0])
				if err != nil {
					results <- uncover.Result{Source: agent.Name(), Error: err}
				}
				result.Host = hostname
				result.Url = record[0]
				raw, _ := json.Marshal(result)
				result.Raw = raw
				results <- result
				lines = append(lines, trimmedLine)
			}
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
