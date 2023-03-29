package publicwww

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	baseURL      = "https://publicwww.com/"
	baseEndpoint = "websites/"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "publicwww"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.PublicwwwToken == "" {
		return nil, errors.New("empty publicwww keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		numberOfResults := 0

		for {
			publicwwwRequest := &Request{
				Query: query.Query,
			}

			if numberOfResults > query.Limit {
				break
			}

			publicwwwResponse := agent.query(publicwwwRequest.buildURL(session.Keys.PublicwwwToken), session, results)
			if publicwwwResponse == nil {
				break
			}

			if len(publicwwwResponse) == 0 {
				break
			}

			numberOfResults += len(publicwwwResponse)
		}
	}()

	return results, nil
}

func (agent *Agent) query(URL string, session *sources.Session, results chan sources.Result) []string {
	resp, err := agent.queryURL(session, URL)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
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
			results <- sources.Result{Source: agent.Name(), Error: err}
		}

		result := sources.Result{Source: agent.Name()}
		if len(record) > 0 {
			trimmedLine := strings.TrimRight(record[0], " \r\n\t")
			if trimmedLine != "" {
				hostname, err := sources.GetHostname(record[0])
				if err != nil {
					results <- sources.Result{Source: agent.Name(), Error: err}
					continue
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

func (agent *Agent) queryURL(session *sources.Session, URL string) (*http.Response, error) {
	request, err := sources.NewHTTPRequest(
		http.MethodGet,
		URL,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return session.Do(request, agent.Name())
}
