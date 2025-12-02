package github

import (
	"encoding/json"
	"errors"
	"fmt"
	util "github.com/projectdiscovery/uncover/utils"
	"net/http"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL     = "https://api.github.com/search/code?q=%s&per_page=%d&page=%d&sort=indexed&access_token=%s"
	PerPage = 100
	Source  = "github"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return Source
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.GithubToken == "" {
		return nil, errors.New(fmt.Sprintf("empty %s keys please read docs %s on how to add keys ", Source, "https://github.com/projectdiscovery/uncover?tab=readme-ov-file#provider-configuration"))
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		var numberOfResults int

		page := 1
		for {
			github := &githubRequest{
				Query:   query.Query,
				PerPage: PerPage,
				Page:    page,
			}
			githubResponse := agent.query(URL, session, github, results)
			if githubResponse == nil {
				break
			}
			size := len(githubResponse)
			if size == 0 || numberOfResults > query.Limit || len(githubResponse) == 0 || numberOfResults > size {
				break
			}
			numberOfResults += len(githubResponse)
			page++
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, githubRequest *githubRequest) (*http.Response, error) {
	githubURL := fmt.Sprintf(URL, githubRequest.Query, githubRequest.PerPage, githubRequest.Page, session.Keys.GithubToken)
	request, err := sources.NewHTTPRequest(http.MethodGet, githubURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github.v3.text-match+json")
	request.Header.Set("Authorization", "token "+session.Keys.GithubToken)
	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, githubURL)
	}
	return resp, nil
}

func (agent *Agent) query(URL string, session *sources.Session, githubRequest *githubRequest, results chan sources.Result) []sources.Result {
	resp, err := agent.queryURL(session, URL, githubRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	var githubResult []sources.Result
	body, err := sources.ReadBody(resp)
	if err != nil {
		return nil
	}
	subdomains := sources.MatchSubdomains(githubRequest.Query, body.String(), true)
	for _, sub := range subdomains {
		result := sources.Result{Source: agent.Name()}
		_, result.Host, result.Port = util.GetProtocolHostAndPort(sub)
		result.IP = result.Host
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}
	return githubResult
}

type githubRequest struct {
	Query   string `json:"query"`
	PerPage int    `json:"per_page"`
	Page    int    `json:"page"`
}
