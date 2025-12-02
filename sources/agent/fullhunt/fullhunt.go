package fullhunt

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wjlin0/uncover/sources"
	util "github.com/wjlin0/uncover/utils"
	"net/http"
)

const (
	URL         = "https://fullhunt.io/api/v1/domain/%s/subdomains"
	Source      = "fullhunt"
	contentType = "application/json"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return Source
}

type fullhuntRequest struct {
	Domain string `json:"domain"`
}
type response struct {
	Domain   string    `json:"domain"`
	Hosts    []string  `json:"hosts"`
	Message  string    `json:"message"`
	Metadata *metadata `json:"metadata"`
	Status   int       `json:"status"`
}
type metadata struct {
	AllResultsCount        int    `json:"all_results_count"`
	AvailableResultForUser int    `json:"available_results_for_user"`
	Domain                 string `json:"domain"`
	LastScanned            int    `json:"last_scanned"`
	MaxResultsForUser      int    `json:"max_results_for_user"`
	Timestamp              int    `json:"timestamp"`
	UserPlan               string `json:"user_plan"`
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.FullHuntToken == "" {
		return nil, errors.New(fmt.Sprintf("empty %s keys please read docs %s on how to add keys ", Source, "https://github.com/wjlin0/uncover?tab=readme-ov-file#provider-configuration"))
	}

	results := make(chan sources.Result)
	go func() {
		defer close(results)
		var (
			numberOfResults  int
			fullhuntResponse *response
		)

		fullhunt := &fullhuntRequest{
			Domain: query.Query,
		}
		if fullhuntResponse = agent.query(session, URL, fullhunt, results); fullhuntResponse == nil {
			return
		}
		numberOfResults += len(fullhuntResponse.Hosts)

	}()
	return results, nil
}

func (agent *Agent) queryURL(session *sources.Session, URL string, fullhunt *fullhuntRequest) (*http.Response, error) {
	requestURL := fmt.Sprintf(URL, fullhunt.Domain)
	request, err := sources.NewHTTPRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-API-KEY", session.Keys.FullHuntToken)
	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
	}

	return resp, nil
}

func (agent *Agent) query(session *sources.Session, URL string, fullhunt *fullhuntRequest, results chan sources.Result) *response {
	resp, err := agent.queryURL(session, URL, fullhunt)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	defer resp.Body.Close()
	var fullhuntResponse response
	err = json.NewDecoder(resp.Body).Decode(&fullhuntResponse)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	for _, host := range fullhuntResponse.Hosts {
		result := sources.Result{Source: agent.Name()}
		protocol, host, port := util.GetProtocolHostAndPort(host)
		result.Url = fmt.Sprintf("%s://%s:%d", protocol, host, port)
		result.Host = host
		result.IP = host
		result.Port = port
		raw, _ := json.Marshal(result)
		result.Raw = raw
		results <- result
	}

	return &fullhuntResponse
}
