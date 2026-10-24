package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/projectdiscovery/uncover/sources"
)

var (
	ApiInfoURL = "https://api.shodan.io/api-info?key=%s"
)

type ApiInfoResponse struct {
	QueryCredits int    `json:"query_credits"`
	ScanCredits  int    `json:"scan_credits"`
	MonitoredIPs int    `json:"monitored_ips"`
	Plan         string `json:"plan"`
	Unlocked     bool   `json:"unlocked"`
}

func (agent *Agent) Balance(ctx context.Context, session *sources.Session) (*sources.AccountBalance, error) {
	if session.Keys.Shodan == "" {
		return nil, errors.New("empty shodan keys")
	}

	apiURL := fmt.Sprintf(ApiInfoURL, session.Keys.Shodan)
	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var apiInfo ApiInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiInfo); err != nil {
		return nil, err
	}

	details := map[string]string{
		"Query Credits": strconv.Itoa(apiInfo.QueryCredits),
		"Scan Credits":  strconv.Itoa(apiInfo.ScanCredits),
	}
	if apiInfo.Plan != "" {
		details["Plan"] = apiInfo.Plan
	}
	if apiInfo.MonitoredIPs > 0 {
		details["Monitored IPs"] = strconv.Itoa(apiInfo.MonitoredIPs)
	}

	return &sources.AccountBalance{
		Engine:    agent.Name(),
		Remaining: int64(apiInfo.QueryCredits),
		Details:   details,
		Message:   fmt.Sprintf("Query Credits: %d | Scan Credits: %d", apiInfo.QueryCredits, apiInfo.ScanCredits),
	}, nil
}
