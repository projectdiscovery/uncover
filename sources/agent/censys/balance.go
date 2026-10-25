package censys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/projectdiscovery/uncover/sources"
)

// CreditsURL is the Platform account endpoint. It uses the same personal
// access token and organization ID as search, and it does not spend credits.
var CreditsURL = "https://api.platform.censys.io/v3/accounts/organizations/%s/credits"

type creditsResponse struct {
	Result struct {
		Balance int64  `json:"balance"`
		UID     string `json:"uid"`
	} `json:"result"`
}

func (agent *Agent) Balance(ctx context.Context, session *sources.Session) (*sources.AccountBalance, error) {
	if session.Keys.CensysToken == "" || session.Keys.CensysOrgId == "" {
		return nil, errors.New("empty censys keys")
	}

	creditsURL := fmt.Sprintf(CreditsURL, url.PathEscape(session.Keys.CensysOrgId))
	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, creditsURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+session.Keys.CensysToken)
	request.Header.Set("Accept", "application/json")

	resp, err := session.Do(request, agent.Name())
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		return nil, err
	}

	var credits creditsResponse
	if err := json.NewDecoder(resp.Body).Decode(&credits); err != nil {
		return nil, err
	}

	remaining := credits.Result.Balance
	details := map[string]string{
		"Credits": strconv.FormatInt(remaining, 10),
	}
	if credits.Result.UID != "" {
		details["Organization"] = credits.Result.UID
	}

	return &sources.AccountBalance{
		Engine:    agent.Name(),
		Remaining: remaining,
		Details:   details,
		Message:   fmt.Sprintf("Credits: %d", remaining),
	}, nil
}
