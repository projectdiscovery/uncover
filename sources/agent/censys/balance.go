package censys

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
	AccountURL = "https://search.censys.io/api/v1/account"
)

type AccountResponse struct {
	Email string `json:"email"`
	Quota struct {
		Allowance int64  `json:"allowance"`
		Used      int64  `json:"used"`
		ResetsAt  string `json:"resets_at"`
	} `json:"quota"`
}

func (agent *Agent) Balance(ctx context.Context, session *sources.Session) (*sources.AccountBalance, error) {
	if session.Keys.CensysToken == "" || session.Keys.CensysOrgId == "" {
		return nil, errors.New("empty censys keys")
	}

	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, AccountURL, nil)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(session.Keys.CensysToken, session.Keys.CensysOrgId)

	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var accountResp AccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&accountResp); err != nil {
		return nil, err
	}

	remaining := accountResp.Quota.Allowance - accountResp.Quota.Used
	details := map[string]string{
		"Allowance": strconv.FormatInt(accountResp.Quota.Allowance, 10),
		"Used":      strconv.FormatInt(accountResp.Quota.Used, 10),
		"Remaining": strconv.FormatInt(remaining, 10),
	}
	if accountResp.Quota.ResetsAt != "" {
		details["Resets At"] = accountResp.Quota.ResetsAt
	}
	if accountResp.Email != "" {
		details["Email"] = accountResp.Email
	}

	return &sources.AccountBalance{
		Engine:    agent.Name(),
		Remaining: remaining,
		Details:   details,
		Message:   fmt.Sprintf("Remaining: %d / %d (Used: %d)", remaining, accountResp.Quota.Allowance, accountResp.Quota.Used),
	}, nil
}
