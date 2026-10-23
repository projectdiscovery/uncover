package fofa

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
	AccountInfoURL = "https://fofa.info/api/v1/info/my?key=%s"
)

type AccountInfoResponse struct {
	Error           bool   `json:"error"`
	Errmsg          string `json:"errmsg,omitempty"`
	Email           string `json:"email"`
	Username        string `json:"username"`
	FofaPoint       int64  `json:"fofa_point"`
	RemainFreePoint int64  `json:"remain_free_point"`
	RemainAPIQuery  int64  `json:"remain_api_query"`
	RemainAPIData   int64  `json:"remain_api_data"`
	IsVIP           bool   `json:"is_vip"`
	VIPLevel        int    `json:"vip_level"`
}

func (agent *Agent) Balance(ctx context.Context, session *sources.Session) (*sources.AccountBalance, error) {
	if session.Keys.FofaKey == "" {
		return nil, errors.New("empty fofa keys")
	}

	apiURL := fmt.Sprintf(AccountInfoURL, session.Keys.FofaKey)
	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var accountResp AccountInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&accountResp); err != nil {
		return nil, err
	}

	if accountResp.Error {
		return nil, fmt.Errorf("fofa error: %s", accountResp.Errmsg)
	}

	details := map[string]string{
		"Remaining Queries": strconv.FormatInt(accountResp.RemainAPIQuery, 10),
		"Remaining Data":    strconv.FormatInt(accountResp.RemainAPIData, 10),
		"FOFA Points":       strconv.FormatInt(accountResp.FofaPoint, 10),
	}
	if accountResp.Email != "" {
		details["Email"] = accountResp.Email
	}

	return &sources.AccountBalance{
		Engine:    agent.Name(),
		Remaining: accountResp.RemainAPIQuery,
		Details:   details,
		Message:   fmt.Sprintf("Remaining Queries: %d | Remaining Data: %d | FOFA Points: %d", accountResp.RemainAPIQuery, accountResp.RemainAPIData, accountResp.FofaPoint),
	}, nil
}
