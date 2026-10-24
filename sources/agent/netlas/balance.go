package netlas

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
	UserInfoURL = "https://app.netlas.io/api/users/current/"
)

type UserInfoResponse struct {
	Email   string `json:"email"`
	Coins   int64  `json:"coins"`
	Balance int64  `json:"balance"`
	Plan    string `json:"plan"`
}

func (agent *Agent) Balance(ctx context.Context, session *sources.Session) (*sources.AccountBalance, error) {
	if session.Keys.NetlasToken == "" {
		return nil, errors.New("empty netlas keys")
	}

	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Api-Key", session.Keys.NetlasToken)

	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var userInfo UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	coins := userInfo.Coins
	if coins == 0 && userInfo.Balance != 0 {
		coins = userInfo.Balance
	}

	details := map[string]string{
		"Coins": strconv.FormatInt(coins, 10),
	}
	if userInfo.Plan != "" {
		details["Plan"] = userInfo.Plan
	}
	if userInfo.Email != "" {
		details["Email"] = userInfo.Email
	}

	return &sources.AccountBalance{
		Engine:    agent.Name(),
		Remaining: coins,
		Details:   details,
		Message:   fmt.Sprintf("Coins: %d", coins),
	}, nil
}
