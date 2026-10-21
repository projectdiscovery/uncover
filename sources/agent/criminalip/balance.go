package criminalip

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
	UserInfoURL = "https://api.criminalip.io/v1/user/me"
)

type UserInfoResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Data    struct {
		Email      string `json:"email"`
		Membership string `json:"membership"`
		QueryCount int64  `json:"query_count"`
		QueryLimit int64  `json:"query_limit"`
	} `json:"data"`
}

func (agent *Agent) Balance(ctx context.Context, session *sources.Session) (*sources.AccountBalance, error) {
	if session.Keys.CriminalIPToken == "" {
		return nil, errors.New("empty criminalip keys")
	}

	request, err := sources.NewHTTPRequest(ctx, http.MethodPost, UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("x-api-key", session.Keys.CriminalIPToken)

	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var userInfo UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	details := map[string]string{}
	if userInfo.Data.Membership != "" {
		details["Membership"] = userInfo.Data.Membership
	}
	var remaining int64 = -1
	if userInfo.Data.QueryLimit > 0 {
		details["Query Limit"] = strconv.FormatInt(userInfo.Data.QueryLimit, 10)
		details["Query Count"] = strconv.FormatInt(userInfo.Data.QueryCount, 10)
		remaining = userInfo.Data.QueryLimit - userInfo.Data.QueryCount
		details["Remaining"] = strconv.FormatInt(remaining, 10)
	}
	if userInfo.Data.Email != "" {
		details["Email"] = userInfo.Data.Email
	}

	msg := "Membership: " + userInfo.Data.Membership
	if remaining >= 0 {
		msg += fmt.Sprintf(" | Remaining: %d / %d", remaining, userInfo.Data.QueryLimit)
	}

	return &sources.AccountBalance{
		Engine:    agent.Name(),
		Remaining: remaining,
		Details:   details,
		Message:   msg,
	}, nil
}
