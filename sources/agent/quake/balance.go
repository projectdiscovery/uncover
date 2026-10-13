package quake

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
	UserInfoURL = "https://quake.360.net/api/v3/user/info"
)

type UserInfoResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		UserID              string `json:"user_id"`
		Email               string `json:"email"`
		Credit              int64  `json:"credit"`
		MonthRemainingQuota int64  `json:"month_remaining_quota"`
		TotalRemainingQuota int64  `json:"total_remaining_quota"`
	} `json:"data"`
}

func (agent *Agent) Balance(ctx context.Context, session *sources.Session) (*sources.AccountBalance, error) {
	if session.Keys.QuakeToken == "" {
		return nil, errors.New("empty quake keys")
	}

	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-QuakeToken", session.Keys.QuakeToken)

	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userInfo UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	if userInfo.Code != 0 {
		return nil, fmt.Errorf("quake error (code %d): %s", userInfo.Code, userInfo.Message)
	}

	details := map[string]string{
		"Credit":                  strconv.FormatInt(userInfo.Data.Credit, 10),
		"Monthly Remaining Quota": strconv.FormatInt(userInfo.Data.MonthRemainingQuota, 10),
		"Total Remaining Quota":   strconv.FormatInt(userInfo.Data.TotalRemainingQuota, 10),
	}
	if userInfo.Data.Email != "" {
		details["Email"] = userInfo.Data.Email
	}

	return &sources.AccountBalance{
		Engine:    agent.Name(),
		Remaining: userInfo.Data.MonthRemainingQuota,
		Details:   details,
		Message:   fmt.Sprintf("Monthly Remaining Quota: %d | Credit: %d", userInfo.Data.MonthRemainingQuota, userInfo.Data.Credit),
	}, nil
}
