package hunter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/projectdiscovery/uncover/sources"
)

// UserInfoURL reports account points. Unlike the search API, it does not spend quota.
var UserInfoURL = "https://hunter.qianxin.com/openApi/userInfo?api-key=%s"

type apiCode int

func (c *apiCode) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var raw string
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			return err
		}
		*c = apiCode(n)
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*c = apiCode(n)
	return nil
}

type userInfoResponse struct {
	Code    apiCode `json:"code"`
	Msg     string  `json:"msg"`
	Message string  `json:"message"`
	Data    struct {
		RestFreePoint   int64  `json:"rest_free_point"`
		RestEquityPoint int64  `json:"rest_equity_point"`
		Type            string `json:"type"`
		PersonalInfo    struct {
			UserName string `json:"user_name"`
		} `json:"personal_info"`
	} `json:"data"`
}

func (r userInfoResponse) errorText() string {
	if r.Message != "" {
		return r.Message
	}
	return r.Msg
}

func (agent *Agent) Balance(ctx context.Context, session *sources.Session) (*sources.AccountBalance, error) {
	if session.Keys.HunterToken == "" {
		return nil, errors.New("empty hunter keys")
	}

	hunterURL := fmt.Sprintf(UserInfoURL, session.Keys.HunterToken)
	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, hunterURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")

	resp, err := session.Do(request, agent.Name())
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	var userInfo userInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	if userInfo.Code != http.StatusOK {
		return nil, fmt.Errorf("hunter error (code %d): %s", userInfo.Code, userInfo.errorText())
	}

	freePoints := userInfo.Data.RestFreePoint
	equityPoints := userInfo.Data.RestEquityPoint
	details := map[string]string{
		"Free Points":   strconv.FormatInt(freePoints, 10),
		"Equity Points": strconv.FormatInt(equityPoints, 10),
	}
	if userInfo.Data.Type != "" {
		details["Account Type"] = userInfo.Data.Type
	}
	if userInfo.Data.PersonalInfo.UserName != "" {
		details["Username"] = userInfo.Data.PersonalInfo.UserName
	}

	return &sources.AccountBalance{
		Engine:    agent.Name(),
		Remaining: freePoints + equityPoints,
		Details:   details,
		Message:   fmt.Sprintf("Free Points: %d | Equity Points: %d", freePoints, equityPoints),
	}, nil
}
