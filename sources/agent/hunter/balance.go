package hunter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/projectdiscovery/uncover/sources"
)

func (agent *Agent) Balance(ctx context.Context, session *sources.Session) (*sources.AccountBalance, error) {
	if session.Keys.HunterToken == "" {
		return nil, errors.New("empty hunter keys")
	}

	base64Query := base64.URLEncoding.EncodeToString([]byte(`ip="1.1.1.1"`))
	hunterURL := fmt.Sprintf(URL, session.Keys.HunterToken, base64Query, 1, 1, 0, "", "")
	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, hunterURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")

	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var hunterResponse Response
	if err := json.NewDecoder(resp.Body).Decode(&hunterResponse); err != nil {
		return nil, err
	}

	if hunterResponse.Code != http.StatusOK && hunterResponse.Code != 0 && hunterResponse.Msg != "" {
		return nil, fmt.Errorf("hunter error: %s", hunterResponse.Msg)
	}

	details := map[string]string{
		"Rest Quota":    hunterResponse.Data.RestQuota,
		"Consume Quota": hunterResponse.Data.ConsumeQuota,
	}
	remaining, _ := strconv.ParseInt(hunterResponse.Data.RestQuota, 10, 64)

	return &sources.AccountBalance{
		Engine:    agent.Name(),
		Remaining: remaining,
		Details:   details,
		Message:   fmt.Sprintf("Remaining Quota: %s | Consumed Quota: %s", hunterResponse.Data.RestQuota, hunterResponse.Data.ConsumeQuota),
	}, nil
}
