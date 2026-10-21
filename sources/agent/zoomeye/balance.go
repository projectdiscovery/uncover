package zoomeye

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
	UserInfoURL = "https://api.zoomeye.ai/v2/userinfo"
)

type UserInfoResponse struct {
	Code          int    `json:"code"`
	Message       string `json:"message"`
	Plan          string `json:"plan"`
	Points        int64  `json:"points"`
	ZoomEyePoints int64  `json:"zoomeye_points"`
	Data          *struct {
		Plan          string `json:"plan"`
		Points        int64  `json:"points"`
		ZoomEyePoints int64  `json:"zoomeye_points"`
	} `json:"data,omitempty"`
}

func (agent *Agent) Balance(ctx context.Context, session *sources.Session) (*sources.AccountBalance, error) {
	if session.Keys.ZoomEyeToken == "" {
		return nil, errors.New("empty zoomeye keys")
	}

	request, err := sources.NewHTTPRequest(ctx, http.MethodPost, UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("API-KEY", session.Keys.ZoomEyeToken)

	resp, err := session.Do(request, agent.Name())
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var userInfo UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	points := userInfo.Points
	zoomeyePoints := userInfo.ZoomEyePoints
	plan := userInfo.Plan
	if userInfo.Data != nil {
		if points == 0 && userInfo.Data.Points != 0 {
			points = userInfo.Data.Points
		}
		if zoomeyePoints == 0 && userInfo.Data.ZoomEyePoints != 0 {
			zoomeyePoints = userInfo.Data.ZoomEyePoints
		}
		if plan == "" {
			plan = userInfo.Data.Plan
		}
	}

	details := map[string]string{
		"Points":         strconv.FormatInt(points, 10),
		"ZoomEye Points": strconv.FormatInt(zoomeyePoints, 10),
	}
	if plan != "" {
		details["Plan"] = plan
	}

	return &sources.AccountBalance{
		Engine:    agent.Name(),
		Remaining: points,
		Details:   details,
		Message:   fmt.Sprintf("Points: %d | ZoomEye Points: %d", points, zoomeyePoints),
	}, nil
}
