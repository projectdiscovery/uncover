package zoomeye

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func TestZoomEyeBalance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "test-zoomeye-token", r.Header.Get("API-KEY"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"code":60000,"message":"success","plan":"standard","points":15000,"zoomeye_points":300}`)
	}))
	defer ts.Close()

	originalURL := UserInfoURL
	UserInfoURL = ts.URL
	defer func() { UserInfoURL = originalURL }()

	keys := &sources.Keys{ZoomEyeToken: "test-zoomeye-token"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"zoomeye"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)

	require.Equal(t, "zoomeye", balance.Engine)
	require.Equal(t, int64(15000), balance.Remaining)
	require.Equal(t, "15000", balance.Details["Points"])
	require.Equal(t, "300", balance.Details["ZoomEye Points"])
	require.Equal(t, "standard", balance.Details["Plan"])
	require.Contains(t, balance.Message, "Points: 15000")
	require.Contains(t, balance.Message, "ZoomEye Points: 300")
}

func TestZoomEyeBalanceEmptyKeys(t *testing.T) {
	keys := &sources.Keys{}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"zoomeye"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty zoomeye keys")
}
