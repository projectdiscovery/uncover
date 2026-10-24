package quake

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

func TestQuakeBalance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "test-quake-token", r.Header.Get("X-QuakeToken"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"code":0,"message":"Successful.","data":{"user_id":"u-123","email":"quake@example.com","credit":500,"month_remaining_quota":3000,"total_remaining_quota":8000}}`)
	}))
	defer ts.Close()

	originalURL := UserInfoURL
	UserInfoURL = ts.URL
	defer func() { UserInfoURL = originalURL }()

	keys := &sources.Keys{QuakeToken: "test-quake-token"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"quake"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)

	require.Equal(t, "quake", balance.Engine)
	require.Equal(t, int64(3000), balance.Remaining)
	require.Equal(t, "500", balance.Details["Credit"])
	require.Equal(t, "3000", balance.Details["Monthly Remaining Quota"])
	require.Equal(t, "8000", balance.Details["Total Remaining Quota"])
	require.Equal(t, "quake@example.com", balance.Details["Email"])
	require.Contains(t, balance.Message, "Monthly Remaining Quota: 3000")
	require.Contains(t, balance.Message, "Credit: 500")
}

func TestQuakeBalanceErrorCode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"code":401,"message":"Authentication failed"}`)
	}))
	defer ts.Close()

	originalURL := UserInfoURL
	UserInfoURL = ts.URL
	defer func() { UserInfoURL = originalURL }()

	keys := &sources.Keys{QuakeToken: "invalid-token"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"quake"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Authentication failed")
}

func TestQuakeBalanceEmptyKeys(t *testing.T) {
	keys := &sources.Keys{}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"quake"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty quake keys")
}
