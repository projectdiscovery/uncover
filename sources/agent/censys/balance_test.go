package censys

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

func TestCensysBalance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		user, pass, ok := r.BasicAuth()
		require.True(t, ok)
		require.Equal(t, "test-token", user)
		require.Equal(t, "test-org", pass)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"email":"test@example.com","quota":{"allowance":250,"used":15,"resets_at":"2026-11-01 00:00:00"}}`)
	}))
	defer ts.Close()

	originalURL := AccountURL
	AccountURL = ts.URL
	defer func() { AccountURL = originalURL }()

	keys := &sources.Keys{CensysToken: "test-token", CensysOrgId: "test-org"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"censys"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)

	require.Equal(t, "censys", balance.Engine)
	require.Equal(t, int64(235), balance.Remaining)
	require.Equal(t, "250", balance.Details["Allowance"])
	require.Equal(t, "15", balance.Details["Used"])
	require.Equal(t, "235", balance.Details["Remaining"])
	require.Equal(t, "2026-11-01 00:00:00", balance.Details["Resets At"])
	require.Equal(t, "test@example.com", balance.Details["Email"])
	require.Contains(t, balance.Message, "Remaining: 235 / 250 (Used: 15)")
}

func TestCensysBalanceEmptyKeys(t *testing.T) {
	keys := &sources.Keys{CensysToken: "test-token"} // Missing OrgId
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"censys"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty censys keys")
}
