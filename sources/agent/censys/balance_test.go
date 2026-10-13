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
	require.Contains(t, CreditsURL, "api.platform.censys.io")
	require.NotContains(t, CreditsURL, "search.censys.io")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v3/accounts/organizations/test-org/credits", r.URL.Path)
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		_, _, ok := r.BasicAuth()
		require.False(t, ok)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":{"balance":235,"uid":"test-org","auto_replenish_config":{"enabled":false},"credit_expirations":[]}}`)
	}))
	defer ts.Close()

	originalURL := CreditsURL
	CreditsURL = ts.URL + "/v3/accounts/organizations/%s/credits"
	defer func() { CreditsURL = originalURL }()

	keys := &sources.Keys{CensysToken: "test-token", CensysOrgId: "test-org"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"censys"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)

	require.Equal(t, "censys", balance.Engine)
	require.Equal(t, int64(235), balance.Remaining)
	require.Equal(t, "235", balance.Details["Credits"])
	require.Equal(t, "test-org", balance.Details["Organization"])
	require.Equal(t, "Credits: 235", balance.Message)
}

func TestCensysBalanceEmptyKeys(t *testing.T) {
	keys := &sources.Keys{CensysToken: "test-token"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"censys"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty censys keys")
}

func TestCensysBalanceHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()

	originalURL := CreditsURL
	CreditsURL = ts.URL + "/v3/accounts/organizations/%s/credits"
	defer func() { CreditsURL = originalURL }()

	keys := &sources.Keys{CensysToken: "test-token", CensysOrgId: "test-org"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"censys"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "401")
}
