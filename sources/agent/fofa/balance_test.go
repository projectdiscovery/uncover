package fofa

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

func TestFofaBalance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.RawQuery, "key=test-fofa-key")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"error":false,"email":"user@fofa.so","username":"user","remain_api_query":9900,"remain_api_data":10000,"fofa_point":500}`)
	}))
	defer ts.Close()

	originalURL := AccountInfoURL
	AccountInfoURL = ts.URL + "?key=%s"
	defer func() { AccountInfoURL = originalURL }()

	keys := &sources.Keys{FofaKey: "test-fofa-key"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"fofa"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)

	require.Equal(t, "fofa", balance.Engine)
	require.Equal(t, int64(9900), balance.Remaining)
	require.Equal(t, "9900", balance.Details["Remaining Queries"])
	require.Equal(t, "10000", balance.Details["Remaining Data"])
	require.Equal(t, "500", balance.Details["FOFA Points"])
	require.Equal(t, "user@fofa.so", balance.Details["Email"])
	require.Contains(t, balance.Message, "Remaining Queries: 9900")
	require.Contains(t, balance.Message, "FOFA Points: 500")
}

func TestFofaBalanceErrorResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"error":true,"errmsg":"invalid key"}`)
	}))
	defer ts.Close()

	originalURL := AccountInfoURL
	AccountInfoURL = ts.URL + "?key=%s"
	defer func() { AccountInfoURL = originalURL }()

	keys := &sources.Keys{FofaKey: "invalid-key"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"fofa"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid key")
}

func TestFofaBalanceEmptyKeys(t *testing.T) {
	keys := &sources.Keys{}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"fofa"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty fofa keys")
}
