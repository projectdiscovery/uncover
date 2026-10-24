package shodan

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

func TestShodanBalance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.RawQuery, "key=test-shodan-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"query_credits":100,"scan_credits":25,"monitored_ips":5,"plan":"dev","unlocked":true}`)
	}))
	defer ts.Close()

	originalURL := ApiInfoURL
	ApiInfoURL = ts.URL + "?key=%s"
	defer func() { ApiInfoURL = originalURL }()

	keys := &sources.Keys{Shodan: "test-shodan-key"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"shodan"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)

	require.Equal(t, "shodan", balance.Engine)
	require.Equal(t, int64(100), balance.Remaining)
	require.Equal(t, "100", balance.Details["Query Credits"])
	require.Equal(t, "25", balance.Details["Scan Credits"])
	require.Equal(t, "5", balance.Details["Monitored IPs"])
	require.Equal(t, "dev", balance.Details["Plan"])
	require.Contains(t, balance.Message, "Query Credits: 100")
	require.Contains(t, balance.Message, "Scan Credits: 25")
}

func TestShodanBalanceEmptyKeys(t *testing.T) {
	keys := &sources.Keys{}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"shodan"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty shodan keys")
}
