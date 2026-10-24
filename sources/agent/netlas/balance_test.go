package netlas

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

func TestNetlasBalance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "test-netlas-token", r.Header.Get("X-Api-Key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"email":"netlas@example.com","coins":75,"plan":"business"}`)
	}))
	defer ts.Close()

	originalURL := UserInfoURL
	UserInfoURL = ts.URL
	defer func() { UserInfoURL = originalURL }()

	keys := &sources.Keys{NetlasToken: "test-netlas-token"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"netlas"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)

	require.Equal(t, "netlas", balance.Engine)
	require.Equal(t, int64(75), balance.Remaining)
	require.Equal(t, "75", balance.Details["Coins"])
	require.Equal(t, "business", balance.Details["Plan"])
	require.Equal(t, "netlas@example.com", balance.Details["Email"])
	require.Equal(t, "Coins: 75", balance.Message)
}

func TestNetlasBalanceEmptyKeys(t *testing.T) {
	keys := &sources.Keys{}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"netlas"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty netlas keys")
}
