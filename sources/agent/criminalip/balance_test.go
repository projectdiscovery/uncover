package criminalip

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

func TestCriminalIPBalance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "test-criminalip-token", r.Header.Get("x-api-key"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":200,"message":"success","data":{"email":"cip@example.com","membership":"Pro","query_count":30,"query_limit":100}}`)
	}))
	defer ts.Close()

	originalURL := UserInfoURL
	UserInfoURL = ts.URL
	defer func() { UserInfoURL = originalURL }()

	keys := &sources.Keys{CriminalIPToken: "test-criminalip-token"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"criminalip"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)

	require.Equal(t, "criminalip", balance.Engine)
	require.Equal(t, int64(70), balance.Remaining)
	require.Equal(t, "Pro", balance.Details["Membership"])
	require.Equal(t, "100", balance.Details["Query Limit"])
	require.Equal(t, "30", balance.Details["Query Count"])
	require.Equal(t, "70", balance.Details["Remaining"])
	require.Equal(t, "cip@example.com", balance.Details["Email"])
	require.Contains(t, balance.Message, "Membership: Pro")
	require.Contains(t, balance.Message, "Remaining: 70 / 100")
}

func TestCriminalIPBalanceEmptyKeys(t *testing.T) {
	keys := &sources.Keys{}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"criminalip"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty criminalip keys")
}
