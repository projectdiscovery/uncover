package hunter

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

func TestHunterBalance(t *testing.T) {
	require.Contains(t, UserInfoURL, "/openApi/userInfo")
	require.NotContains(t, UserInfoURL, "search=")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "test-hunter-key", r.URL.Query().Get("api-key"))
		require.Empty(t, r.URL.Query().Get("search"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"code":200,"message":"success","data":{"rest_free_point":10,"rest_equity_point":100,"type":"个人账号","personal_info":{"user_name":"hunter-user"}}}`)
	}))
	defer ts.Close()

	originalURL := UserInfoURL
	UserInfoURL = ts.URL + "?api-key=%s"
	defer func() { UserInfoURL = originalURL }()

	keys := &sources.Keys{HunterToken: "test-hunter-key"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"hunter"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)

	require.Equal(t, "hunter", balance.Engine)
	require.Equal(t, int64(110), balance.Remaining)
	require.Equal(t, "10", balance.Details["Free Points"])
	require.Equal(t, "100", balance.Details["Equity Points"])
	require.Equal(t, "个人账号", balance.Details["Account Type"])
	require.Equal(t, "hunter-user", balance.Details["Username"])
	require.Contains(t, balance.Message, "Free Points: 10")
	require.Contains(t, balance.Message, "Equity Points: 100")
}

func TestHunterBalanceStringCode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":"200","data":{"rest_free_point":4,"rest_equity_point":6}}`)
	}))
	defer ts.Close()

	originalURL := UserInfoURL
	UserInfoURL = ts.URL + "?api-key=%s"
	defer func() { UserInfoURL = originalURL }()

	keys := &sources.Keys{HunterToken: "test-hunter-key"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"hunter"}, time.Second, "")
	require.NoError(t, err)

	balance, err := (&Agent{}).Balance(context.Background(), session)
	require.NoError(t, err)
	require.Equal(t, int64(10), balance.Remaining)
}

func TestHunterBalanceEmptyKeys(t *testing.T) {
	keys := &sources.Keys{}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"hunter"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty hunter keys")
}

func TestHunterBalanceErrorCode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"code":401,"message":"invalid api key"}`)
	}))
	defer ts.Close()

	originalURL := UserInfoURL
	UserInfoURL = ts.URL + "?api-key=%s"
	defer func() { UserInfoURL = originalURL }()

	keys := &sources.Keys{HunterToken: "test-hunter-key"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"hunter"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "hunter error (code 401): invalid api key")
}
