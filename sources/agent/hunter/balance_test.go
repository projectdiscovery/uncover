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
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.RawQuery, "api-key=test-hunter-key")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"code":200,"data":{"total":10,"rest_quota":"1250","consume_quota":"50","arr":[]}}`)
	}))
	defer ts.Close()

	originalURL := URL
	URL = ts.URL + "?api-key=%s&search=%s&page=%d&page_size=%d&is_web=%d&start_time=%s&end_time=%s"
	defer func() { URL = originalURL }()

	keys := &sources.Keys{HunterToken: "test-hunter-key"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"hunter"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)

	require.Equal(t, "hunter", balance.Engine)
	require.Equal(t, int64(1250), balance.Remaining)
	require.Equal(t, "1250", balance.Details["Rest Quota"])
	require.Equal(t, "50", balance.Details["Consume Quota"])
	require.Contains(t, balance.Message, "Remaining Quota: 1250")
	require.Contains(t, balance.Message, "Consumed Quota: 50")
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
		fmt.Fprint(w, `{"code":401,"msg":"invalid api key"}`)
	}))
	defer ts.Close()

	originalURL := URL
	URL = ts.URL + "?api-key=%s&search=%s&page=%d&page_size=%d&is_web=%d&start_time=%s&end_time=%s"
	defer func() { URL = originalURL }()

	keys := &sources.Keys{HunterToken: "test-hunter-key"}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"hunter"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	_, err = agent.Balance(context.Background(), session)
	require.Error(t, err)
	require.Contains(t, err.Error(), "hunter error (code 401): invalid api key")
}
