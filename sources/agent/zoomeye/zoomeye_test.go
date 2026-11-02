package zoomeye

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func TestResolveURL(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		defaultURL  string
		defaultPath string
		want        string
	}{
		{
			name:        "empty host returns default URL",
			host:        "",
			defaultURL:  "https://api.zoomeye.ai/v2/search",
			defaultPath: "/v2/search",
			want:        "https://api.zoomeye.ai/v2/search",
		},
		{
			name:        "zoomeye.org adds api prefix and path",
			host:        "zoomeye.org",
			defaultURL:  "https://api.zoomeye.ai/v2/search",
			defaultPath: "/v2/search",
			want:        "https://api.zoomeye.org/v2/search",
		},
		{
			name:        "api.zoomeye.org keeps api prefix and adds path",
			host:        "api.zoomeye.org",
			defaultURL:  "https://api.zoomeye.ai/v2/search",
			defaultPath: "/v2/search",
			want:        "https://api.zoomeye.org/v2/search",
		},
		{
			name:        "full https URL without path appends default path",
			host:        "https://api.zoomeye.org",
			defaultURL:  "https://api.zoomeye.ai/v2/search",
			defaultPath: "/v2/search",
			want:        "https://api.zoomeye.org/v2/search",
		},
		{
			name:        "full https URL with trailing slash appends default path",
			host:        "https://api.zoomeye.org/",
			defaultURL:  "https://api.zoomeye.ai/v2/search",
			defaultPath: "/v2/search",
			want:        "https://api.zoomeye.org/v2/search",
		},
		{
			name:        "full https URL with custom path preserves custom path",
			host:        "https://custom.zoomeye.org/custom/v2/search",
			defaultURL:  "https://api.zoomeye.ai/v2/search",
			defaultPath: "/v2/search",
			want:        "https://custom.zoomeye.org/custom/v2/search",
		},
		{
			name:        "zoomeye.hk userinfo resolution",
			host:        "zoomeye.hk",
			defaultURL:  "https://api.zoomeye.ai/v2/userinfo",
			defaultPath: "/v2/userinfo",
			want:        "https://api.zoomeye.hk/v2/userinfo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveURL(tt.host, tt.defaultURL, tt.defaultPath)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestZoomEyeQueryWithCustomHost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v2/search", r.URL.Path)
		require.Equal(t, "china-region-token", r.Header.Get("API-KEY"))
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var reqBody map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)
		require.NotEmpty(t, reqBody["qbase64"])

		w.Header().Set("Content-Type", "application/json")
		resp := ZoomEyeResponse{
			Total: 1,
			Results: []ZoomEyeResult{
				{
					IP:       "1.1.1.1",
					Port:     443,
					Hostname: "china.zoomeye.org",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	keys := &sources.Keys{
		ZoomEyeToken: "china-region-token",
		ZoomEyeHost:  ts.URL,
	}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"zoomeye"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	results, err := agent.Query(context.Background(), session, &sources.Query{Query: "app:nginx", Limit: 1})
	require.NoError(t, err)

	var gotResults []sources.Result
	for r := range results {
		gotResults = append(gotResults, r)
	}

	require.Len(t, gotResults, 1)
	require.Equal(t, "1.1.1.1", gotResults[0].IP)
	require.Equal(t, 443, gotResults[0].Port)
	require.Equal(t, "china.zoomeye.org", gotResults[0].Host)
}

func TestZoomEyeBalanceWithCustomHost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v2/userinfo", r.URL.Path)
		require.Equal(t, "china-region-token", r.Header.Get("API-KEY"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"code":60000,"message":"success","plan":"china-enterprise","points":99999,"zoomeye_points":888}`)
	}))
	defer ts.Close()

	keys := &sources.Keys{
		ZoomEyeToken: "china-region-token",
		ZoomEyeHost:  ts.URL,
	}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"zoomeye"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	balance, err := agent.Balance(context.Background(), session)
	require.NoError(t, err)
	require.NotNil(t, balance)
	require.Equal(t, int64(99999), balance.Remaining)
	require.Equal(t, "china-enterprise", balance.Details["Plan"])
	require.Equal(t, "888", balance.Details["ZoomEye Points"])
}
