package criminalip

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func TestBuildURL(t *testing.T) {
	testCases := []struct {
		name        string
		request     *CriminalIPRequest
		endpoint    string
		expectedURL string
		expectErr   bool
	}{
		{
			name: "standard query with spaces and colon",
			request: &CriminalIPRequest{
				Query:  "port: 80",
				Offset: 0,
			},
			endpoint:    URL,
			expectedURL: "https://api.criminalip.io/v1/banner/search?query=port%3A+80&offset=0",
			expectErr:   false,
		},
		{
			name: "special characters escaping",
			request: &CriminalIPRequest{
				Query:  `ssl_subject_common_name: "example.com" & status: 200`,
				Offset: 10,
			},
			endpoint:    URL,
			expectedURL: fmt.Sprintf("https://api.criminalip.io/v1/banner/search?query=%s&offset=10", url.QueryEscape(`ssl_subject_common_name: "example.com" & status: 200`)),
			expectErr:   false,
		},
		{
			name: "query with leading and trailing whitespace",
			request: &CriminalIPRequest{
				Query:  "   apache server   ",
				Offset: 20,
			},
			endpoint:    URL,
			expectedURL: "https://api.criminalip.io/v1/banner/search?query=apache+server&offset=20",
			expectErr:   false,
		},
		{
			name: "negative offset defaults to zero",
			request: &CriminalIPRequest{
				Query:  "nginx",
				Offset: -5,
			},
			endpoint:    URL,
			expectedURL: "https://api.criminalip.io/v1/banner/search?query=nginx&offset=0",
			expectErr:   false,
		},
		{
			name: "endpoint without format specifiers uses url query encoding",
			request: &CriminalIPRequest{
				Query:  "redis",
				Offset: 10,
			},
			endpoint:    "https://api.criminalip.io/v1/banner/search",
			expectedURL: "https://api.criminalip.io/v1/banner/search?offset=10&query=redis",
			expectErr:   false,
		},
		{
			name: "empty query returns error",
			request: &CriminalIPRequest{
				Query:  "",
				Offset: 0,
			},
			endpoint:  URL,
			expectErr: true,
		},
		{
			name: "whitespace only query returns error",
			request: &CriminalIPRequest{
				Query:  "   \t\n  ",
				Offset: 0,
			},
			endpoint:  URL,
			expectErr: true,
		},
		{
			name:      "nil request returns error",
			request:   nil,
			endpoint:  URL,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualURL, err := tc.request.buildURL(tc.endpoint)
			if tc.expectErr {
				require.Error(t, err)
				require.Empty(t, actualURL)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectedURL, actualURL)
			}
		})
	}
}

func TestAgentQueryValidation(t *testing.T) {
	agent := &Agent{}
	ctx := context.Background()

	// Empty token
	sessionWithoutKey, err := sources.NewSession(&sources.Keys{}, 0, 5, 60, []string{"criminalip"}, time.Second, "")
	require.NoError(t, err)
	_, err = agent.Query(ctx, sessionWithoutKey, &sources.Query{Query: "test", Limit: 10})
	require.Error(t, err)
	require.Equal(t, "empty criminalip keys", err.Error())

	// Valid token
	sessionWithKey, err := sources.NewSession(&sources.Keys{CriminalIPToken: "dummy-token"}, 0, 5, 60, []string{"criminalip"}, time.Second, "")
	require.NoError(t, err)

	// Nil query
	_, err = agent.Query(ctx, sessionWithKey, nil)
	require.Error(t, err)
	require.Equal(t, "empty criminalip query", err.Error())

	// Empty query string
	_, err = agent.Query(ctx, sessionWithKey, &sources.Query{Query: "", Limit: 10})
	require.Error(t, err)
	require.Equal(t, "empty criminalip query", err.Error())

	// Whitespace query string
	_, err = agent.Query(ctx, sessionWithKey, &sources.Query{Query: "   \n\t  ", Limit: 10})
	require.Error(t, err)
	require.Equal(t, "empty criminalip query", err.Error())
}

func TestQueryMockServerAndEscaping(t *testing.T) {
	var receivedQuery string
	var receivedOffset string
	var receivedAuthHeader string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.Query().Get("query")
		receivedOffset = r.URL.Query().Get("offset")
		receivedAuthHeader = r.Header.Get("x-api-key")

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"message": "Success",
			"data": {
				"count": 1,
				"result": [
					{
						"ip_address": "192.168.1.1",
						"open_port_no": 8080,
						"hostname": "test.local"
					}
				]
			}
		}`)
	}))
	t.Cleanup(ts.Close)

	originalURL := URL
	URL = ts.URL + "/v1/banner/search?query=%s&offset=%d"
	t.Cleanup(func() { URL = originalURL })

	session, err := sources.NewSession(&sources.Keys{CriminalIPToken: "secret-token-123"}, 0, 5, 60, []string{"criminalip"}, time.Second, "")
	require.NoError(t, err)

	ctx := context.Background()
	agent := &Agent{}

	inputQuery := "title: admin portal & status: 200"
	ch, err := agent.Query(ctx, session, &sources.Query{Query: inputQuery, Limit: 1})
	require.NoError(t, err)

	var results []sources.Result
	for res := range ch {
		results = append(results, res)
	}

	require.Equal(t, inputQuery, receivedQuery)
	require.Equal(t, "0", receivedOffset)
	require.Equal(t, "secret-token-123", receivedAuthHeader)
	require.Len(t, results, 1)
	require.Equal(t, "192.168.1.1", results[0].IP)
	require.Equal(t, 8080, results[0].Port)
	require.Equal(t, "test.local", results[0].Host)
	require.Equal(t, "criminalip", results[0].Source)
}

func TestBatchSequentialQueries(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"message": "Success",
			"data": {
				"count": 1,
				"result": [
					{
						"ip_address": "10.0.0.1",
						"open_port_no": 443,
						"hostname": "batch.local"
					}
				]
			}
		}`)
	}))
	t.Cleanup(ts.Close)

	originalURL := URL
	URL = ts.URL + "/v1/banner/search?query=%s&offset=%d"
	t.Cleanup(func() { URL = originalURL })

	session, err := sources.NewSession(&sources.Keys{CriminalIPToken: "test-token"}, 0, 5, 60, []string{"criminalip"}, time.Second, "")
	require.NoError(t, err)

	ctx := context.Background()
	agent := &Agent{}

	queries := []string{
		"query-1",
		"",
		"   ",
		"query-2",
		"query-3",
	}

	successCount := 0
	errorCount := 0

	for _, q := range queries {
		ch, err := agent.Query(ctx, session, &sources.Query{Query: q, Limit: 1})
		if err != nil {
			errorCount++
			continue
		}
		for res := range ch {
			require.NoError(t, res.Error)
			successCount++
		}
	}

	require.Equal(t, 3, successCount)
	require.Equal(t, 2, errorCount)
}

func TestQueryRespectsCancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"status": 200,
			"message": "Success",
			"data": {
				"count": 100,
				"result": [
					{"ip_address": "1.1.1.1", "open_port_no": 80},
					{"ip_address": "1.1.1.2", "open_port_no": 80}
				]
			}
		}`)
	}))
	t.Cleanup(ts.Close)

	originalURL := URL
	URL = ts.URL + "/v1/banner/search?query=%s&offset=%d"
	t.Cleanup(func() { URL = originalURL })

	session, err := sources.NewSession(&sources.Keys{CriminalIPToken: "token"}, 0, 5, 60, []string{"criminalip"}, time.Second, "")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	agent := &Agent{}
	ch, err := agent.Query(ctx, session, &sources.Query{Query: "test", Limit: 1000})
	require.NoError(t, err)

	select {
	case _, ok := <-ch:
		require.True(t, ok, "expected at least one result")
	case <-time.After(2 * time.Second):
		t.Fatal("agent produced no results within 2s")
	}

	cancel()

	select {
	case _, ok := <-ch:
		require.False(t, ok, "agent still emitting after cancel")
	case <-time.After(2 * time.Second):
		t.Fatal("channel did not close after cancel")
	}
}
