package google

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

func TestResolveURL(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "empty host returns google endpoint",
			host: "",
			want: "https://www.googleapis.com/customsearch/v1",
		},
		{
			name: "bare host adds scheme and path",
			host: "search.example.com",
			want: "https://search.example.com/customsearch/v1",
		},
		{
			name: "full URL without path appends default path",
			host: "https://search.example.com/",
			want: "https://search.example.com/customsearch/v1",
		},
		{
			name: "full URL with custom path preserves custom path",
			host: "https://search.example.com/api/customsearch/v1/",
			want: "https://search.example.com/api/customsearch/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ResolveURL(tt.host))
		})
	}
}

func TestBuildURLDefault(t *testing.T) {
	request := &Request{SearchTerms: "jira", Count: 10, StartIndex: 1}
	got := request.buildURL(ResolveURL(""), "test-key", "test-cx")
	require.Equal(t, "https://www.googleapis.com/customsearch/v1?key=test-key&cx=test-cx&q=jira&start=1&num=10", got)
}

func TestGoogleQueryWithCustomHost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/customsearch/v1", r.URL.Path)
		require.Equal(t, "test-key", r.URL.Query().Get("key"))
		require.Equal(t, "test-cx", r.URL.Query().Get("cx"))
		require.Equal(t, "jira", r.URL.Query().Get("q"))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("start") != "1" {
			_, _ = fmt.Fprint(w, `{"items":[]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"items":[{"link":"https://jira.example.com/login"}]}`)
	}))
	defer ts.Close()

	keys := &sources.Keys{
		GoogleKey:  "test-key",
		GoogleCX:   "test-cx",
		GoogleHost: ts.URL,
	}
	session, err := sources.NewSession(keys, 1, 5, 0, []string{"google"}, time.Second, "")
	require.NoError(t, err)

	agent := &Agent{}
	results, err := agent.Query(context.Background(), session, &sources.Query{Query: "jira", Limit: 1})
	require.NoError(t, err)

	var gotResults []sources.Result
	for r := range results {
		gotResults = append(gotResults, r)
	}

	require.Len(t, gotResults, 1)
	require.NoError(t, gotResults[0].Error)
	require.Equal(t, "https://jira.example.com/login", gotResults[0].Url)
	require.Equal(t, "jira.example.com", gotResults[0].Host)
}
