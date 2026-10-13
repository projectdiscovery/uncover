package subdomaincenter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func TestNewRequest(t *testing.T) {
	parsed, err := newRequest("vpn domain:example.com match:prefix")
	require.NoError(t, err)
	require.Equal(t, "vpn", parsed.keyword)
	require.Equal(t, "example.com", parsed.domain)
	require.Equal(t, "prefix", parsed.match)

	parsed, err = newRequest("keyword:admin")
	require.NoError(t, err)
	require.Equal(t, "admin", parsed.keyword)

	_, err = newRequest("a")
	require.Error(t, err)

	_, err = newRequest("vpn unknown:value")
	require.Error(t, err)
}

func TestBuildURL(t *testing.T) {
	parsed, err := newRequest("vpn domain:example.com match:prefix")
	require.NoError(t, err)

	anonymous, err := url.Parse(parsed.buildURL(false, 20, 5))
	require.NoError(t, err)
	query := anonymous.Query()
	require.Equal(t, "ammonites", query.Get("engine"))
	require.Equal(t, "vpn", query.Get("keyword"))
	require.Equal(t, "example.com", query.Get("domain"))
	require.Equal(t, "prefix", query.Get("match"))
	require.Empty(t, query.Get("limit"))
	require.Empty(t, query.Get("offset"))
	require.NotContains(t, anonymous.RawQuery, "api")

	authenticated, err := url.Parse(parsed.buildURL(true, 20, 5))
	require.NoError(t, err)
	require.Equal(t, "5", authenticated.Query().Get("limit"))
	require.Equal(t, "20", authenticated.Query().Get("offset"))
}

func TestQueryStopsAtLimit(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.Equal(t, "secret", r.Header.Get("X-API-Key"))
		require.NotContains(t, r.URL.RawQuery, "secret")
		w.Header().Set("X-Truncated", "true")
		w.Header().Set("X-Next-Offset", "2")
		_ = json.NewEncoder(w).Encode([]string{"one.example", "two.example", "three.example"})
	}))
	t.Cleanup(server.Close)

	original := endpoint
	endpoint = server.URL
	t.Cleanup(func() { endpoint = original })

	session, err := sources.NewSession(&sources.Keys{SubdomainCenter: "secret"}, 0, 5, 0, []string{"subdomaincenter"}, time.Second, "")
	require.NoError(t, err)

	ch, err := (&Agent{}).Query(context.Background(), session, &sources.Query{Query: "vpn", Limit: 2})
	require.NoError(t, err)

	var hosts []string
	for result := range ch {
		require.NoError(t, result.Error)
		hosts = append(hosts, result.Host)
	}
	require.Equal(t, []string{"one.example", "two.example"}, hosts)
	require.Equal(t, 1, requests)
}

func TestAnonymousQueryDoesNotPaginate(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.Empty(t, r.Header.Get("X-API-Key"))
		require.Empty(t, r.URL.Query().Get("limit"))
		w.Header().Set("X-Truncated", "true")
		_ = json.NewEncoder(w).Encode([]string{"one.example"})
	}))
	t.Cleanup(server.Close)

	original := endpoint
	endpoint = server.URL
	t.Cleanup(func() { endpoint = original })

	session, err := sources.NewSession(&sources.Keys{}, 0, 5, 0, []string{"subdomaincenter"}, time.Second, "")
	require.NoError(t, err)

	ch, err := (&Agent{}).Query(context.Background(), session, &sources.Query{Query: "vpn", Limit: 10})
	require.NoError(t, err)

	var hosts []string
	for result := range ch {
		require.NoError(t, result.Error)
		hosts = append(hosts, result.Host)
	}
	require.Equal(t, []string{"one.example"}, hosts)
	require.Equal(t, 1, requests)
}

func TestQueryFollowsNextOffset(t *testing.T) {
	var offsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offsets = append(offsets, r.URL.Query().Get("offset"))
		if len(offsets) == 1 {
			w.Header().Set("X-Truncated", "true")
			w.Header().Set("X-Next-Offset", "1")
			_ = json.NewEncoder(w).Encode([]string{"one.example"})
			return
		}
		_ = json.NewEncoder(w).Encode([]string{"two.example"})
	}))
	t.Cleanup(server.Close)

	original := endpoint
	endpoint = server.URL
	t.Cleanup(func() { endpoint = original })

	session, err := sources.NewSession(&sources.Keys{SubdomainCenter: "secret"}, 0, 5, 0, []string{"subdomaincenter"}, time.Second, "")
	require.NoError(t, err)

	ch, err := (&Agent{}).Query(context.Background(), session, &sources.Query{Query: "vpn", Limit: 10})
	require.NoError(t, err)

	var hosts []string
	for result := range ch {
		require.NoError(t, result.Error)
		hosts = append(hosts, result.Host)
	}
	require.Equal(t, []string{"one.example", "two.example"}, hosts)
	require.Equal(t, []string{"0", "1"}, offsets)
}

func TestQueryReportsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	original := endpoint
	endpoint = server.URL
	t.Cleanup(func() { endpoint = original })

	session, err := sources.NewSession(&sources.Keys{}, 0, 5, 0, []string{"subdomaincenter"}, time.Second, "")
	require.NoError(t, err)

	ch, err := (&Agent{}).Query(context.Background(), session, &sources.Query{Query: "vpn", Limit: 10})
	require.NoError(t, err)

	result := <-ch
	require.Error(t, result.Error)
	_, ok := <-ch
	require.False(t, ok)
}
