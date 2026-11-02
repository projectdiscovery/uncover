package subdomaincenter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func TestQuery_Anonymous(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "ammonites", r.URL.Query().Get("engine"))
		require.Equal(t, "admin", r.URL.Query().Get("keyword"))
		require.Empty(t, r.Header.Get("X-API-Key"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]string{
			"admin.example.com",
			"portal.admin.corp.net",
		})
	}))
	t.Cleanup(ts.Close)

	originalURL := URL
	URL = ts.URL
	t.Cleanup(func() { URL = originalURL })

	session, err := sources.NewSession(&sources.Keys{}, 0, 5, 60, []string{"subdomaincenter"}, time.Second, "")
	require.NoError(t, err)

	ctx := context.Background()
	agent := &Agent{}
	require.Equal(t, "subdomaincenter", agent.Name())

	ch, err := agent.Query(ctx, session, &sources.Query{Query: "admin", Limit: 10})
	require.NoError(t, err)

	var results []sources.Result
	for res := range ch {
		results = append(results, res)
	}

	require.Len(t, results, 2)
	require.Equal(t, "admin.example.com", results[0].Host)
	require.Equal(t, "portal.admin.corp.net", results[1].Host)
	require.NoError(t, results[0].Error)
	require.NoError(t, results[1].Error)
}

func TestQuery_AuthenticatedPagination(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		require.Equal(t, "ammonites", r.URL.Query().Get("engine"))
		require.Equal(t, "staging", r.URL.Query().Get("keyword"))
		require.Equal(t, "secret-key", r.Header.Get("X-API-Key"))

		w.Header().Set("Content-Type", "application/json")
		if count == 1 {
			w.Header().Set("X-Truncated", "true")
			w.Header().Set("X-Next-Offset", "2")
			_ = json.NewEncoder(w).Encode([]string{"stage1.example.com", "stage2.example.com"})
		} else {
			w.Header().Set("X-Truncated", "false")
			_ = json.NewEncoder(w).Encode([]string{"stage3.example.com"})
		}
	}))
	t.Cleanup(ts.Close)

	originalURL := URL
	URL = ts.URL
	t.Cleanup(func() { URL = originalURL })

	session, err := sources.NewSession(&sources.Keys{SubdomainCenterToken: "secret-key"}, 0, 5, 60, []string{"subdomaincenter"}, time.Second, "")
	require.NoError(t, err)

	ctx := context.Background()
	agent := &Agent{}

	ch, err := agent.Query(ctx, session, &sources.Query{Query: "staging", Limit: 5})
	require.NoError(t, err)

	var hosts []string
	for res := range ch {
		require.NoError(t, res.Error)
		hosts = append(hosts, res.Host)
	}

	require.Equal(t, int32(2), atomic.LoadInt32(&requestCount))
	require.Equal(t, []string{"stage1.example.com", "stage2.example.com", "stage3.example.com"}, hosts)
}

func TestQuery_EmptyResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "[]")
	}))
	t.Cleanup(ts.Close)

	originalURL := URL
	URL = ts.URL
	t.Cleanup(func() { URL = originalURL })

	session, err := sources.NewSession(&sources.Keys{}, 0, 5, 60, []string{"subdomaincenter"}, time.Second, "")
	require.NoError(t, err)

	ch, err := (&Agent{}).Query(context.Background(), session, &sources.Query{Query: "nonexistent", Limit: 10})
	require.NoError(t, err)

	var count int
	for range ch {
		count++
	}
	require.Equal(t, 0, count)
}

func TestQuery_RespectsContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var items []string
		for i := 0; i < 500; i++ {
			items = append(items, fmt.Sprintf("sub%d.domain.com", i))
		}
		_ = json.NewEncoder(w).Encode(items)
	}))
	t.Cleanup(ts.Close)

	originalURL := URL
	URL = ts.URL
	t.Cleanup(func() { URL = originalURL })

	session, err := sources.NewSession(&sources.Keys{}, 0, 5, 60, []string{"subdomaincenter"}, time.Second, "")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ch, err := (&Agent{}).Query(ctx, session, &sources.Query{Query: "test", Limit: 1000})
	require.NoError(t, err)

	// Consume 2 results
	select {
	case _, ok := <-ch:
		require.True(t, ok)
	case <-time.After(2 * time.Second):
		t.Fatal("no results received")
	}

	cancel()

	// Goroutine must exit and close ch without hanging
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine did not exit cleanly after cancellation")
	}
}
