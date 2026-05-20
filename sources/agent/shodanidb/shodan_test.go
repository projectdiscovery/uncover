package shodanidb

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

// Producer goroutines must abort their pending channel sends when the caller
// cancels ctx. Without that, the goroutine blocks forever on results <- r once
// the downstream relay (uncover.Service.Execute) has exited via ctx.Done.
func TestQueryRespectsCancelledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"1.2.3.4","ports":[80,443,22,8080,8443,21,25,53,110,143],"hostnames":["a","b","c"]}`)
	}))
	t.Cleanup(ts.Close)

	originalURL := URL
	URL = ts.URL + "/%s"
	t.Cleanup(func() { URL = originalURL })

	session, err := sources.NewSession(&sources.Keys{}, 0, 5, 60, []string{"shodan-idb"}, time.Second, "")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ch, err := (&Agent{}).Query(ctx, session, &sources.Query{Query: "10.0.0.0/24", Limit: 100000})
	require.NoError(t, err)

	select {
	case _, ok := <-ch:
		require.True(t, ok, "expected at least one result before cancel")
	case <-time.After(2 * time.Second):
		t.Fatal("agent produced no results within 2s")
	}

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case _, ok := <-ch:
		require.False(t, ok, "agent still emitting after cancel; producer ignored ctx")
	case <-time.After(2 * time.Second):
		t.Fatal("agent goroutine leaked: channel did not close within 2s after cancel")
	}
}
