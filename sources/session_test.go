package sources

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestSessionRetry(t *testing.T) {
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		time.Sleep(10 * time.Second)
		t.Log("Slept for 10 seconds")
	}))
	ts := httptest.NewServer(router)
	engines := []string{"shodan", "publicwww"}
	session, err := NewSession(&Keys{}, 5, 3, 60, engines, time.Second, "")
	require.Nil(t, err)
	req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.Nil(t, err)
	resp, err := session.Do(req, engines[0])
	t.Log(resp, err)
	require.ErrorContains(t, err, "giving up after 6 attempts")
	require.Nil(t, resp)
}

func TestSessionVerifiesTLS(t *testing.T) {
	var requests atomic.Int64
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer ts.Close()
	engines := []string{"shodan"}
	session, err := NewSession(&Keys{}, 0, 5, 0, engines, time.Second, "")
	require.Nil(t, err)
	req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL+"/?key=test-key", nil)
	require.Nil(t, err)
	_, err = session.Do(req, engines[0])
	require.ErrorContains(t, err, "certificate")
	require.Zero(t, requests.Load(), "the engine key went to an untrusted server")
}
