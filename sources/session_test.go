package sources

import (
	"net/http"
	"net/http/httptest"
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
	session, err := NewSession(&Keys{}, 5, 3, 60, engines, time.Second)
	require.Nil(t, err)
	req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.Nil(t, err)
	resp, err := session.Do(req, engines[0])
	t.Log(resp, err)
	require.ErrorContains(t, err, "giving up after 6 attempts")
	require.Nil(t, resp)
}
