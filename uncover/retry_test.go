package uncover

import (
"net/http"
"net/http/httptest"
"testing"
"time"

"github.com/julienschmidt/httprouter"
"github.com/stretchr/testify/require"
)

func TestSessionRetry(t *testing.T) {
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		time.Sleep(10 * time.Minute)
	}))
	ts := httptest.NewServer(router)
	session, err := NewSession(&Keys{}, 5, 1)
	require.Nil(t, err)
	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	require.Nil(t, err)
	resp, err := session.Do(req)
	t.Log(resp, err)
	require.ErrorContains(t, err, "giving up after 5 attempts")
	require.Nil(t, resp)
}


