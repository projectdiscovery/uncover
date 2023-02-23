package uncover

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
)

type Session struct {
	Keys       *Keys
	Client     *retryablehttp.Client
	RetryMax   int
	RateLimits map[string]*ratelimit.Limiter
}

func NewSession(keys *Keys, retryMax, timeout, delay int, engines []string) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
		Proxy:                 http.ProxyFromEnvironment,
	}

	httpclient := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	options := retryablehttp.Options{RetryMax: retryMax}
	options.RetryWaitMax = time.Duration(timeout) * time.Second
	client := retryablehttp.NewWithHTTPClient(httpclient, options)

	session := &Session{
		Client:     client,
		Keys:       keys,
		RetryMax:   retryMax,
		RateLimits: make(map[string]*ratelimit.Limiter),
	}

	for _, engine := range engines {
		if delay > 0 {
			session.RateLimits[engine] = ratelimit.New(context.Background(), 1, time.Duration(delay))
		} else {
			session.RateLimits[engine] = ratelimit.NewUnlimited(context.Background())
		}
	}

	return session, nil
}

func (s *Session) Do(request *retryablehttp.Request) (*http.Response, error) {
	// close request connection (does not reuse connections)
	request.Close = true
	resp, err := s.Client.Do(request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(request.URL.String())
		return resp, errors.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
	}
	// var f *os.File
	// var err error
	// if _, _, ok := request.BasicAuth(); ok {
	// 	f, err = os.Open("/Users/marcornvh/go/src/github.com/projectdiscovery/uncover/uncover/agent/censys/example.json")
	// } else {
	// 	f, err = os.Open("/Users/marcornvh/go/src/github.com/projectdiscovery/uncover/uncover/agent/shodan/example.json")
	// }

	if err != nil {
		return nil, err
	}

	// resp := &http.Response{
	// 	StatusCode: 200,
	// 	Body:       f,
	// }
	return resp, nil
}
