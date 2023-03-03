package uncover

import (
	"context"
	"crypto/tls"
	"fmt"
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
	RateLimits *ratelimit.MultiLimiter
}

func NewSession(keys *Keys, retryMax, timeout, rateLimit int, engines []string, duration time.Duration) (*Session, error) {
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

	var defaultRateLimits = map[string]*ratelimit.Options{
		"shodan":     {Key: "shodan", MaxCount: 1, Duration: time.Second, IsUnlimited: true},
		"shodan-idb": {Key: "shodan-idb", MaxCount: 1, Duration: time.Second, IsUnlimited: true},
		"fofa":       {Key: "fofa", MaxCount: 1, Duration: time.Second, IsUnlimited: true},
		"censys":     {Key: "censys", MaxCount: 1, Duration: 3 * time.Second, IsUnlimited: false},
		"quake":      {Key: "quake", MaxCount: 1, Duration: time.Second, IsUnlimited: true},
		"hunter":     {Key: "hunter", MaxCount: 15, Duration: time.Second, IsUnlimited: false},
		"zoomeye":    {Key: "zoomeye", MaxCount: 1, Duration: time.Second, IsUnlimited: false},
		"netlas":     {Key: "netlas", MaxCount: 1, Duration: time.Second, IsUnlimited: false},
		"criminalip": {Key: "criminalip", MaxCount: 1, Duration: time.Second, IsUnlimited: true},
		"publicwww":  {Key: "publicwww", MaxCount: 1, Duration: time.Minute, IsUnlimited: false},
	}

	session := &Session{
		Client:     client,
		Keys:       keys,
		RetryMax:   retryMax,
		RateLimits: &ratelimit.MultiLimiter{},
	}

	var err error
	session.RateLimits, err = ratelimit.NewMultiLimiter(context.Background(), defaultRateLimits[engines[0]])
	if err != nil {
		return &Session{}, err
	}

	for _, engine := range engines[1:] {
		rateLimitOpts := defaultRateLimits[engine]
		if rateLimitOpts == nil {
			return nil, fmt.Errorf("no default rate limit found for engine %s", engine)
		}

		if rateLimit > 0 {
			rateLimitOpts.MaxCount = uint(rateLimit)
			rateLimitOpts.Duration = duration
		}
		rateLimitOpts.IsUnlimited = rateLimit == 0
		err := session.RateLimits.Add(rateLimitOpts)
		if err != nil {
			return nil, err
		}
	}

	return session, nil
}

func (s *Session) Do(request *retryablehttp.Request, sources ...string) (*http.Response, error) {
	for _, source := range sources {
		err := s.RateLimits.Take(source)
		if err != nil {
			return nil, err
		}
	}
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
