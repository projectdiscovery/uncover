package uncover

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

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
		"hunterhow":  {Key: "hunterhow", MaxCount: 1, Duration: time.Second, IsUnlimited: false},
	}

	session := &Session{
		Client:     client,
		Keys:       keys,
		RetryMax:   retryMax,
		RateLimits: &ratelimit.MultiLimiter{},
	}

	for i, engine := range engines {
		var err error
		rateLimitOpts := defaultRateLimits[engine]
		if rateLimitOpts == nil {
			return nil, fmt.Errorf("no default rate limit found for engine %s", engine)
		}
		if i == 0 {
			session.RateLimits, err = ratelimit.NewMultiLimiter(context.Background(), rateLimitOpts)
			if err != nil {
				return &Session{}, err
			}
		} else {
			if rateLimit > 0 {
				rateLimitOpts.MaxCount = uint(rateLimit)
				rateLimitOpts.Duration = duration
			} else {
				rateLimitOpts.IsUnlimited = true
			}
			err = session.RateLimits.Add(rateLimitOpts)
			if err != nil {
				return nil, err
			}
		}
	}

	return session, nil
}

func (s *Session) Do(request *retryablehttp.Request, source string) (*http.Response, error) {
	err := s.RateLimits.Take(source)
	if err != nil {
		return nil, err
	}
	// close request connection (does not reuse connections)
	request.Close = true
	resp, err := s.Client.Do(request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(request.URL.String())
		return resp, fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
	}

	if err != nil {
		return nil, err
	}

	return resp, nil
}
