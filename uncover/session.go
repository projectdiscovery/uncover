package uncover

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

type Session struct {
	Keys       *Keys
	Client     *http.Client
	CheckRetry CheckRetry
	RetryMax   int
}

func NewSession(keys *Keys, retryMax, timeout int) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
		Proxy:                 http.ProxyFromEnvironment,
	}

	client := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	session := &Session{
		Client:     client,
		Keys:       keys,
		CheckRetry: DefaultRetryPolicy(),
		RetryMax:   retryMax,
	}

	return session, nil
}

func (s *Session) Do(request *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	for i := 0; ; i++ {
		request.Header.Set("Connection", "close")
		resp, err = s.Client.Do(request)
		// Check if we should continue with retries.
		checkOK, checkErr := s.CheckRetry(request.Context(), resp, err)
		// Now decide if we should continue.
		if !checkOK {
			if checkErr != nil {
				err = checkErr
			} else {
				if resp.StatusCode != http.StatusOK {
					requestURL, _ := url.QueryUnescape(request.URL.String())
					return resp, errors.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
				}
			}
			return resp, err
		}
		// We do this before drainBody beause there's no need for the I/O if
		// we're breaking out
		remain := s.RetryMax - i
		if remain <= 1 {
			break
		}
	}
	return nil, fmt.Errorf("%s %s giving up after %d attempts: %w", request.Method, request.URL, s.RetryMax, err)
}
