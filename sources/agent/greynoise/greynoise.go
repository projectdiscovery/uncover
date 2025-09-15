package greynoise

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL = "https://api.greynoise.io/v3/gnql"
)

type Agent struct{}

func (agent *Agent) Name() string { return "greynoise" }

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.GreyNoiseKey == "" {
		return nil, errors.New("empty GreyNoise API key")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		scrollToken := ""
		total := 0
		done := false

		pageSize := 1000
		if query.Limit > 0 && query.Limit < pageSize {
			pageSize = query.Limit
		}

		for !done {
			req := &Request{
				Query:      query.Query,
				Size:       pageSize,
				Scroll:     scrollToken,
				ExcludeRaw: true,
			}

			apiResponse, err := agent.query(session, req)
			if err != nil {
				results <- sources.Result{Source: agent.Name(), Error: err}
				return
			}
			if apiResponse == nil || len(apiResponse.Data) == 0 {
				return
			}

			for _, item := range apiResponse.Data {
				host := firstNonEmpty(
					item.InternetScannerIntelligence.Metadata.Domain,
					item.InternetScannerIntelligence.Metadata.RDNS,
				)

				r := sources.Result{
					Source: agent.Name(),
					IP:     item.IP,
					Host:   host,
				}
				if raw, err := json.Marshal(item); err == nil {
					r.Raw = raw
				}
				results <- r

				total++
				if query.Limit > 0 && total >= query.Limit {
					done = true
					break
				}
			}

			done = done || apiResponse.RequestMetadata.Complete
			scrollToken = apiResponse.RequestMetadata.Scroll
			if strings.TrimSpace(scrollToken) == "" {
				done = true
			}

			if query.Limit > 0 && !done {
				remain := query.Limit - total
				if remain < pageSize {
					pageSize = remain
				}
			}
		}
	}()

	return results, nil
}

func (agent *Agent) query(session *sources.Session, request *Request) (*Response, error) {
	params := url.Values{}
	params.Set("query", request.Query)

	if request.Size > 0 {
		if request.Size > 10000 {
			request.Size = 10000
		}
		params.Set("size", strconv.Itoa(request.Size))
	}
	if request.Scroll != "" {
		params.Set("scroll", request.Scroll)
	}
	if request.ExcludeRaw {
		params.Set("exclude_raw", "true")
	}

	fullURL := URL
	if enc := params.Encode(); enc != "" {
		fullURL = fullURL + "?" + enc
	}

	req, err := sources.NewHTTPRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("key", session.Keys.GreyNoiseKey)

	resp, err := session.Do(req, agent.Name())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(b))

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf(
				"GreyNoise GNQL request failed: status=%d. Your API key may not include GNQL access (Enterprise key required). body=%s",
				resp.StatusCode, msg,
			)
		}

		return nil, fmt.Errorf("greynoise GNQL request failed: status=%d body=%s", resp.StatusCode, msg)
	}

	var apiResponse Response
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		fmt.Fprintf(os.Stderr, "DEBUG: GreyNoise decode error status=%d: %v\n", resp.StatusCode, err)
		return nil, err
	}

	fmt.Fprintf(os.Stderr,
		"DEBUG: GNQL count=%d complete=%v scroll=%s data=%d msg=%s\n",
		apiResponse.RequestMetadata.Count,
		apiResponse.RequestMetadata.Complete,
		short(apiResponse.RequestMetadata.Scroll, 12),
		len(apiResponse.Data),
		short(apiResponse.RequestMetadata.Message, 120),
	)

	return &apiResponse, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func short(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
