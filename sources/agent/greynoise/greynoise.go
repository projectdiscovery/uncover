package greynoise

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/sources"
)

const (
	URL = "https://api.greynoise.io/v3/gnql"
)

var (
	ErrUnauthorized = errors.New("unauthorized: invalid or missing API key")
	ErrPlanLimited  = errors.New("forbidden: plan limitations (GNQL not enabled for this plan)")
	ErrRateLimited  = errors.New("rate limited: too many requests")
)

func retryAfterHint(h http.Header) string {
	ra := h.Get("Retry-After")
	if strings.TrimSpace(ra) == "" {
		return ""
	}
	return ra
}

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
				ExcludeRaw: false,
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
				hosts := collectHostnamesFromItem(item)
				ports := collectPortsFromItem(item)

				emit := func(h string, p int) {
					r := sources.Result{
						Source: agent.Name(),
						IP:     item.IP,
						Host:   h,
						Port:   p,
					}
					if raw, err := json.Marshal(item); err == nil {
						r.Raw = raw
					}
					results <- r
					total++
				}

				switch {
				case len(hosts) == 0 && len(ports) == 0:
					emit("", 0)

				case len(hosts) == 0 && len(ports) > 0:
					for _, p := range ports {
						emit("", p)
						if query.Limit > 0 && total >= query.Limit {
							done = true
							break
						}
					}

				case len(hosts) > 0 && len(ports) == 0:
					for _, h := range hosts {
						emit(h, 0)
						if query.Limit > 0 && total >= query.Limit {
							done = true
							break
						}
					}

				default:
					for _, h := range hosts {
						for _, p := range ports {
							emit(h, p)
							if query.Limit > 0 && total >= query.Limit {
								done = true
								break
							}
						}
						if done {
							break
						}
					}
				}

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
	path := "/v3/gnql"
	if request.ExcludeRaw {
		path = "/v3/gnql/metadata"
	}

	baseURL, _ := url.Parse(URL)
	baseURL.Path = path
	fullURL := baseURL.String()
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

		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("%w (status=%d): %s", ErrUnauthorized, resp.StatusCode, msg)
		case http.StatusForbidden:
			return nil, fmt.Errorf("%w (status=%d): %s", ErrPlanLimited, resp.StatusCode, msg)
		case http.StatusNotFound:
			return nil, fmt.Errorf("not found (status=%d): %s", resp.StatusCode, msg)
		case http.StatusTooManyRequests:
			ra := retryAfterHint(resp.Header)
			if ra != "" {
				return nil, fmt.Errorf("%w (status=%d, retry-after=%s): %s", ErrRateLimited, resp.StatusCode, ra, msg)
			}
			return nil, fmt.Errorf("%w (status=%d): %s", ErrRateLimited, resp.StatusCode, msg)
		default:
			if resp.StatusCode >= 500 {
				return nil, fmt.Errorf("server error (status=%d): %s", resp.StatusCode, msg)
			}
			return nil, fmt.Errorf("request failed (status=%d): %s", resp.StatusCode, msg)
		}
	}

	var apiResponse Response
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		gologger.Error().Msgf("greynoise decode error (status=%d): %v", resp.StatusCode, err)
		return nil, err
	}

	gologger.Debug().Msgf(
		"GNQL count=%d complete=%v scroll=%s data=%d msg=%s",
		apiResponse.RequestMetadata.Count,
		apiResponse.RequestMetadata.Complete,
		short(apiResponse.RequestMetadata.Scroll, 12),
		len(apiResponse.Data),
		short(apiResponse.RequestMetadata.Message, 120),
	)

	return &apiResponse, nil
}

func collectPortsFromItem(it GNQLItem) []int {
	ports := make(map[int]struct{})

	for _, s := range it.InternetScannerIntelligence.RawData.Scan {
		if s.Port > 0 {
			ports[s.Port] = struct{}{}
		}
	}

	for _, j := range it.InternetScannerIntelligence.RawData.JA3 {
		if j.Port > 0 {
			ports[j.Port] = struct{}{}
		}
	}

	for _, h := range it.InternetScannerIntelligence.RawData.HASSH {
		if h.Port > 0 {
			ports[h.Port] = struct{}{}
		}
	}

	for _, host := range flattenHTTPHosts(it.InternetScannerIntelligence.RawData.HTTP.Host) {
		if i := strings.LastIndex(host, ":"); i > 0 && i < len(host)-1 {
			if p, err := strconv.Atoi(host[i+1:]); err == nil && p > 0 {
				ports[p] = struct{}{}
			}
		}
	}

	out := make([]int, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	return out
}

func collectHostnamesFromItem(it GNQLItem) []string {
	uniq := make(map[string]struct{})

	add := func(h string) {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			return
		}
		if i := strings.LastIndex(h, ":"); i > 0 && i < len(h)-1 {
			if !(strings.HasPrefix(h, "[") && strings.Contains(h, "]")) {
				h = h[:i]
			}
		}
		if net.ParseIP(h) != nil {
			return
		}
		h = strings.TrimSuffix(h, ".")
		if h == "" {
			return
		}
		uniq[h] = struct{}{}
	}

	add(it.InternetScannerIntelligence.Metadata.Domain)
	add(it.InternetScannerIntelligence.Metadata.RDNS)
	add(it.InternetScannerIntelligence.Metadata.RDNSParent)

	for _, h := range flattenHTTPHosts(it.InternetScannerIntelligence.RawData.HTTP.Host) {
		add(h)
	}

	out := make([]string, 0, len(uniq))
	for h := range uniq {
		out = append(out, h)
	}
	return out
}

func flattenHTTPHosts(rows [][]string) []string {
	if len(rows) == 0 {
		return nil
	}
	out := make([]string, 0, len(rows)*2)
	for _, row := range rows {
		out = append(out, row...)
	}
	return out
}

func short(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
