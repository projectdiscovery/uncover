// Package subdomaincenter queries the Subdomain Center ammonites engine, which
// finds hosts anywhere in the dataset carrying a given subdomain label.
package subdomaincenter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/projectdiscovery/uncover/sources"
)

// pageSize is the largest page an authenticated query asks for. The API accepts
// an explicit limit of up to 1,000,000, but smaller pages complete faster and
// are cheaper to retry individually.
const pageSize = 10000

type Agent struct{}

func (agent *Agent) Name() string {
	return "subdomaincenter"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	ammonitesRequest, err := newRequest(query.Query)
	if err != nil {
		return nil, err
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		apiKey := session.Keys.SubdomainCenter
		numberOfResults := 0

		for offset := 0; ; {
			page, err := agent.queryPage(ctx, session, ammonitesRequest, apiKey, offset, query.Limit-numberOfResults)
			if err != nil {
				sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
				return
			}

			for _, host := range page.hosts {
				if numberOfResults >= query.Limit {
					return
				}
				raw, _ := json.Marshal(host)
				if !sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Host: host, Raw: raw}) {
					return
				}
				numberOfResults++
			}

			// The anonymous tier ignores limit/offset and always answers with a
			// single capped sample, so there is nothing to page through.
			if apiKey == "" || !page.truncated || len(page.hosts) == 0 {
				return
			}
			offset = page.nextOffset
		}
	}()

	return results, nil
}

// page is one response from the ammonites engine.
type page struct {
	hosts      []string
	truncated  bool
	nextOffset int
}

func (agent *Agent) queryPage(ctx context.Context, session *sources.Session, ammonitesRequest *request, apiKey string, offset, remaining int) (*page, error) {
	limit := pageSize
	if remaining > 0 && remaining < limit {
		limit = remaining
	}

	httpRequest, err := sources.NewHTTPRequest(ctx, http.MethodGet, ammonitesRequest.buildURL(apiKey != "", offset, limit), nil)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Accept", "application/json")
	if apiKey != "" {
		// Header only: the API rejects the key as a query parameter so it cannot
		// leak through proxy, browser or CDN logs.
		httpRequest.Header.Set("X-API-Key", apiKey)
	}

	resp, err := session.Do(httpRequest, agent.Name())
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var hosts []string
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		return nil, err
	}

	current := &page{
		hosts:      hosts,
		truncated:  strings.EqualFold(resp.Header.Get("X-Truncated"), "true"),
		nextOffset: offset + len(hosts),
	}
	if next, err := strconv.Atoi(resp.Header.Get("X-Next-Offset")); err == nil && next > offset {
		current.nextOffset = next
	}

	return current, nil
}

// request is an ammonites keyword search.
type request struct {
	keyword string
	domain  string
	match   string
}

// newRequest parses an uncover query into an ammonites request. The query is the
// subdomain label to search for, optionally scoped to a single zone and widened
// to a prefix search: "vpn", "vpn domain:example.com", "vpn match:prefix".
func newRequest(query string) (*request, error) {
	parsed := &request{}
	for _, field := range strings.Fields(query) {
		name, value, found := strings.Cut(field, ":")
		if !found {
			if parsed.keyword == "" {
				parsed.keyword = field
			}
			continue
		}
		switch strings.ToLower(name) {
		case "keyword":
			parsed.keyword = value
		case "domain":
			parsed.domain = value
		case "match":
			parsed.match = value
		default:
			return nil, fmt.Errorf("subdomaincenter: unknown query field %q", name)
		}
	}

	if len(parsed.keyword) < 2 {
		return nil, errors.New("subdomaincenter: keyword must be at least 2 characters")
	}

	return parsed, nil
}

func (r *request) buildURL(authenticated bool, offset, limit int) string {
	query := url.Values{}
	query.Set("engine", "ammonites")
	query.Set("keyword", r.keyword)
	if r.domain != "" {
		query.Set("domain", r.domain)
	}
	if r.match != "" {
		query.Set("match", r.match)
	}
	if authenticated {
		query.Set("limit", strconv.Itoa(limit))
		query.Set("offset", strconv.Itoa(offset))
	}

	return "https://api.subdomain.center/?" + query.Encode()
}
