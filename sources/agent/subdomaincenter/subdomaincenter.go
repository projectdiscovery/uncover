package subdomaincenter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/projectdiscovery/uncover/sources"
)

var (
	URL = "https://api.subdomain.center/"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "subdomaincenter"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	results := make(chan sources.Result)

	go func() {
		defer close(results)

		agent.query(ctx, session, query, results)
	}()

	return results, nil
}

func (agent *Agent) query(ctx context.Context, session *sources.Session, query *sources.Query, results chan sources.Result) {
	apiKey := ""
	if session != nil && session.Keys != nil {
		apiKey = session.Keys.SubdomainCenterToken
	}
	authenticated := apiKey != ""

	offset := 0
	pageSize := 100
	if query.Limit > 0 && query.Limit < pageSize {
		pageSize = query.Limit
	}
	totalResults := 0

	for {
		if ctx.Err() != nil {
			return
		}

		reqURL, err := url.Parse(URL)
		if err != nil {
			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
			return
		}

		q := reqURL.Query()
		q.Set("engine", "ammonites")
		q.Set("keyword", query.Query)
		if authenticated {
			q.Set("limit", strconv.Itoa(pageSize))
			q.Set("offset", strconv.Itoa(offset))
		}
		reqURL.RawQuery = q.Encode()

		req, err := sources.NewHTTPRequest(ctx, http.MethodGet, reqURL.String(), nil)
		if err != nil {
			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
			return
		}
		req.Header.Set("Accept", "application/json")
		if authenticated {
			req.Header.Set("X-API-Key", apiKey)
		}

		resp, err := session.Do(req, agent.Name())
		if err != nil {
			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
			return
		}

		var names []string
		decodeErr := json.NewDecoder(resp.Body).Decode(&names)
		isTruncated := strings.EqualFold(resp.Header.Get("X-Truncated"), "true")
		nextOffset := offset + len(names)
		if next, convErr := strconv.Atoi(resp.Header.Get("X-Next-Offset")); convErr == nil && next > offset {
			nextOffset = next
		}
		_ = resp.Body.Close()

		if decodeErr != nil {
			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: decodeErr})
			return
		}

		if len(names) == 0 {
			return
		}

		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}

			result := sources.Result{Source: agent.Name(), Host: name}
			result.Raw, _ = json.Marshal(name)
			if !sources.SendResult(ctx, results, result) {
				return
			}

			totalResults++
			if query.Limit > 0 && totalResults >= query.Limit {
				return
			}
		}

		// The anonymous tier ignores limit/offset and answers with a single sample.
		if !authenticated {
			return
		}

		if !isTruncated || len(names) == 0 {
			return
		}

		offset = nextOffset
	}
}
