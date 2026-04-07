package nerdydata

import (
	"encoding/json"
	"net/url"
)

const (
	baseURL      = "https://api.nerdydata.com"
	baseEndpoint = "/search"
)

type Request struct {
	Query string
	Page  string // cursor from next_page field; empty for first page
}

func (r *Request) buildURL() string {
	params := url.Values{}

	var obj map[string]any
	if json.Unmarshal([]byte(r.Query), &obj) == nil {
		// Already a JSON search object — pass through unchanged.
		params.Set("search", r.Query)
	} else {
		// Wrap plain string as a code search term.
		wrapped, _ := json.Marshal(map[string]any{
			"all": []map[string]string{
				{"type": "code", "value": r.Query},
			},
		})
		params.Set("search", string(wrapped))
	}

	params.Set("facets", "false")
	if r.Page != "" {
		params.Set("page", r.Page)
	}

	return baseURL + baseEndpoint + "?" + params.Encode()
}
