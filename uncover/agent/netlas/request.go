package netlas

import (
	"fmt"
	"net/url"
)

type Request struct {
	Query string `json:"query"`
	Start int    `json:"start"`
}

func (r *Request) buildURL() string {
	return baseURL +
		baseEndpoint +
		"?q=" +
		url.QueryEscape(r.Query) +
		"&start=" +
		fmt.Sprint(r.Start)
}
