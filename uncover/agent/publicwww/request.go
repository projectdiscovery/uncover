package publicwww

import "net/url"

type Request struct {
	Query string `json:"query"`
	Start int    `json:"start"`
}

func (r *Request) buildURL(key string) string {
	return baseURL +
		baseEndpoint +
		url.QueryEscape(`"`+r.Query+`"`) +
		`/?export=urls&key=` + key
}
