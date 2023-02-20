package publicwww

type Request struct {
	Query string `json:"query"`
	Start int    `json:"start"`
}

func (r *Request) buildURL(key string) string {
	return baseURL +
		baseEndpoint +
		`"` + r.Query + `"` +
		`/?export=csvu&key=` + key
}
