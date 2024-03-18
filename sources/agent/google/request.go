package google

import "fmt"

type Request struct {
	SearchTerms string `json:"q"`
	Count       int    `json:"num"`
	StartIndex  int    `json:"start"`
	CX          string `json:"cx"`
}

func (request *Request) buildURL(key, cx string) string {
	return fmt.Sprintf(baseURL, key, cx, request.SearchTerms, request.StartIndex, request.Count)
}
