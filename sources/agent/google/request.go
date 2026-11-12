package google

import "fmt"

type Request struct {
	SearchTerms string `json:"q"`
	Count       int    `json:"num"`
	StartIndex  int    `json:"start"`
	CX          string `json:"cx"`
}

func (request *Request) buildURL(endpoint, key, cx string) string {
	return fmt.Sprintf("%s?key=%s&cx=%s&q=%s&start=%d&num=%d", endpoint, key, cx, request.SearchTerms, request.StartIndex, request.Count)
}
