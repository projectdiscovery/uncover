package google

import "fmt"

type Request struct {
	SearchTerms            string `json:"q"`
	Count                  int    `json:"num,omitempty"`
	StartIndex             int    `json:"start,omitempty"`
	Language               string `json:"lr,omitempty"`
	Safe                   string `json:"safe,omitempty"`
	CX                     string `json:"cx"`
	Sort                   string `json:"sort,omitempty"`
	Filter                 string `json:"filter,omitempty"`
	GL                     string `json:"gl,omitempty"`
	CR                     string `json:"cr,omitempty"`
	GoogleHost             string `json:"googlehost,omitempty"`
	DisableCnTwTranslation string `json:"c2coff,omitempty"`
	HQ                     string `json:"hq,omitempty"`
	HL                     string `json:"hl,omitempty"`
	SiteSearch             string `json:"siteSearch,omitempty"`
	SiteSearchFilter       string `json:"siteSearchFilter,omitempty"`
	ExactTerms             string `json:"exactTerms,omitempty"`
	ExcludeTerms           string `json:"excludeTerms,omitempty"`
	LinkSite               string `json:"linkSite,omitempty"`
	OrTerms                string `json:"orTerms,omitempty"`
	DateRestrict           string `json:"dateRestrict,omitempty"`
	LowRange               string `json:"lowRange,omitempty"`
	HighRange              string `json:"highRange,omitempty"`
	SearchType             string `json:"searchType,omitempty"`
	FileType               string `json:"fileType,omitempty"`
	Rights                 string `json:"rights,omitempty"`
	ImgSize                string `json:"imgSize,omitempty"`
	ImgType                string `json:"imgType,omitempty"`
	ImgColorType           string `json:"imgColorType,omitempty"`
	ImgDominantColor       string `json:"imgDominantColor,omitempty"`
	Alt                    string `json:"alt"`
}

func (request *Request) buildURL(key, cx string) string {
	return fmt.Sprintf(baseURL, key, cx, request.SearchTerms, request.StartIndex, request.Count)
}
