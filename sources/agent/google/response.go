package google

type Response struct {
	Kind              string            `json:"kind,omitempty"`
	URL               URL               `json:"url,omitempty"`
	Queries           Queries           `json:"queries,omitempty"`
	Context           Context           `json:"context,omitempty"`
	SearchInformation SearchInformation `json:"searchInformation,omitempty"`
	Items             []Items           `json:"items,omitempty"`
}

type URL struct {
	Type     string `json:"type,omitempty"`
	Template string `json:"template,omitempty"`
}

type NextPage struct {
	Title          string `json:"title,omitempty"`
	TotalResults   string `json:"totalResults,omitempty"`
	SearchTerms    string `json:"searchTerms,omitempty"`
	Count          int    `json:"count,omitempty"`
	StartIndex     int    `json:"startIndex,omitempty"`
	InputEncoding  string `json:"inputEncoding,omitempty"`
	OutputEncoding string `json:"outputEncoding,omitempty"`
	Safe           string `json:"safe,omitempty"`
	Cx             string `json:"cx,omitempty"`
}

type ResponseRequest struct {
	Title          string `json:"title"`
	TotalResults   string `json:"totalResults"`
	SearchTerms    string `json:"searchTerms"`
	Count          int    `json:"count"`
	StartIndex     int    `json:"startIndex"`
	InputEncoding  string `json:"inputEncoding"`
	OutputEncoding string `json:"outputEncoding"`
	Safe           string `json:"safe"`
	Cx             string `json:"cx"`
}

type Queries struct {
	Request  []ResponseRequest `json:"request,omitempty"`
	NextPage []NextPage        `json:"nextPage,omitempty"`
}

type Context struct {
	Title string `json:"title,omitempty"`
}

type SearchInformation struct {
	SearchTime            float64 `json:"searchTime,omitempty"`
	FormattedSearchTime   string  `json:"formattedSearchTime,omitempty"`
	TotalResults          string  `json:"totalResults,omitempty"`
	FormattedTotalResults string  `json:"formattedTotalResults,omitempty"`
}

type Items struct {
	Kind             string  `json:"kind,omitempty"`
	Title            string  `json:"title,omitempty"`
	HTMLTitle        string  `json:"htmlTitle,omitempty"`
	Link             string  `json:"link,omitempty"`
	DisplayLink      string  `json:"displayLink,omitempty"`
	Snippet          string  `json:"snippet,omitempty"`
	HTMLSnippet      string  `json:"htmlSnippet,omitempty"`
	CacheID          string  `json:"cacheId,omitempty"`
	FormattedURL     string  `json:"formattedUrl,omitempty"`
	HTMLFormattedURL string  `json:"htmlFormattedUrl,omitempty"`
	Pagemap          Pagemap `json:"pagemap,omitempty"`
}

type Metatags struct {
	OgImage                  string `json:"og:image,omitempty"`
	OgType                   string `json:"og:type,omitempty"`
	TwitterTitle             string `json:"twitter:title,omitempty"`
	TwitterCard              string `json:"twitter:card,omitempty"`
	OgSiteName               string `json:"og:site_name,omitempty"`
	OgTitle                  string `json:"og:title,omitempty"`
	SlackAppID               string `json:"slack-app-id,omitempty"`
	CsrfParam                string `json:"csrf-param,omitempty"`
	OgDescription            string `json:"og:description,omitempty"`
	TwitterImage             string `json:"twitter:image,omitempty"`
	FbAppID                  string `json:"fb:app_id,omitempty"`
	TwitterSite              string `json:"twitter:site,omitempty"`
	Viewport                 string `json:"viewport,omitempty"`
	AppleMobileWebAppCapable string `json:"apple-mobile-web-app-capable,omitempty"`
	TwitterDescription       string `json:"twitter:description,omitempty"`
	CsrfToken                string `json:"csrf-token,omitempty"`
	SentryReleaseID          string `json:"sentry-release-id,omitempty"`
	OgURL                    string `json:"og:url,omitempty"`
}

type CseImage struct {
	Src string `json:"src,omitempty"`
}

type Pagemap struct {
	Metatags []Metatags `json:"metatags,omitempty"`
	CseImage []CseImage `json:"cse_image,omitempty"`
}
