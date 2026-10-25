package daydaymap

// DaydaymapRequest represents the API request structure
type DaydaymapRequest struct {
	Page          int    `json:"page"`
	PageSize      int    `json:"page_size"`
	Keyword       string `json:"keyword"`
	Fields        string `json:"fields,omitempty"`
	ExcludeFields string `json:"exclude_fields,omitempty"`
}
