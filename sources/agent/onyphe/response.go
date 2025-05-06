package onyphe

type OnypheResponse struct {
	Error    int      `json:"error"`
	Results  []Result `json:"results"`
	Page     string   `json:"page"`
	PageSize int      `json:"page_size"`
	Total    int      `json:"total"`
}

type Result struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}
