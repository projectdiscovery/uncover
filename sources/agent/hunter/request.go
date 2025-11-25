package hunter

type Request struct {
	Username   string `json:"username"`
	ApiKey     string `json:"api-key"`
	Search     string `json:"search"`
	StartTime  string `json:"start_time"`
	EndTime    string `json:"end_time"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
	IsWeb      int    `json:"is_web"`
	PortFilter bool   `json:"port_filter"`
	StatusCode string `json:"status_code"`
}
