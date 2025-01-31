package odin

type OdinResponse struct {
	Success    bool       `json:"success"`
	Pagination Pagination `json:"pagination"`
	Data       []HostData `json:"data"`
}

type Pagination struct {
	Start []float64 `json:"start"`
	Last  []float64 `json:"last"`
	Limit int       `json:"limit"`
	Total int       `json:"total"`
}

type HostData struct {
	ScanID        int64     `json:"scan_id"`
	IP            string    `json:"ip"`
	IsIPv4        bool      `json:"is_ipv4"`
	IsIPv6        bool      `json:"is_ipv6"`
	Services      []Service `json:"services"`
	LastUpdatedAt string    `json:"last_updated_at"`
}

type Service struct {
	Port          int    `json:"port"`
	Protocol      string `json:"protocol"`
	Name          string `json:"name"`
	LastUpdatedAt string `json:"last_updated_at"`
}
