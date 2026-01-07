package daydaymap

// DaydaymapResponse represents the API response structure
type DaydaymapResponse struct {
	Code int           `json:"code"`
	Data DaydaymapData `json:"data"`
	Msg  string        `json:"msg"`
}

// DaydaymapData represents the data field in response
type DaydaymapData struct {
	List     []DaydaymapResult `json:"list"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
	Total    int               `json:"total"`
	UseTime  string            `json:"use_time"`
}

// DaydaymapResult represents a single asset result
type DaydaymapResult map[string]interface{}
