package zoomeye

type ZoomEyeResponse struct {
	Total   int                      `json:"total"`
	Results []map[string]interface{} `json:"matches"`
}
