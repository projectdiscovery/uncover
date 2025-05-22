package zoomeye

type ZoomEyeResponse struct {
	Total   int             `json:"total"`
	Results []ZoomEyeResult `json:"data"`
}

type ZoomEyeResult struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname"`
}
