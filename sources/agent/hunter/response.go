package hunter

type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int `json:"total"`
		Time  int `json:"time"`
		Arr   []struct {
			WebTitle     string `json:"web_title"`
			Ip           string `json:"ip"`
			Port         int    `json:"port"`
			BaseProtocol string `json:"base_protocol"`
			Protocol     string `json:"protocol"`
			Domain       string `json:"domain"`
			Component    []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
			Url            string `json:"url"`
			Os             string `json:"os"`
			Country        string `json:"country"`
			Province       string `json:"province"`
			City           string `json:"city"`
			UpdatedAt      string `json:"updated_at"`
			StatusCode     int    `json:"status_code"`
			Number         string `json:"number"`
			Company        string `json:"company"`
			IsWeb          string `json:"is_web"`
			IsRisk         string `json:"is_risk"`
			IsRiskProtocol string `json:"is_risk_protocol"`
			AsOrg          string `json:"as_org"`
			Isp            string `json:"isp"`
			Banner         string `json:"banner"`
			Header         string `json:"header"`
		} `json:"arr"`
		ConsumeQuota string `json:"consume_quota"`
		RestQuota    string `json:"rest_quota"`
	} `json:"data"`
}
