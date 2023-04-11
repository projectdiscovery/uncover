package hunter

type ResponseDataArr struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Domain string `json:"domain"`
}

type responseData struct {
	Total        int               `json:"total"`
	Time         int               `json:"time"`
	Arr          []ResponseDataArr `json:"arr"`
	ConsumeQuota string            `json:"consume_quota"`
	RestQuota    string            `json:"rest_quota"`
}

type Response struct {
	Code int          `json:"code"`
	Data responseData `json:"data"`
	Msg  string       `json:"msg"`
}
