package criminalip

type CriminalIPResponse struct {
	Data responseData `json:"data"`
	Msg    string     `json:"message"`
	Status int        `json:"status"`
}

type ResponseDataArr struct {
	IP     string `json:"ip_address"`
	Port   int    `json:"open_port_no"`
	Domain string `json:"hostname"`
}

type responseData struct {
	Result       []ResponseDataArr `json:"result"`
	Count        int               `json:"count"`
	SearchKeyword string           `json:"search_keyword"`
}
