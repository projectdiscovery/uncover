package zone0

// response contains the fofa response
type response struct {
	Code     int     `json:"code,omitempty"`
	Msg      string  `json:"message,omitempty"`
	Page     int     `json:"page,omitempty"`
	PageSize int     `json:"pagesize,omitempty"`
	Total    string  `json:"total,omitempty"`
	Data     []*data `json:"data,omitempty"`
}

type data struct {
	Ip   string `json:"ip,omitempty"`
	Port string `json:"port,omitempty"`
	Url  string `json:"url,omitempty"`
}
