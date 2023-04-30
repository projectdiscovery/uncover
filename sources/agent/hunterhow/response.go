package hunterhow

type Response struct {
	Code    int    `json:"code"`
	Data    Data   `json:"data"`
	Message string `json:"message"`
}
type List struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
}
type Data struct {
	List  []List `json:"list"`
	Total int    `json:"total"`
}
