package google

type Response struct {
	Items []Items `json:"items"`
}

type Items struct {
	Link string `json:"link"`
}
