package nerdydata

type Response struct {
	Total    int    `json:"total"`
	Sites    []Site `json:"sites"`
	NextPage string `json:"next_page"`
	Errors   []any  `json:"errors"`
}

// Site contains the fields returned by the API for each result.
type Site struct {
	Domain   string `json:"domain"`
	URL      string `json:"url"`
	Country  string `json:"country"`
	Vertical string `json:"vertical"`
	Rank     int    `json:"rank"`
	Company  string `json:"company"`
	SpendMax int    `json:"spend_max"`
}
