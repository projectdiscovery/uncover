package driftnet

type DriftnetAPIPortCount map[int]int
type DriftnetAPIIPSummary map[string]DriftnetAPIOpenPortResponse

type DriftnetAPIOpenPortResponse struct {
	// Honeypot indicates the IP(s) are exhibiting honeypot behaviours
	Honeypot bool `json:"honeypot"`

	// Other is a count of unsummarised ports (the number of summarised was larger than the api limit of 100)
	Other int `json:"other"`

	// Values are the summarised open ports with observation count per port
	Values DriftnetAPIPortCount `json:"values"`
}

type DriftnetAPIOpenIPPortResponse struct {
	// Other is a count of unsummarised ip addresses (the number of summarised was larger than the api limit of 1024)
	Other int `json:"other"`

	// Values are the summarised open ports with observation count per port
	Values DriftnetAPIIPSummary `json:"values"`
}

type DriftnetAPIResultItem struct {
	// Value is the actual reported value (e.g. jira)
	Value string `json:"value"`

	// Type is the type of value (e.g. product-tag)
	Type string `json:"type"`

	// Context is the context in which the value is being reported (e.g. nmap-app)
	Context string `json:"context"`
}

type DriftnetAPIResult struct {

	// Items are the reported items.
	Items []DriftnetAPIResultItem `json:"items"`
}

type DriftnetAPIPaginatedResponse struct {
	Page        int                 `json:"page"`
	Pages       int                 `json:"pages"`
	ResultCount int                 `json:"result_count"`
	Results     []DriftnetAPIResult `json:"results"`
}

type DriftnetResponse struct {
	Hostnames []string `json:"hostnames"`
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
}
