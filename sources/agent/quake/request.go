package quake

type Request struct {
	Query       string `json:"query"`
	Size        int    `json:"size"`
	Start       int    `json:"start"`
	IgnoreCache bool   `json:"ignore_cache"`
	Latest      bool   `json:"latest"`
	// Include     []string `json:"include"`
	Exclude []string `json:"exclude"`
}
