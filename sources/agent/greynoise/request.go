package greynoise

type Request struct {
	Query      string `json:"query"`
	Size       int    `json:"size,omitempty"`
	Scroll     string `json:"scroll,omitempty"`
	ExcludeRaw bool   `json:"-"`
}
