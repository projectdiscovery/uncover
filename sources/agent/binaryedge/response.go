package binaryedge

type BinaryedgeResponse struct {
	Total  int               `json:"total"`
	Query  string            `json:"query"`
	Events []BinaryedgeEvent `json:"events"`
}

type BinaryedgeEvent struct {
	Results []BinaryedgeResult `json:"results"`
	Port    int                `json:"port"`
}

type BinaryedgeResult struct {
	Origin BinaryedgeOrigin `json:"origin"`
	Target BinaryedgeTarget `json:"target"`
}

type BinaryedgeOrigin struct {
	Module  string `json:"module"`
	Port    int    `json:"port"`
	IP      string `json:"ip"`
	Type    string `json:"type"`
	Ts      int64  `json:"ts"`
	Country string `json:"country"`
}

type BinaryedgeTarget struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	IP       string `json:"ip"`
}
