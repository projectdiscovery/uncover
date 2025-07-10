package sources

type Query struct {
	Query      string
	Limit      int
	Full       bool   // Used for fofa query of full data
	StatusCode string // Used for hunter to query the content of a specified status code list
	PortFilter bool   // Used for Hunter data filtering
	IsWeb      int    // Used for Hunter filtering asset types
	StartTime  string // Used for hunter filtering start time
	EndTime    string // Used for hunter filtering end time
}

type Agent interface {
	Query(*Session, *Query) (chan Result, error)
	Name() string
}
