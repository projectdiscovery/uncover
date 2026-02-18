package sources

type Query struct {
	Query string
	Limit int
}

// Agent is the basic interface for all search engines
type Agent interface {
	Query(*Session, *Query) (chan Result, error)
	Name() string
}

// InfoAgent is an interface for agents that support checking balance/account info
type InfoAgent interface {
	Agent
	Info(*Session) (string, error)
}
