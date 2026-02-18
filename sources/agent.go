package sources

// AccountInfo holds credit or usage information for a provider.
type AccountInfo struct {
	Plan         string
	QueriesLeft  int
	Raw          string
}

// Query represents the search parameters for the agents.
type Query struct {
	Query string
	Limit int
}

// Agent is the basic interface for all search engines.
type Agent interface {
	// Query performs the search and returns a channel of results.
	Query(*Session, *Query) (chan Result, error)
	// Name returns the provider name.
	Name() string
}

// InfoAgent is an interface for agents that support checking balance/account info.
type InfoAgent interface {
	Agent
	// Info retrieves account-specific information like remaining credits.
	Info(*Session) (*AccountInfo, error)
}
