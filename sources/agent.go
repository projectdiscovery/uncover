package sources

type Query struct {
	Query string
	Limit int
	Full  bool
}

type Agent interface {
	Query(*Session, *Query) (chan Result, error)
	Name() string
}
