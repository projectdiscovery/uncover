package publicwww

import (
	"errors"

	"github.com/projectdiscovery/uncover/uncover"
)

const (
	baseURL      = "https://publicwww.com/"
	baseEndpoint = "websites/"
)

type Agent struct {
	options *uncover.AgentOptions
}

func New() (uncover.Agent, error) {
	return &Agent{}, nil
}

func NewWithOptions(options *uncover.AgentOptions) (uncover.Agent, error) {
	return &Agent{options: options}, nil
}

func (agent *Agent) Name() string {
	return "publicwww"
}

func (agent *Agent) Query(session *uncover.Session, query *uncover.Query) (chan uncover.Result, error) {
	if session.Keys.NetlasToken == "" {
		return nil, errors.New("empty netlas keys")
	}

	results := make(chan uncover.Result)

	return results, nil
}
