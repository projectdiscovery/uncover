package runner

import (
	"errors"

	"github.com/projectdiscovery/uncover/uncover"
	"github.com/projectdiscovery/uncover/uncover/agent/censys"
	"github.com/projectdiscovery/uncover/uncover/agent/criminalip"
	"github.com/projectdiscovery/uncover/uncover/agent/fofa"
	"github.com/projectdiscovery/uncover/uncover/agent/hunter"
	"github.com/projectdiscovery/uncover/uncover/agent/hunterhow"
	"github.com/projectdiscovery/uncover/uncover/agent/netlas"
	"github.com/projectdiscovery/uncover/uncover/agent/publicwww"
	"github.com/projectdiscovery/uncover/uncover/agent/quake"
	"github.com/projectdiscovery/uncover/uncover/agent/shodan"
	"github.com/projectdiscovery/uncover/uncover/agent/shodanidb"
	"github.com/projectdiscovery/uncover/uncover/agent/zoomeye"
)

// AgentFactory is an interface for creating uncover agents.
type AgentFactory interface {
	CreateAgents(options *Options) ([]uncover.Agent, error)
}

// DefaultAgentFactory is the default implementation of the AgentFactory interface.
type DefaultAgentFactory struct{}

// CreateAgents creates a list of uncover agents based on the provided engines and queries.
func (f *DefaultAgentFactory) CreateAgents(options *Options) ([]uncover.Agent, error) {
	var agents []uncover.Agent
	query := []string{}

	if len(options.Shodan) > 0 {
		options.Engine = append(options.Engine, "shodan")
		query = append(query, options.Shodan...)
	}
	if len(options.ShodanIdb) > 0 {
		options.Engine = append(options.Engine, "shodan-idb")
		query = append(query, options.ShodanIdb...)
	}
	if len(options.Fofa) > 0 {
		options.Engine = append(options.Engine, "fofa")
		query = append(query, options.Fofa...)
	}
	if len(options.Censys) > 0 {
		options.Engine = append(options.Engine, "censys")
		query = append(query, options.Censys...)
	}
	if len(options.Quake) > 0 {
		options.Engine = append(options.Engine, "quake")
		query = append(query, options.Quake...)
	}
	if len(options.Hunter) > 0 {
		options.Engine = append(options.Engine, "hunter")
		query = append(query, options.Hunter...)
	}
	if len(options.ZoomEye) > 0 {
		options.Engine = append(options.Engine, "zoomeye")
		query = append(query, options.ZoomEye...)
	}
	if len(options.Netlas) > 0 {
		options.Engine = append(options.Engine, "netlas")
		query = append(query, options.Netlas...)
	}
	if len(options.CriminalIP) > 0 {
		options.Engine = append(options.Engine, "criminalip")
		query = append(query, options.CriminalIP...)
	}
	if len(options.Publicwww) > 0 {
		options.Engine = append(options.Engine, "publicwww")
		query = append(query, options.Publicwww...)
	}
	if len(options.HunterHow) > 0 {
		options.Engine = append(options.Engine, "hunterhow")
		query = append(query, options.HunterHow...)
	}

	for _, engine := range options.Engine {
		var (
			err error
		)
		switch engine {
		case "shodan":
			agents = append(agents, &shodan.Agent{})
		case "censys":
			agents = append(agents, &censys.Agent{})
		case "fofa":
			agents = append(agents, &fofa.Agent{})
		case "shodan-idb":
			agents = append(agents, &shodanidb.Agent{})
		case "quake":
			agents = append(agents, &quake.Agent{})
		case "hunter":
			agents = append(agents, &hunter.Agent{})
		case "zoomeye":
			agents = append(agents, &zoomeye.Agent{})
		case "netlas":
			agents = append(agents, &netlas.Agent{})
		case "criminalip":
			agents = append(agents, &criminalip.Agent{})
		case "publicwww":
			agents = append(agents, &publicwww.Agent{})
		case "hunterhow":
			agents = append(agents, &hunterhow.Agent{})
		default:
			err = errors.New("unknown agent type")
		}
		if err != nil {
			return nil, err
		}
	}
	return agents, nil
}
