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

// AgentFactory is an implementation for creating and executing uncover agents.
type AgentFactory struct {
	options *Options
}

func New(options *Options) (AgentFactory, error) {
	factory := AgentFactory{
		options: options,
	}

	err := factory.updateOptionsQueries()
	if err != nil {
		return AgentFactory{}, err
	}

	return factory, nil
}

func (f *AgentFactory) CreateAgents() ([]uncover.Agent, error) {
	var agents []uncover.Agent

	for _, engine := range f.options.Engine {
		agent, err := f.createAgentByType(engine)
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}

	return agents, nil
}

func (f *AgentFactory) createAgentByType(engine string) (uncover.Agent, error) {
	switch engine {
	case "shodan":
		return &shodan.Agent{}, nil
	case "censys":
		return &censys.Agent{}, nil
	case "fofa":
		return &fofa.Agent{}, nil
	case "shodan-idb":
		return &shodanidb.Agent{}, nil
	case "quake":
		return &quake.Agent{}, nil
	case "hunter":
		return &hunter.Agent{}, nil
	case "zoomeye":
		return &zoomeye.Agent{}, nil
	case "netlas":
		return &netlas.Agent{}, nil
	case "criminalip":
		return &criminalip.Agent{}, nil
	case "publicwww":
		return &publicwww.Agent{}, nil
	case "hunterhow":
		return &hunterhow.Agent{}, nil
	default:
		return nil, errors.New("unknown agent type")
	}
}

func (f *AgentFactory) updateOptionsQueries() error {
	var query []string = f.options.Query
	if len(f.options.Shodan) > 0 {
		f.options.Engine = append(f.options.Engine, "shodan")
		query = append(query, f.options.Shodan...)
	}
	if len(f.options.ShodanIdb) > 0 {
		f.options.Engine = append(f.options.Engine, "shodan-idb")
		query = append(query, f.options.ShodanIdb...)
	}
	if len(f.options.Fofa) > 0 {
		f.options.Engine = append(f.options.Engine, "fofa")
		query = append(query, f.options.Fofa...)
	}
	if len(f.options.Censys) > 0 {
		f.options.Engine = append(f.options.Engine, "censys")
		query = append(query, f.options.Censys...)
	}
	if len(f.options.Quake) > 0 {
		f.options.Engine = append(f.options.Engine, "quake")
		query = append(query, f.options.Quake...)
	}
	if len(f.options.Hunter) > 0 {
		f.options.Engine = append(f.options.Engine, "hunter")
		query = append(query, f.options.Hunter...)
	}
	if len(f.options.ZoomEye) > 0 {
		f.options.Engine = append(f.options.Engine, "zoomeye")
		query = append(query, f.options.ZoomEye...)
	}
	if len(f.options.Netlas) > 0 {
		f.options.Engine = append(f.options.Engine, "netlas")
		query = append(query, f.options.Netlas...)
	}
	if len(f.options.CriminalIP) > 0 {
		f.options.Engine = append(f.options.Engine, "criminalip")
		query = append(query, f.options.CriminalIP...)
	}
	if len(f.options.Publicwww) > 0 {
		f.options.Engine = append(f.options.Engine, "publicwww")
		query = append(query, f.options.Publicwww...)
	}
	if len(f.options.HunterHow) > 0 {
		f.options.Engine = append(f.options.Engine, "hunterhow")
		query = append(query, f.options.HunterHow...)
	}

	f.options.Query = query
	return nil
}
