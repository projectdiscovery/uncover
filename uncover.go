package uncover

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/sources"
	"github.com/projectdiscovery/uncover/sources/agent/censys"
	"github.com/projectdiscovery/uncover/sources/agent/criminalip"
	"github.com/projectdiscovery/uncover/sources/agent/fofa"
	"github.com/projectdiscovery/uncover/sources/agent/hunter"
	"github.com/projectdiscovery/uncover/sources/agent/hunterhow"
	"github.com/projectdiscovery/uncover/sources/agent/netlas"
	"github.com/projectdiscovery/uncover/sources/agent/publicwww"
	"github.com/projectdiscovery/uncover/sources/agent/quake"
	"github.com/projectdiscovery/uncover/sources/agent/shodan"
	"github.com/projectdiscovery/uncover/sources/agent/shodanidb"
	"github.com/projectdiscovery/uncover/sources/agent/zoomeye"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var DefaultChannelBuffSize = 32

type Options struct {
	Agents   []string // Uncover Agents to use
	Queries  []string // Queries to pass to Agents
	Limit    int
	MaxRetry int
	Timeout  int
	// Note these ratelimits are used as fallback in case agent
	// ratelimit is not available in DefaultRateLimits
	RateLimit     uint          // default 30 req
	RateLimitUnit time.Duration // default unit
}

// Service handler of all uncover Agents
type Service struct {
	Options  *Options
	Agents   []sources.Agent
	Session  *sources.Session
	Provider *sources.Provider
	Keys     sources.Keys
}

// New creates new uncover service instance
func New(opts *Options) (*Service, error) {
	s := &Service{Agents: []sources.Agent{}, Options: opts}
	for _, v := range opts.Agents {
		switch v {
		case "shodan":
			s.Agents = append(s.Agents, &shodan.Agent{})
		case "censys":
			s.Agents = append(s.Agents, &censys.Agent{})
		case "fofa":
			s.Agents = append(s.Agents, &fofa.Agent{})
		case "shodan-idb":
			s.Agents = append(s.Agents, &shodanidb.Agent{})
		case "quake":
			s.Agents = append(s.Agents, &quake.Agent{})
		case "hunter":
			s.Agents = append(s.Agents, &hunter.Agent{})
		case "zoomeye":
			s.Agents = append(s.Agents, &zoomeye.Agent{})
		case "netlas":
			s.Agents = append(s.Agents, &netlas.Agent{})
		case "criminalip":
			s.Agents = append(s.Agents, &criminalip.Agent{})
		case "publicwww":
			s.Agents = append(s.Agents, &publicwww.Agent{})
		case "hunterhow":
			s.Agents = append(s.Agents, &hunterhow.Agent{})
		}
	}
	s.Provider = sources.NewProvider()
	s.Keys = s.Provider.GetKeys()

	if opts.RateLimit == 0 {
		opts.RateLimit = 30
	}
	if opts.RateLimitUnit == 0 {
		opts.RateLimitUnit = time.Minute
	}

	var err error
	s.Session, err = sources.NewSession(&s.Keys, opts.MaxRetry, opts.Timeout, 10, opts.Agents, opts.RateLimitUnit)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) Execute(ctx context.Context) (<-chan sources.Result, error) {
	// unlikely but as a precaution to handle random panics check all types
	if err := s.nilCheck(); err != nil {
		return nil, err
	}
	switch {
	case len(s.Agents) == 0:
		return nil, errorutil.NewWithTag("uncover", "no agent/source specified")
	case !s.hasAnyAnonymousProvider() && !s.Provider.HasKeys():
		return nil, errorutil.NewWithTag("uncover", "agents %v requires keys but no keys were found", s.Options.Agents)
	}

	megaChan := make(chan sources.Result, DefaultChannelBuffSize)
	// iterate and run all sources
	wg := &sync.WaitGroup{}
	for _, q := range s.Options.Queries {
	agentLabel:
		for _, agent := range s.Agents {
			keys := s.Provider.GetKeys()
			if keys.Empty() && agent.Name() != "shodan-idb" {
				gologger.Error().Msgf(agent.Name(), "agent given but keys not found")
				continue agentLabel
			}
			ch, err := agent.Query(s.Session, &sources.Query{
				Query: q,
				Limit: s.Options.Limit,
			})
			if err != nil {
				gologger.Error().Msgf("%s\n", err)
				continue agentLabel
			}
			wg.Add(1)
			go func(source, relay chan sources.Result, ctx context.Context) {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case res, ok := <-source:
						res.Timestamp = time.Now().Unix()
						if !ok {
							return
						}
						relay <- res
					}
				}
			}(ch, megaChan, ctx)
		}
	}

	// close channel when all sources return
	go func(wg *sync.WaitGroup, megaChan chan sources.Result) {
		wg.Wait()
		defer close(megaChan)
	}(wg, megaChan)

	return megaChan, nil
}

// ExecuteWithWriters writes output to writer along with stdout
func (s *Service) ExecuteWithCallback(ctx context.Context, callback func(result sources.Result)) error {
	ch, err := s.Execute(ctx)
	if err != nil {
		return err
	}
	if callback == nil {
		return errorutil.NewWithTag("uncover", "result callback cannot be nil")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case result, ok := <-ch:
			if !ok {
				return nil
			}
			callback(result)
		}
	}
}

// AllAgents returns all supported uncover Agents
func (s *Service) AllAgents() []string {
	return []string{
		"shodan", "censys", "fofa", "shodan-idb", "quake", "hunter", "zoomeye", "netlas", "criminalip", "publicwww", "hunterhow",
	}
}

func (s *Service) nilCheck() error {
	if s.Provider == nil {
		return errorutil.NewWithTag("uncover", "provider cannot be nil")
	}
	if s.Options == nil {
		return errorutil.NewWithTag("uncover", "options cannot be nil")
	}
	if s.Session == nil {
		return errorutil.NewWithTag("uncover", "session cannot be nil")
	}
	return nil
}

func (s *Service) hasAnyAnonymousProvider() bool {
	return stringsutil.EqualFoldAny("shodan-idb", s.Options.Agents...)
}
