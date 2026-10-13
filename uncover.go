package uncover

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/sources"
	"github.com/projectdiscovery/uncover/sources/agent/binaryedge"
	"github.com/projectdiscovery/uncover/sources/agent/censys"
	"github.com/projectdiscovery/uncover/sources/agent/criminalip"
	"github.com/projectdiscovery/uncover/sources/agent/daydaymap"
	"github.com/projectdiscovery/uncover/sources/agent/driftnet"
	"github.com/projectdiscovery/uncover/sources/agent/fofa"
	"github.com/projectdiscovery/uncover/sources/agent/google"
	"github.com/projectdiscovery/uncover/sources/agent/greynoise"
	"github.com/projectdiscovery/uncover/sources/agent/hunter"
	"github.com/projectdiscovery/uncover/sources/agent/hunterhow"
	"github.com/projectdiscovery/uncover/sources/agent/nerdydata"
	"github.com/projectdiscovery/uncover/sources/agent/netlas"
	"github.com/projectdiscovery/uncover/sources/agent/odin"
	"github.com/projectdiscovery/uncover/sources/agent/onyphe"
	"github.com/projectdiscovery/uncover/sources/agent/publicwww"
	"github.com/projectdiscovery/uncover/sources/agent/quake"
	"github.com/projectdiscovery/uncover/sources/agent/shodan"
	"github.com/projectdiscovery/uncover/sources/agent/shodanidb"
	"github.com/projectdiscovery/uncover/sources/agent/zoomeye"

	"github.com/projectdiscovery/utils/errkit"
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
	Proxy         string        // http proxy to use with uncover
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
		case "google":
			s.Agents = append(s.Agents, &google.Agent{})
		case "odin":
			s.Agents = append(s.Agents, &odin.Agent{})
		case "binaryedge":
			s.Agents = append(s.Agents, &binaryedge.Agent{})
		case "onyphe":
			s.Agents = append(s.Agents, &onyphe.Agent{})
		case "driftnet":
			s.Agents = append(s.Agents, &driftnet.Agent{})
		case "greynoise":
			s.Agents = append(s.Agents, &greynoise.Agent{})
		case "daydaymap":
			s.Agents = append(s.Agents, &daydaymap.Agent{})
		case "nerdydata":
			s.Agents = append(s.Agents, &nerdydata.Agent{})
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
	s.Session, err = sources.NewSession(&s.Keys, opts.MaxRetry, opts.Timeout, 10, opts.Agents, opts.RateLimitUnit, opts.Proxy)
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
		return nil, errkit.New("no agent/source specified")
	case !s.hasAnyAnonymousProvider() && !s.Provider.HasKeys():
		return nil, errkit.Newf("agents %v requires keys but no keys were found", s.Options.Agents)
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
			ch, err := agent.Query(ctx, s.Session, &sources.Query{
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
		return errkit.New("result callback cannot be nil")
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
		"shodan", "censys", "fofa", "shodan-idb", "quake", "hunter", "zoomeye", "netlas", "criminalip", "publicwww", "hunterhow", "google", "odin", "binaryedge", "onyphe", "driftnet", "greynoise", "daydaymap", "nerdydata",
	}
}

// AllBalanceAgents returns search engine agents that support querying account balance
func AllBalanceAgents() []string {
	return []string{
		"shodan", "censys", "fofa", "hunter", "quake", "zoomeye", "netlas", "criminalip",
	}
}

func (s *Service) AllBalanceAgents() []string {
	return AllBalanceAgents()
}

// CheckCredits queries account remaining credits across configured search engine providers
func (s *Service) CheckCredits(ctx context.Context, allProvidersMode bool) ([]*sources.AccountBalance, error) {
	var balances []*sources.AccountBalance
	err := s.ExecuteCheckCredits(ctx, allProvidersMode, func(balance *sources.AccountBalance) {
		balances = append(balances, balance)
	})
	return balances, err
}

// ExecuteCheckCredits queries account remaining credits and invokes callback on each result
func (s *Service) ExecuteCheckCredits(ctx context.Context, allProvidersMode bool, callback func(balance *sources.AccountBalance)) error {
	if err := s.nilCheck(); err != nil {
		return err
	}
	if callback == nil {
		return errkit.New("balance callback cannot be nil")
	}

	keys := s.Provider.GetKeys()
	checkedCount := 0

	for _, agent := range s.Agents {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		balanceAgent, ok := agent.(sources.BalanceAccount)
		if !ok {
			if !allProvidersMode {
				gologger.Warning().Label(agent.Name()).Msg("balance check not supported for provider")
			}
			continue
		}

		if allProvidersMode && !keys.HasKeysFor(agent.Name()) {
			continue
		}

		checkedCount++
		balance, err := balanceAgent.Balance(ctx, s.Session)
		if err != nil {
			gologger.Warning().Label(agent.Name()).Msgf("%s\n", err)
			continue
		}
		if balance != nil {
			callback(balance)
		}
	}

	if allProvidersMode && checkedCount == 0 {
		gologger.Warning().Msg("no configured provider keys found")
	}

	return nil
}

func (s *Service) nilCheck() error {
	if s.Provider == nil {
		return errkit.New("provider cannot be nil")
	}
	if s.Options == nil {
		return errkit.New("options cannot be nil")
	}
	if s.Session == nil {
		return errkit.New("session cannot be nil")
	}
	return nil
}

func (s *Service) hasAnyAnonymousProvider() bool {
	return stringsutil.EqualFoldAny("shodan-idb", s.Options.Agents...)
}
