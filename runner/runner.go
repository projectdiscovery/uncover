package runner

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/uncover"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Runner is an instance of the uncover enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options *Options
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}
	return runner, nil
}

// RunEnumeration runs the subdomain enumeration flow on the targets specified
func (r *Runner) Run(ctx context.Context) error {
	if !r.options.Provider.HasKeys() && !r.options.hasAnyAnonymousProvider() {
		return errors.New("no keys provided")
	}

	agents, err := NewAgents(r.options)
	if err != nil {
		return err
	}

	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}

	if !r.options.Verbose {
		outputWriter.AddWriters(os.Stdout)
	}

	if r.options.OutputFile != "" {
		outputFile, err := os.Create(r.options.OutputFile)
		if err != nil {
			return err
		}
		defer outputFile.Close()
		outputWriter.AddWriters(outputFile)
	}

	var wg sync.WaitGroup
	for _, q := range r.options.Query {
		uncoverQuery := &uncover.Query{
			Query: q,
			Limit: r.options.Limit,
		}
		for _, agent := range agents {
			wg.Add(1)
			keys := r.options.Provider.GetKeys()
			if keys.Empty() && agent.Name() != "shodan-idb" {
				gologger.Error().Label(agent.Name()).Msgf("empty keys\n")
				return nil
			}
			var session *uncover.Session
			if r.options.RateLimitMinute > 0 {
				session, err = uncover.NewSession(&keys, r.options.Retries, r.options.Timeout, r.options.RateLimitMinute, r.options.Engine, time.Minute)
			} else {
				session, err = uncover.NewSession(&keys, r.options.Retries, r.options.Timeout, r.options.RateLimit, r.options.Engine, time.Second)
			}
			if err != nil {
				gologger.Error().Label(agent.Name()).Msgf("couldn't create new session: %s\n", err)
			}
			go func(agent uncover.Agent, uncoverQuery *uncover.Query) {
				defer wg.Done()

				err := r.Execute(agent, session, uncoverQuery, outputWriter)
				if err != nil {
					gologger.Warning().Msgf("%s\n", err)
				}
			}(agent, uncoverQuery)
		}
	}

	wg.Wait()
	return nil
}
