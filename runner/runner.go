package runner

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/uncover"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Runner is an instance of the uncover enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options      *Options
	agentFactory AgentFactory
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options, agentFactory AgentFactory) (*Runner, error) {
	runner := &Runner{options: options, agentFactory: agentFactory}
	return runner, nil
}

// RunEnumeration runs the subdomain enumeration flow on the targets specified
func (r *Runner) Run(ctx context.Context) error {
	if !r.options.Provider.HasKeys() && !r.options.hasAnyAnonymousProvider() {
		return errors.New("no keys provided")
	}

	agents, err := r.agentFactory.CreateAgents()
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
			go func(agent uncover.Agent, uncoverQuery *uncover.Query) {
				optionFields := r.options.OutputFields
				defer wg.Done()
				keys := r.options.Provider.GetKeys()
				if keys.Empty() && agent.Name() != "shodan-idb" {
					gologger.Error().Label(agent.Name()).Msgf("empty keys\n")
					return
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

				ch, err := agent.Query(session, uncoverQuery)
				if err != nil {
					gologger.Warning().Msgf("%s\n", err)
					return
				}
				for result := range ch {
					result.Timestamp = time.Now().Unix()
					switch {
					case result.Error != nil:
						gologger.Warning().Label(agent.Name()).Msgf("%s\n", result.Error.Error())
					case r.options.JSON:
						gologger.Verbose().Label(agent.Name()).Msgf("%s\n", result.JSON())
						outputWriter.WriteJsonData(result)
					case r.options.Raw:
						gologger.Verbose().Label(agent.Name()).Msgf("%s\n", result.RawData())
						outputWriter.WriteString(result.RawData())
					default:
						port := fmt.Sprint(result.Port)
						replacer := strings.NewReplacer(
							"ip", result.IP,
							"host", result.Host,
							"port", port,
							"url", result.Url,
						)
						if (result.IP == "" || port == "0") && stringsutil.ContainsAny(r.options.OutputFields, "ip", "port") {
							optionFields = "host"
						}
						outData := replacer.Replace(optionFields)
						searchFor := []string{result.IP, port}
						if result.Host != "" || r.options.OutputFile != "" {
							searchFor = append(searchFor, result.Host)
						}
						if stringsutil.ContainsAny(outData, searchFor...) {
							gologger.Verbose().Label(agent.Name()).Msgf("%s\n", outData)
							outputWriter.WriteString(outData)
						}
					}
				}
			}(agent, uncoverQuery)
		}
	}

	wg.Wait()
	return nil
}
