package runner

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/stringsutil"
	"github.com/projectdiscovery/uncover/uncover"
	"github.com/projectdiscovery/uncover/uncover/agent/censys"
	"github.com/projectdiscovery/uncover/uncover/agent/fofa"
	"github.com/projectdiscovery/uncover/uncover/agent/hunter"
	"github.com/projectdiscovery/uncover/uncover/agent/quake"
	"github.com/projectdiscovery/uncover/uncover/agent/shodan"
	"github.com/projectdiscovery/uncover/uncover/agent/shodanidb"
	"github.com/projectdiscovery/uncover/uncover/agent/zoomeye"
	"go.uber.org/ratelimit"
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
func (r *Runner) Run(ctx context.Context, query ...string) error {
	if !r.options.Provider.HasKeys() && !r.options.hasAnyAnonymousProvider() {
		return errors.New("no keys provided")
	}

	var censysRateLimiter, fofaRateLimiter, shodanRateLimiter, shodanIdbRateLimiter, quakeRatelimiter, hunterRatelimiter, zoomeyeRatelimiter ratelimit.Limiter
	if r.options.Delay > 0 {
		censysRateLimiter = ratelimit.New(1, ratelimit.Per(r.options.delay))
		fofaRateLimiter = ratelimit.New(1, ratelimit.Per(r.options.delay))
		shodanRateLimiter = ratelimit.New(1, ratelimit.Per(r.options.delay))
		shodanIdbRateLimiter = ratelimit.New(1, ratelimit.Per(r.options.delay))
		quakeRatelimiter = ratelimit.New(1, ratelimit.Per(r.options.delay))
		hunterRatelimiter = ratelimit.New(1, ratelimit.Per(r.options.delay))
		zoomeyeRatelimiter = ratelimit.New(1, ratelimit.Per(r.options.delay))
	} else {
		censysRateLimiter = ratelimit.NewUnlimited()
		fofaRateLimiter = ratelimit.NewUnlimited()
		shodanRateLimiter = ratelimit.NewUnlimited()
		shodanIdbRateLimiter = ratelimit.NewUnlimited()
		quakeRatelimiter = ratelimit.NewUnlimited()
		hunterRatelimiter = ratelimit.NewUnlimited()
		zoomeyeRatelimiter = ratelimit.NewUnlimited()
	}

	var agents []uncover.Agent
	if len(r.options.Shodan) > 0 {
		r.options.Engine = append(r.options.Engine, "shodan")
		query = append(query, r.options.Shodan...)
	}
	if len(r.options.ShodanIdb) > 0 {
		r.options.Engine = append(r.options.Engine, "shodan-idb")
		query = append(query, r.options.ShodanIdb...)
	}
	if len(r.options.Fofa) > 0 {
		r.options.Engine = append(r.options.Engine, "fofa")
		query = append(query, r.options.Fofa...)
	}
	if len(r.options.Censys) > 0 {
		r.options.Engine = append(r.options.Engine, "censys")
		query = append(query, r.options.Censys...)
	}
	if len(r.options.Quake) > 0 {
		r.options.Engine = append(r.options.Engine, "quake")
		query = append(query, r.options.Quake...)
	}
	if len(r.options.Hunter) > 0 {
		r.options.Engine = append(r.options.Engine, "hunter")
		query = append(query, r.options.Hunter...)
	}
	if len(r.options.ZoomEye) > 0 {
		r.options.Engine = append(r.options.Engine, "zoomeye")
		query = append(query, r.options.ZoomEye...)
	}

	// declare clients
	for _, engine := range r.options.Engine {
		var (
			agent uncover.Agent
			err   error
		)
		switch engine {
		case "shodan":
			agent, err = shodan.NewWithOptions(&uncover.AgentOptions{RateLimiter: shodanRateLimiter})
		case "censys":
			agent, err = censys.NewWithOptions(&uncover.AgentOptions{RateLimiter: censysRateLimiter})
		case "fofa":
			agent, err = fofa.NewWithOptions(&uncover.AgentOptions{RateLimiter: fofaRateLimiter})
		case "shodan-idb":
			agent, err = shodanidb.NewWithOptions(&uncover.AgentOptions{RateLimiter: shodanIdbRateLimiter})
		case "quake":
			agent, err = quake.NewWithOptions(&uncover.AgentOptions{RateLimiter: quakeRatelimiter})
		case "hunter":
			agent, err = hunter.NewWithOptions(&uncover.AgentOptions{RateLimiter: hunterRatelimiter})
		case "zoomeye":
			agent, err = zoomeye.NewWithOptions(&uncover.AgentOptions{RateLimiter: zoomeyeRatelimiter})
		default:
			err = errors.New("unknown agent type")
		}
		if err != nil {
			return err
		}
		agents = append(agents, agent)
	}

	// open the output file - always overwrite
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}

	// don't write to stdout if we're using verbose mode
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
	// enumerate
	var wg sync.WaitGroup

	for _, q := range query {
		uncoverQuery := &uncover.Query{
			Query: q,
			Limit: r.options.Limit,
		}
		for _, agent := range agents {
			// skip all agents for pure ips/cidrs
			if shouldSkipForAgent(agent, uncoverQuery) {
				continue
			}
			wg.Add(1)
			go func(agent uncover.Agent, uncoverQuery *uncover.Query) {
				defer wg.Done()
				keys := r.options.Provider.GetKeys()
				if keys.Empty() && agent.Name() != "shodan-idb" {
					gologger.Error().Label(agent.Name()).Msgf("empty keys\n")
					return
				}
				session, err := uncover.NewSession(&keys, r.options.Retries, r.options.Timeout)
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
						)
						outData := replacer.Replace(r.options.OutputFields)
						searchFor := []string{result.IP, port}
						if result.Host != "" || r.options.OutputFile != "" {
							searchFor = append(searchFor, result.Host)
						}
						// send to output if any of the field got replaced
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

func shouldSkipForAgent(agent uncover.Agent, uncoverQuery *uncover.Query) bool {
	return (iputil.IsIP(uncoverQuery.Query) || iputil.IsCIDR(uncoverQuery.Query)) && agent.Name() != "shodan-idb"
}
