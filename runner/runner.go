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
	stringsutil "github.com/projectdiscovery/utils/strings"
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
	if len(r.options.Netlas) > 0 {
		r.options.Engine = append(r.options.Engine, "netlas")
		query = append(query, r.options.Netlas...)
	}
	if len(r.options.CriminalIP) > 0 {
		r.options.Engine = append(r.options.Engine, "criminalip")
		query = append(query, r.options.CriminalIP...)
	}
	if len(r.options.Publicwww) > 0 {
		r.options.Engine = append(r.options.Engine, "publicwww")
		query = append(query, r.options.Publicwww...)
	}
	if len(r.options.HunterHow) > 0 {
		r.options.Engine = append(r.options.Engine, "hunterhow")
		query = append(query, r.options.HunterHow...)
	}

	// declare clients
	for _, engine := range r.options.Engine {
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
			return err
		}
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
