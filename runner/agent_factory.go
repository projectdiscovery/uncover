package runner

import (
	"errors"
	"fmt"
	"strings"
	"time"

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

func NewAgents(options *Options) ([]uncover.Agent, error) {
	var agents []uncover.Agent

	// Update options queries
	err := updateOptionsQueries(options)
	if err != nil {
		return nil, err
	}

	for _, engine := range options.Engine {
		agent, err := createAgentByType(engine)
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}

	return agents, nil
}

func (r *Runner) Execute(agent uncover.Agent, session *uncover.Session, query *uncover.Query, outputWriter *OutputWriter) error {
	optionFields := r.options.OutputFields

	ch, err := agent.Query(session, query)
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
		return err
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
	return nil
}

func createAgentByType(engine string) (uncover.Agent, error) {
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

func updateOptionsQueries(options *Options) error {
	var query []string = options.Query
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

	options.Query = query
	return nil
}
