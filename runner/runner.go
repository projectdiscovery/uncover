package runner

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Runner is an instance of the uncover enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options      *Options
	service      *uncover.Service
	outputWriter *OutputWriter
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}
	appendAllQueries(options)

	opts := uncover.Options{
		Agents:  options.Engine,
		Queries: options.Query,
		Limit:   options.Limit,
	}
	service, err := uncover.New(&opts)
	if err != nil {
		return nil, err
	}
	runner.service = service

	runner.outputWriter, err = NewOutputWriter()
	if err != nil {
		return nil, err
	}

	return runner, nil
}

// RunEnumeration runs the subdomain enumeration flow on the targets specified
func (r *Runner) Run(ctx context.Context) error {
	resultCallback := func(result sources.Result) {
		optionFields := r.options.OutputFields
		switch {
		case result.Error != nil:
			gologger.Warning().Label(result.Source).Msgf("%s\n", result.Error.Error())
		case r.options.JSON:
			gologger.Verbose().Label(result.Source).Msgf("%s\n", result.JSON())
			r.outputWriter.WriteJsonData(result)
		case r.options.Raw:
			gologger.Verbose().Label(result.Source).Msgf("%s\n", result.RawData())
			r.outputWriter.WriteString(result.RawData())
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
				gologger.Verbose().Label(result.Source).Msgf("%s\n", outData)
				r.outputWriter.WriteString(outData)
			}
		}
	}
	return r.service.ExecuteWithCallback(ctx, resultCallback)
}
