package runner

import (
	"os"
	"path/filepath"

	"errors"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/uncover/sources"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	genericutil "github.com/projectdiscovery/utils/generic"
	updateutils "github.com/projectdiscovery/utils/update"
)

var (
	defaultConfigLocation = filepath.Join(folderutil.HomeDirOrDefault("."), ".config/uncover/config.yaml")
)

// Options contains the configuration options for tuning the enumeration process.
type Options struct {
	Query              goflags.StringSlice
	Engine             goflags.StringSlice
	ConfigFile         string
	ProviderFile       string
	OutputFile         string
	OutputFields       string
	JSON               bool
	Raw                bool
	Limit              int
	Silent             bool
	Verbose            bool
	NoColor            bool
	Timeout            int
	RateLimit          int
	RateLimitMinute    int
	Retries            int
	Shodan             goflags.StringSlice
	ShodanIdb          goflags.StringSlice
	Fofa               goflags.StringSlice
	Censys             goflags.StringSlice
	Quake              goflags.StringSlice
	Netlas             goflags.StringSlice
	Hunter             goflags.StringSlice
	ZoomEye            goflags.StringSlice
	CriminalIP         goflags.StringSlice
	Publicwww          goflags.StringSlice
	HunterHow          goflags.StringSlice
	DisableUpdateCheck bool
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`quickly discover exposed assets on the internet using multiple search engines.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Query, "query", "q", nil, "search query, supports: stdin,file,config input (example: -q 'example query', -q 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.Engine, "engine", "e", nil, "search engine to query (shodan,shodan-idb,fofa,censys,quake,hunter,zoomeye,netlas,publicwww,criminalip,hunterhow) (default shodan)", goflags.FileNormalizedStringSliceOptions),
	)

	flagSet.CreateGroup("search-engine", "Search-Engine",
		flagSet.StringSliceVarP(&options.Shodan, "shodan", "s", nil, "search query for shodan (example: -shodan 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.ShodanIdb, "shodan-idb", "sd", nil, "search query for shodan-idb (example: -shodan-idb 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.Fofa, "fofa", "ff", nil, "search query for fofa (example: -fofa 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.Censys, "censys", "cs", nil, "search query for censys (example: -censys 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.Quake, "quake", "qk", nil, "search query for quake (example: -quake 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.Hunter, "hunter", "ht", nil, "search query for hunter (example: -hunter 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.ZoomEye, "zoomeye", "ze", nil, "search query for zoomeye (example: -zoomeye 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.Netlas, "netlas", "ne", nil, "search query for netlas (example: -netlas 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.CriminalIP, "criminalip", "cl", nil, "search query for criminalip (example: -criminalip 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.Publicwww, "publicwww", "pw", nil, "search query for publicwww (example: -publicwww 'query.txt')", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.HunterHow, "hunterhow", "hh", nil, "search query for hunterhow (example: -hunterhow 'query.txt')", goflags.FileStringSliceOptions),
	)

	flagSet.CreateGroup("config", "Config",
		flagSet.StringVarP(&options.ProviderFile, "provider", "pc", sources.DefaultProviderConfigLocation, "provider configuration file"),
		flagSet.StringVar(&options.ConfigFile, "config", defaultConfigLocation, "flag configuration file"),
		flagSet.IntVar(&options.Timeout, "timeout", 30, "timeout in seconds"),
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 0, "maximum number of http requests to send per second"),
		flagSet.IntVarP(&options.RateLimitMinute, "rate-limit-minute", "rlm", 0, "maximum number of requests to send per minute"),
		flagSet.IntVar(&options.Retries, "retry", 2, "number of times to retry a failed request"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "update uncover to latest version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic uncover update check"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "output file to write found results"),
		flagSet.StringVarP(&options.OutputFields, "field", "f", "ip:port", "field to display in output (ip,port,host)"),
		flagSet.BoolVarP(&options.JSON, "json", "j", false, "write output in JSONL(ines) format"),
		flagSet.BoolVarP(&options.Raw, "raw", "r", false, "write raw output as received by the remote api"),
		flagSet.IntVarP(&options.Limit, "limit", "l", 100, "limit the number of results to return"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable colors in output"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "show only results in output"),
		flagSet.CallbackVar(versionCallback, "version", "show version of the project"),
		flagSet.BoolVar(&options.Verbose, "v", false, "show verbose output"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	options.configureOutput()
	showBanner()

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("uncover", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("uncover version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current uncover version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	if options.ConfigFile != defaultConfigLocation {
		_ = options.loadConfigFrom(options.ConfigFile)
	}

	if options.ProviderFile != sources.DefaultProviderConfigLocation {
		sources.DefaultProviderConfigLocation = options.ProviderFile
	}

	if genericutil.EqualsAll(0,
		len(options.Engine),
		len(options.Shodan),
		len(options.Censys),
		len(options.Quake),
		len(options.Fofa),
		len(options.ShodanIdb),
		len(options.Hunter),
		len(options.ZoomEye),
		len(options.Netlas),
		len(options.CriminalIP),
		len(options.Publicwww),
		len(options.HunterHow)) {
		options.Engine = append(options.Engine, "shodan")
	}

	// we make the assumption that input queries aren't that much
	if fileutil.HasStdin() {
		stdchan, err := fileutil.ReadFileWithReader(os.Stdin)
		if err != nil {
			gologger.Fatal().Msgf("couldn't read stdin: %s\n", err)
		}
		for query := range stdchan {
			options.Query = append(options.Query, query)
		}
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	if err := options.validateOptions(); err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

func (Options *Options) loadConfigFrom(location string) error {
	if !fileutil.FileExists(location) {
		return errorutil.New("config file %s does not exist", location)
	}
	return fileutil.Unmarshal(fileutil.YAML, []byte(location), Options)
}

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// Check if domain, list of domains, or stdin info was provided.
	// If none was provided, then return.
	if genericutil.EqualsAll(0,
		len(options.Query),
		len(options.Shodan),
		len(options.Censys),
		len(options.Quake),
		len(options.Fofa),
		len(options.ShodanIdb),
		len(options.Hunter),
		len(options.ZoomEye),
		len(options.Netlas),
		len(options.CriminalIP),
		len(options.Publicwww),
		len(options.HunterHow)) {
		return errors.New("no query provided")
	}

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	// Validate threads and options
	if genericutil.EqualsAll(0,
		len(options.Engine),
		len(options.Shodan),
		len(options.Censys),
		len(options.Quake),
		len(options.Fofa),
		len(options.ShodanIdb),
		len(options.Hunter),
		len(options.ZoomEye),
		len(options.Netlas),
		len(options.CriminalIP),
		len(options.Publicwww),
		len(options.HunterHow)) {
		return errors.New("no engine specified")
	}

	return nil
}

func versionCallback() {
	gologger.Info().Msgf("Current Version: %s\n", version)
	os.Exit(0)
}

func appendQuery(options *Options, name string, queries ...string) {
	if len(queries) > 0 {
		options.Engine = append(options.Engine, name)
		options.Query = append(options.Query, queries...)
	}
}

func appendAllQueries(options *Options) {
	appendQuery(options, "shodan", options.Shodan...)
	appendQuery(options, "shodan-idb", options.ShodanIdb...)
	appendQuery(options, "fofa", options.Fofa...)
	appendQuery(options, "censys", options.Censys...)
	appendQuery(options, "quake", options.Quake...)
	appendQuery(options, "hunter", options.Hunter...)
	appendQuery(options, "zoomeye", options.ZoomEye...)
	appendQuery(options, "netlas", options.Netlas...)
	appendQuery(options, "criminalip", options.CriminalIP...)
	appendQuery(options, "publicwww", options.Publicwww...)
	appendQuery(options, "hunterhow", options.HunterHow...)
}
