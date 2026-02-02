Usage:
  ./uncover [flags]

Flags:
INPUT:
   -q, -query string[]   search query, supports: stdin,file,config input (example: -q 'example query', -q 'query.txt')
   -e, -engine string[]  search engine to query (shodan,shodan-idb,fofa,censys,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow,google,driftnet) (default shodan)
   -asq, -awesome-search-queries string[]  use awesome search queries to discover exposed assets on the internet (example: -asq 'jira')

SEARCH-ENGINE:
   -s, -shodan string[]       search query for shodan (example: -shodan 'query.txt')
   -sd, -shodan-idb string[]  search query for shodan-idb (example: -shodan-idb 'query.txt')
   -ff, -fofa string[]        search query for fofa (example: -fofa 'query.txt')
   -cs, -censys string[]      search query for censys (example: -censys 'query.txt')
   -qk, -quake string[]       search query for quake (example: -quake 'query.txt')
   -ht, -hunter string[]      search query for hunter (example: -hunter 'query.txt')
   -ze, -zoomeye string[]     search query for zoomeye (example: -zoomeye 'query.txt')
   -ne, -netlas string[]      search query for netlas (example: -netlas 'query.txt')
   -cl, -criminalip string[]  search query for criminalip (example: -criminalip 'query.txt')
   -pw, -publicwww string[]   search query for publicwww (example: -publicwww 'query.txt')
   -hh, -hunterhow string[]   search query for hunterhow (example: -hunterhow 'query.txt')
   -gg, -google string[]       search query for google (example: -google 'query.txt')
   -on, -onyphe string[]      search query for onyphe (example: -onyphe 'query.txt')
   -df, -driftnet string[]    search query for driftnet (example: -driftnet 'query.txt')

CONFIG:
   -pc, -provider string         provider configuration file (default "$CONFIG/uncover/provider-config.yaml")
   -config string                flag configuration file (default "$CONFIG/uncover/config.yaml")
   -timeout int                  timeout in seconds (default 30)
   -rl, -rate-limit int          maximum number of http requests to send per second
   -rlm, -rate-limit-minute int  maximum number of requests to send per minute
   -retry int                    number of times to retry a failed request (default 2)
   -proxy string                 http proxy to use with uncover

OUTPUT:
   -o, -output string  output file to write found results
   -f, -field string   field to display in output (ip,port,host) (default "ip:port")
   -j, -json           write output in JSONL(ines) format
   -r, -raw            write raw output as received by the remote api
   -l, -limit int      limit the number of results to return (default 100)
   -nc, -no-color      disable colors in output

DEBUG:
   -silent   show only results in output
   -version  show version of the project
   -v        show verbose outputpackage main

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"
)

func main() {
	opts := uncover.Options{
		Agents:   []string{"shodan"},
		Queries:  []string{"ssl:'hackerone.com'"},
		Limit:    50,
		MaxRetry: 2,
		Timeout:  20,
	}

	u, err := uncover.New(&opts)
	if err != nil {
		panic(err)
	}

	allagents := u.AllAgents()
	gologger.Info().Msgf("Available uncover agents/sources :")
	for _, v := range allagents {
		fmt.Println(v)
	}

	fmt.Println("\n\n- Uncover Results:")
	result := func(result sources.Result) {
		fmt.Println(result.IpPort())
	}

	// Execute executes and returns a channel with all results
	// ch , err := u.Execute(context.Background())

	// Execute with Callback calls u.Execute() internally and abstracts channel handling logic
	if err := u.ExecuteWithCallback(context.TODO(), result); err != nil {
		panic(err)
	}
}
