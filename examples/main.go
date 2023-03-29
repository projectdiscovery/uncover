package main

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
