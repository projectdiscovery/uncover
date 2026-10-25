package uncover

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

type resultAgent struct {
	results chan sources.Result
}

func (a *resultAgent) Name() string { return "shodan-idb" }

func (a *resultAgent) Query(context.Context, *sources.Session, *sources.Query) (chan sources.Result, error) {
	return a.results, nil
}

func serviceWithResults(results chan sources.Result) *Service {
	return &Service{
		Options:  &Options{Agents: []string{"shodan-idb"}, Queries: []string{"test"}},
		Agents:   []sources.Agent{&resultAgent{results: results}},
		Session:  &sources.Session{},
		Provider: &sources.Provider{},
	}
}

func TestExecuteCancelsBlockedRelay(t *testing.T) {
	for _, bufferSize := range []int{0, DefaultChannelBuffSize} {
		t.Run(fmt.Sprintf("buffer=%d", bufferSize), func(t *testing.T) {
			originalBufferSize := DefaultChannelBuffSize
			DefaultChannelBuffSize = bufferSize
			t.Cleanup(func() { DefaultChannelBuffSize = originalBufferSize })

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			source := make(chan sources.Result)
			results, err := serviceWithResults(source).Execute(ctx)
			require.NoError(t, err)
			t.Cleanup(func() {
				cancel()
				close(source)
				// Also release a blocked relay if the regression is present.
				for range results {
				}
			})

			// The final unbuffered source send can only finish once the relay
			// has accepted a result that will not fit in its output buffer.
			for i := 0; i <= bufferSize; i++ {
				select {
				case source <- sources.Result{Host: fmt.Sprintf("host-%d", i)}:
				case <-time.After(5 * time.Second):
					t.Fatal("relay did not accept the source result")
				}
			}
			cancel()

			// Keep the consumer stopped while cancellation is handled. Draining
			// immediately would unblock the send and hide the goroutine leak.
			time.Sleep(100 * time.Millisecond)
			for i := 0; i < bufferSize; i++ {
				result := <-results
				require.Equal(t, fmt.Sprintf("host-%d", i), result.Host)
				require.NotZero(t, result.Timestamp)
			}
			select {
			case _, ok := <-results:
				require.False(t, ok, "relay delivered the blocked result after cancellation")
			case <-time.After(5 * time.Second):
				t.Fatal("result channel did not close after cancellation")
			}
		})
	}
}

func TestExecuteRelaysResults(t *testing.T) {
	source := make(chan sources.Result, 2)
	source <- sources.Result{Host: "first"}
	source <- sources.Result{Host: "second"}
	close(source)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := serviceWithResults(source).Execute(ctx)
	require.NoError(t, err)
	var hosts []string
	for {
		select {
		case result, ok := <-results:
			if !ok {
				require.Equal(t, []string{"first", "second"}, hosts)
				return
			}
			require.NotZero(t, result.Timestamp)
			hosts = append(hosts, result.Host)
		case <-ctx.Done():
			t.Fatal("result channel did not close after the source finished")
		}
	}
}

func TestAllBalanceAgents(t *testing.T) {
	agents := AllBalanceAgents()
	require.NotEmpty(t, agents)
	require.Contains(t, agents, "shodan")
	require.Contains(t, agents, "censys")
	require.Contains(t, agents, "fofa")
	require.Contains(t, agents, "hunter")
	require.Contains(t, agents, "quake")
	require.Contains(t, agents, "zoomeye")
	require.Contains(t, agents, "netlas")
	require.Contains(t, agents, "criminalip")
}

func TestService_ExecuteCheckCredits_AllProvidersNoKeys(t *testing.T) {
	isolateProviderConfig(t)

	opts := &Options{
		Agents: AllBalanceAgents(),
	}
	s, err := New(opts)
	require.NoError(t, err)

	var receivedBalances []*sources.AccountBalance
	err = s.ExecuteCheckCredits(context.Background(), true, func(b *sources.AccountBalance) {
		receivedBalances = append(receivedBalances, b)
	})
	require.NoError(t, err)
	// When no keys are configured, allProvidersMode should skip without error
	require.Empty(t, receivedBalances)
}

func TestService_CheckCredits_Method(t *testing.T) {
	isolateProviderConfig(t)

	opts := &Options{
		Agents: []string{"shodan"},
	}
	s, err := New(opts)
	require.NoError(t, err)

	balances, err := s.CheckCredits(context.Background(), false)
	require.NoError(t, err)
	// Shodan with empty keys will fail to query and log warning, returning nil balances
	require.Empty(t, balances)
}

func isolateProviderConfig(t *testing.T) {
	t.Helper()
	origConfig := sources.DefaultProviderConfigLocation
	sources.DefaultProviderConfigLocation = filepath.Join(t.TempDir(), "provider-config.yaml")
	t.Cleanup(func() {
		sources.DefaultProviderConfigLocation = origConfig
	})
	for _, env := range providerEnvVars {
		t.Setenv(env, "")
	}
}

var providerEnvVars = []string{
	"SHODAN_API_KEY",
	"HUNTER_API_KEY",
	"QUAKE_TOKEN",
	"NETLAS_API_KEY",
	"CRIMINALIP_API_KEY",
	"PUBLICWWW_API_KEY",
	"HUNTERHOW_API_KEY",
	"ZOOMEYE_API_KEY",
	"DRIFTNET_API_KEY",
	"DAYDAYMAP_API_KEY",
	"FOFA_EMAIL",
	"FOFA_KEY",
	"CENSYS_API_TOKEN",
	"CENSYS_ORGANIZATION_ID",
	"GOOGLE_API_KEY",
	"GOOGLE_API_CX",
	"ODIN_API_KEY",
	"BINARYEDGE_API_KEY",
	"ONYPHE_API_KEY",
	"GREYNOISE_API_KEY",
	"NERDYDATA_API_KEY",
}
