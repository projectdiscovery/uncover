package uncover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

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
