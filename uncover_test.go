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
	origConfig := sources.DefaultProviderConfigLocation
	sources.DefaultProviderConfigLocation = filepath.Join(t.TempDir(), "provider-config.yaml")
	t.Cleanup(func() {
		sources.DefaultProviderConfigLocation = origConfig
	})
	t.Setenv("SHODAN_API_KEY", "")

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
