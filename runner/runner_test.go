package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func TestValidateOptions_CheckCredits(t *testing.T) {
	// Standard mode without query should fail validation
	opts := &Options{
		CheckCredits: false,
	}
	err := opts.validateOptions()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no query provided")

	// CheckCredits enabled does not require a query
	optsCredit := &Options{
		CheckCredits: true,
	}
	err = optsCredit.validateOptions()
	require.NoError(t, err)

	// Both verbose and silent fails even with CheckCredits
	optsConflicting := &Options{
		CheckCredits: true,
		Verbose:      true,
		Silent:       true,
	}
	err = optsConflicting.validateOptions()
	require.Error(t, err)
	require.Contains(t, err.Error(), "both verbose and silent mode specified")
}

func TestNewRunner_CheckCredits_DefaultEngines(t *testing.T) {
	isolateProviderConfig(t)
	opts := &Options{
		CheckCredits: true,
	}
	r, err := NewRunner(opts)
	require.NoError(t, err)
	defer r.Close()

	// When CheckCredits is enabled and no engine is specified, all balance agents should be initialized
	expectedAgents := uncover.AllBalanceAgents()
	require.Equal(t, len(expectedAgents), len(r.service.Agents))
}

func TestNewRunner_CheckCredits_ExplicitEngines(t *testing.T) {
	isolateProviderConfig(t)
	opts := &Options{
		CheckCredits: true,
		Engine:       []string{"shodan", "censys"},
	}
	r, err := NewRunner(opts)
	require.NoError(t, err)
	defer r.Close()

	require.Equal(t, 2, len(r.service.Agents))
}

func TestRunner_CheckCredits_NoKeys(t *testing.T) {
	isolateProviderConfig(t)
	tmpFile, err := os.CreateTemp("", "uncover-test-output-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	opts := &Options{
		CheckCredits: true,
		OutputFile:   tmpFile.Name(),
	}
	r, err := NewRunner(opts)
	require.NoError(t, err)
	defer r.Close()

	// Running check credits with all providers when no keys configured should complete cleanly
	err = r.Run(context.Background())
	require.NoError(t, err)
}

func isolateProviderConfig(t *testing.T) {
	t.Helper()
	origConfig := sources.DefaultProviderConfigLocation
	sources.DefaultProviderConfigLocation = filepath.Join(t.TempDir(), "provider-config.yaml")
	t.Cleanup(func() {
		sources.DefaultProviderConfigLocation = origConfig
	})
	for _, env := range []string{
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
	} {
		t.Setenv(env, "")
	}
}
