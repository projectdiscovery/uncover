package runner

import (
	"bytes"
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
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

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

func TestOutputWriter_WriteCSVData(t *testing.T) {
	writer, err := NewOutputWriter()
	if err != nil {
		t.Fatalf("Failed to create OutputWriter: %s", err)
	}

	var buf bytes.Buffer
	writer.AddWriters(&buf)

	fields := []string{"ip", "port", "host"}
	writer.WriteCSVRow(fields)

	// Host contains a comma and quotes to exercise RFC-4180 escaping.
	result := sources.Result{
		IP:   "192.168.1.1",
		Port: 80,
		Host: `local,"host"`,
	}

	writer.WriteCSVData(result, fields)
	// A second identical write must be suppressed as a duplicate.
	writer.WriteCSVData(result, fields)

	expected := "ip,port,host\n192.168.1.1,80,\"local,\"\"host\"\"\"\n"
	if got := buf.String(); got != expected {
		t.Fatalf("unexpected CSV output:\n got: %q\nwant: %q", got, expected)
	}
}

func TestOutputWriter_WriteCSVData_DistinctProjections(t *testing.T) {
	writer, err := NewOutputWriter()
	if err != nil {
		t.Fatalf("Failed to create OutputWriter: %s", err)
	}

	var buf bytes.Buffer
	writer.AddWriters(&buf)

	// Same IP but different hosts must produce two rows when host is projected.
	writer.WriteCSVData(sources.Result{IP: "1.1.1.1", Port: 80, Host: "a.example.com"}, []string{"ip", "port", "host"})
	writer.WriteCSVData(sources.Result{IP: "1.1.1.1", Port: 80, Host: "b.example.com"}, []string{"ip", "port", "host"})

	expected := "1.1.1.1,80,a.example.com\n1.1.1.1,80,b.example.com\n"
	if got := buf.String(); got != expected {
		t.Fatalf("distinct rows were incorrectly deduplicated:\n got: %q\nwant: %q", got, expected)
	}
}

func TestGetFieldValues(t *testing.T) {
	result := sources.Result{IP: "1.1.1.1", Port: 443, Host: "example.com", Url: "https://example.com"}
	got := getFieldValues(result, []string{"IP", "port", "host", "url", "unknown"})
	want := []string{"1.1.1.1", "443", "example.com", "https://example.com", ""}

	if len(got) != len(want) {
		t.Fatalf("expected %d values, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d: expected %q, got %q", i, want[i], got[i])
		}
	}
}

func TestParseFields(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"ip,port,host", []string{"ip", "port", "host"}},
		{"ip:port:host", []string{"ip", "port", "host"}},
		{"ip;port;host", []string{"ip", "port", "host"}},
		{"ip port host", []string{"ip", "port", "host"}},
		{"ip\tport\thost", []string{"ip", "port", "host"}},
		{"ip\nport\nhost", []string{"ip", "port", "host"}},
	}

	for _, tt := range tests {
		actual := parseFields(tt.input)
		if len(actual) != len(tt.expected) {
			t.Errorf("For %q expected length %d, got %d", tt.input, len(tt.expected), len(actual))
			continue
		}
		for i, v := range actual {
			if v != tt.expected[i] {
				t.Errorf("For %q expected index %d to be %q, got %q", tt.input, i, tt.expected[i], v)
			}
		}
	}
}
