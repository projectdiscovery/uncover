package runner

import (
	"bytes"
	"testing"

	"github.com/projectdiscovery/uncover/sources"
)

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
