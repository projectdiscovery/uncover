package runner

import (
	"bytes"
	"strings"
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

	result := sources.Result{
		IP:   "192.168.1.1",
		Port: 80,
		Host: "localhost",
	}

	writer.WriteCSVData(result, fields)

	output := buf.String()
	expectedHeader := "ip,port,host\n"
	expectedRow := "192.168.1.1,80,localhost\n"

	if !strings.Contains(output, expectedHeader) {
		t.Errorf("Expected output to contain header %q, got %q", expectedHeader, output)
	}
	if !strings.Contains(output, expectedRow) {
		t.Errorf("Expected output to contain row %q, got %q", expectedRow, output)
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
