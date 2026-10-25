package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func TestWriteJsonDataKeepsResultsWithoutIPAndPort(t *testing.T) {
	writer, err := NewOutputWriter()
	require.NoError(t, err)
	var buf bytes.Buffer
	writer.AddWriters(&buf)

	writer.WriteJsonData(sources.Result{Host: "a.example", Url: "https://a.example"})
	writer.WriteJsonData(sources.Result{Host: "b.example", Url: "https://b.example"})
	writer.WriteJsonData(sources.Result{Host: "a.example", Url: "https://a.example"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "a.example")
	require.Contains(t, lines[1], "b.example")
}

func TestWriteJsonDataStillDedupsIPAndPort(t *testing.T) {
	writer, err := NewOutputWriter()
	require.NoError(t, err)
	var buf bytes.Buffer
	writer.AddWriters(&buf)

	writer.WriteJsonData(sources.Result{IP: "1.2.3.4", Port: 443, Host: "a.example"})
	writer.WriteJsonData(sources.Result{IP: "1.2.3.4", Port: 443, Host: "b.example"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 1)
}

func TestWriteJsonDataDoesNotCollapsePartialIPOrPort(t *testing.T) {
	writer, err := NewOutputWriter()
	require.NoError(t, err)
	var buf bytes.Buffer
	writer.AddWriters(&buf)

	writer.WriteJsonData(sources.Result{IP: "1.2.3.4", Host: "a.example"})
	writer.WriteJsonData(sources.Result{IP: "1.2.3.4", Host: "b.example"})
	writer.WriteJsonData(sources.Result{Port: 443, Url: "https://a.example"})
	writer.WriteJsonData(sources.Result{Port: 443, Url: "https://b.example"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 4)
}
