package runner

import (
	"bytes"
	"crypto/sha1"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unicode"

	lru "github.com/hashicorp/golang-lru"
	"github.com/projectdiscovery/uncover/sources"
)

type OutputWriter struct {
	cache   *lru.Cache
	writers []io.Writer
	sync.RWMutex
}

func NewOutputWriter() (*OutputWriter, error) {
	lastPrintedCache, err := lru.New(2048)
	if err != nil {
		return nil, err
	}
	return &OutputWriter{cache: lastPrintedCache}, nil
}

func (o *OutputWriter) AddWriters(writers ...io.Writer) {
	o.writers = append(o.writers, writers...)
}

// Write writes the data taken as input using only
// the writer(s) with that name.
func (o *OutputWriter) Write(data []byte) {
	o.Lock()
	defer o.Unlock()

	for _, w := range o.writers {
		_, _ = w.Write(data)
		_, _ = w.Write([]byte("\n"))
	}
}

func (o *OutputWriter) findDuplicate(data string, markAsSeen bool) bool {
	// check if we've already printed this data
	itemHash := sha1.Sum([]byte(data))
	if o.cache.Contains(itemHash) {
		return true
	}
	if markAsSeen {
		o.cache.Add(itemHash, struct{}{})
	}
	return false
}

// WriteString writes the string taken as input using only
func (o *OutputWriter) WriteString(data string) {
	if o.findDuplicate(data, true) {
		return
	}
	o.Write([]byte(data))
}

// WriteJsonData writes the result taken as input in JSON format
func (o *OutputWriter) WriteJsonData(data sources.Result) {
	if o.findDuplicate(fmt.Sprintf("%s:%d", data.IP, data.Port), true) {
		return
	}
	o.Write([]byte(data.JSON()))
}

func (o *OutputWriter) WriteCSVRow(row []string) {
	o.Lock()
	defer o.Unlock()

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(row); err != nil {
		return
	}
	w.Flush()

	for _, writer := range o.writers {
		_, _ = writer.Write(buf.Bytes())
	}
}

func (o *OutputWriter) WriteCSVData(data sources.Result, fields []string) {
	values := getFieldValues(data, fields)
	dupKey := strings.Join(values, ",")
	if o.findDuplicate(dupKey, true) {
		return
	}
	o.WriteCSVRow(values)
}

func parseFields(fields string) []string {
	var parsed []string
	for _, f := range strings.FieldsFunc(fields, func(r rune) bool {
		return r == ',' || r == ':' || r == ';' || unicode.IsSpace(r)
	}) {
		f = strings.TrimSpace(f)
		if f != "" {
			parsed = append(parsed, f)
		}
	}
	return parsed
}

func getFieldValues(result sources.Result, fields []string) []string {
	values := make([]string, len(fields))
	for i, f := range fields {
		switch strings.ToLower(f) {
		case "ip":
			values[i] = result.IP
		case "port":
			values[i] = fmt.Sprint(result.Port)
		case "host":
			values[i] = result.Host
		case "url":
			values[i] = result.Url
		default:
			values[i] = ""
		}
	}
	return values
}

// Close closes the output writers
func (o *OutputWriter) Close() {
	// Iterate over the writers and close the file writers
	for _, writer := range o.writers {
		if fileWriter, ok := writer.(*os.File); ok {
			_ = fileWriter.Close()
		}
	}
}
