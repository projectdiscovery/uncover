package runner

import (
	"crypto/sha1"
	"fmt"
	"io"
	"sync"

	lru "github.com/hashicorp/golang-lru"
	"github.com/projectdiscovery/uncover/uncover"
)

type OutputWriter struct {
	cache        *lru.Cache
	namedWriters []NamedWriter
	sync.RWMutex
}

type NamedWriter struct {
	Writer io.Writer
	Name   string
}

func NewOutputWriter() (*OutputWriter, error) {
	lastPrintedCache, err := lru.New(2048)
	if err != nil {
		return nil, err
	}
	return &OutputWriter{cache: lastPrintedCache}, nil
}

func (o *OutputWriter) AddWriters(named ...NamedWriter) {
	o.namedWriters = append(o.namedWriters, named...)
}

// WriteAll writes the data taken as input using
// all the writers.
func (o *OutputWriter) WriteAll(data []byte) {
	o.Lock()
	defer o.Unlock()

	for _, w := range o.namedWriters {
		w.Writer.Write(data)
		w.Writer.Write([]byte("\n"))
	}
}

// Write writes the data taken as input using only
// the writer(s) with that name.
func (o *OutputWriter) Write(data []byte, name string) {
	o.Lock()
	defer o.Unlock()

	for _, w := range o.namedWriters {
		if w.Name == name {
			w.Writer.Write(data)
			w.Writer.Write([]byte("\n"))
		}
	}
}

func (o *OutputWriter) findDuplicate(data string) bool {
	// check if we've already printed this data
	itemHash := sha1.Sum([]byte(data))
	if o.cache.Contains(itemHash) {
		return true
	}
	o.cache.Add(itemHash, struct{}{})
	return false
}

// WriteString writes the string taken as input using only
// the writer(s) with that name.
// If name is empty it writes using all the writers.
func (o *OutputWriter) WriteString(data string, name string) {
	if o.findDuplicate(data) {
		return
	}
	if name != "" {
		o.Write([]byte(data), name)
		return
	}
	o.WriteAll([]byte(data))
}

// WriteJsonData writes the result taken as input in JSON format
// using only the writer(s) with that name.
// If name is empty it writes using all the writers.
func (o *OutputWriter) WriteJsonData(data uncover.Result, name string) {
	if o.findDuplicate(fmt.Sprintf("%s:%d", data.IP, data.Port)) {
		return
	}
	if name != "" {
		o.Write([]byte(data.JSON()), name)
		return
	}
	o.WriteAll([]byte(data.JSON()))
}
