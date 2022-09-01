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

func (o *OutputWriter) Write(data []byte) {
	o.Lock()
	defer o.Unlock()

	for _, writer := range o.writers {
		_, _ = writer.Write(data)
		_, _ = writer.Write([]byte("\n"))
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

func (o *OutputWriter) WriteString(data string) {
	if o.findDuplicate(data) {
		return
	}
	o.Write([]byte(data))
}
func (o *OutputWriter) WriteJsonData(data uncover.Result) {
	if o.findDuplicate(fmt.Sprintf("%s:%d", data.IP, data.Port)) {
		return
	}
	o.Write([]byte(data.JSON()))
}
