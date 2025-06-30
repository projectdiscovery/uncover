package runner

import (
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru"
	"github.com/projectdiscovery/uncover/sources"
)

type OutputWriter struct {
	cache   *lru.Cache
	writers []io.Writer
	sync.RWMutex
	headerWritten bool
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


// WriteCSVData writes the result taken as input in CSV format
func (o *OutputWriter) WriteCSVData(data sources.Result) {
    key := fmt.Sprintf("%s:%d", data.IP, data.Port)
    if o.findDuplicate(key, true) {
        return
    }

    // 写入表头（仅第一次）
    if !o.headerWritten {
        o.writeCSVHeader()
        o.headerWritten = true
    }

    // 构造 CSV 数据行
    var b strings.Builder
    _, err := fmt.Fprintf(&b,
        "%d,%s,%s,%d,%s,%s,%s,%s,%s,%s,%v,%s,%s,%s,%s,%s,%s,%d,%v,%s,%s,%s,%s,%s\n",
        data.Timestamp,
        data.Source,
        data.IP,
        data.Port,
        data.Host,
        data.Url,
        data.HtmlTitle,
        data.Domain,
        data.Province,
        data.City,
        data.Country,
        data.Asn,
        data.Location,
        data.ServiceProvider,
        data.Fingerprints,
        data.Banner,
        data.ServiceName,
        data.StatusCode,
        data.Honeypot,
        data.FaviconHash,
        data.Server,
        data.Org,
        data.ISP,
        data.ICPUnit,
        // data.DNSResp.String(),
    )
    if err != nil {
        return
    }

    o.Lock()
    defer o.Unlock()

    for _, w := range o.writers {
        _, _ = w.Write([]byte(b.String()))
    }
}

// writeCSVHeader writes the header row once
func (o *OutputWriter) writeCSVHeader() {
    o.Lock()
    defer o.Unlock()

    header := "Timestamp,Source,IP,Port,Host,Url,HtmlTitle,Domain,Province,City,Country,Asn,Location,ServiceProvider,Fingerprints,Banner,ServiceName,StatusCode,Honeypot,Server,Org,ISP,ICPUnit\n"

    for _, w := range o.writers {
        _, _ = w.Write([]byte(header))
    }
}

// Close closes the output writers
func (o *OutputWriter) Close() {
	// Iterate over the writers and close the file writers
	for _, writer := range o.writers {
		if fileWriter, ok := writer.(*os.File); ok {
			fileWriter.Close()
		}
	}
}
