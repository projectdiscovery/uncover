package sources

import (
	"encoding/json"
	"net"
	"fmt"
	"strconv"
)

type Result struct {
	Timestamp int64  `json:"timestamp"`
	Source    string `json:"source"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Host      string `json:"host"`
	Url       string `json:"url"`
	Raw       []byte `json:"-"`
	Err     error  `json:"-"`
}

func (result *Result) IpPort() string {
    return net.JoinHostPort(result.IP, strconv.Itoa(result.Port))
}

func (result *Result) HostPort() string {
    return net.JoinHostPort(result.Host, strconv.Itoa(result.Port))
}

func (result *Result) RawData() string {
    return string(result.Raw)
}

func (result *Result) JSON() (string, error) {
    data, err := json.Marshal(result)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// Could also be removed
func (result *Result) Error() string {
    if result.Err == nil {
        return result.Err.Error()
    }
    return ""
}
