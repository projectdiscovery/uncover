package sources
import (
	"encoding/json"
	"fmt"
	"net"
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
	Error     error  `json:"-"`
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

func (result *Result) Error() error {
	return result.error
}
