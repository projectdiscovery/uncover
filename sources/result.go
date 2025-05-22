package sources

import (
	"encoding/json"
	"fmt"
	"net"
)

type Result struct {
	Timestamp       int64  `json:"timestamp"`
	Source          string `json:"source"`
	IP              string `json:"ip"`
	Port            int    `json:"port"`
	Host            string `json:"host"`
	Url             string `json:"url"`
	Raw             []byte `json:"-"`
	Error           error  `json:"-"`
	HtmlTitle       string `json:"html_title"`
	Domain          string `json:"domain"`
	Province        string `json:"province"`
	ConfirmHttps    bool   `json:"confirm_https"`
	City            string `json:"city"`
	Country         string `json:"country"`
	Asn             string `json:"asn"`
	Location        string `json:"location"`
	ServiceProvider string `json:"service_provider"`
	Fingerprints    string `json:"fingerprints"`
	Banner          string `json:"banner"`
	ServiceName     string `json:"service_name"`
	StatusCode      int    `json:"status_code"`
	Honeypot        int    `json:"honeypot"`
}

func (result *Result) IpPort() string {
	return net.JoinHostPort(result.IP, fmt.Sprint(result.Port))
}

func (result *Result) HostPort() string {
	return net.JoinHostPort(result.Host, fmt.Sprint(result.Port))
}

func (result *Result) RawData() string {
	return string(result.Raw)
}

func (result *Result) JSON() string {
	data, _ := json.Marshal(result)
	return string(data)
}
