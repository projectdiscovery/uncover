package sources

import (
	"encoding/json"
	"fmt"
	"net"
)

type DNSResp struct {
	Cname []string `json:"cname"`
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
}
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
	//0614
	FaviconURL      string  `json:"favicon_url"`
	FaviconHash     string  `json:"favicon_hash"`
	ResponseHeaders string  `json:"response_headers"`
	Server          string  `json:"server"`
	Org             string  `json:"org"`
	ISP             string  `json:"isp"`
	ImageURL        string  `json:"image_url"`
	ICPLicence      string  `json:"icp_licence"` // ICP 备案号
	ICPUnit         string  `json:"icp_unit"`    // ICP 备案单位
	DNSResp         DNSResp `json:"dns_resp"`    // DNS 解析结果
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
