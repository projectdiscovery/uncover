package netlas

import "time"

type Response struct {
	Items     []Items `json:"items,omitempty"`
	Took      int     `json:"took,omitempty"`
	Timestamp int     `json:"timestamp,omitempty"`
}

type Items struct {
	Data Data `json:"data,omitempty"`
}

type Data struct {
	Referer     []string    `json:"referer,omitempty"`
	LastUpdated time.Time   `json:"last_updated,omitempty"`
	Isp         string      `json:"isp,omitempty"`
	IP          string      `json:"ip,omitempty"`
	Certificate Certificate `json:"certificate,omitempty"`
	URI         string      `json:"uri,omitempty"`
	HostType    string      `json:"host_type,omitempty"`
	Target      Target      `json:"target,omitempty"`
	Prot7       string      `json:"prot7,omitempty"`
	Ptr         []string    `json:"ptr,omitempty"`
	Geo         Geo         `json:"geo,omitempty"`
	Path        string      `json:"path,omitempty"`
	Protocol    string      `json:"protocol,omitempty"`
	Prot4       string      `json:"prot4,omitempty"`
	Timestamp   time.Time   `json:"@timestamp,omitempty"`
	Whois       Whois       `json:"whois,omitempty"`
	Port        int         `json:"port,omitempty"`
	Domain      []string    `json:"domain,omitempty"`
	Host        string      `json:"host,omitempty"`
	Iteration   string      `json:"iteration,omitempty"`
	HTTP        HTTP        `json:"http,omitempty"`
	ScanDate    string      `json:"scan_date,omitempty"`
}

type SignatureAlgorithm struct {
	Name string `json:"name,omitempty"`
	Oid  string `json:"oid,omitempty"`
}

type Signature struct {
	Valid              bool               `json:"valid,omitempty"`
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm,omitempty"`
	Value              string             `json:"value,omitempty"`
	SelfSigned         bool               `json:"self_signed,omitempty"`
}

type Subject struct {
	Country      []string `json:"country,omitempty"`
	Organization []string `json:"organization,omitempty"`
	CommonName   []string `json:"common_name,omitempty"`
}

type CertificatePolicies struct {
	Cps []string `json:"cps,omitempty"`
	ID  string   `json:"id,omitempty"`
}

type KeyUsage struct {
	DigitalSignature bool `json:"digital_signature,omitempty"`
	CertificateSign  bool `json:"certificate_sign,omitempty"`
	CrlSign          bool `json:"crl_sign,omitempty"`
	Value            int  `json:"value,omitempty"`
}

type AuthorityInfoAccess struct {
	IssuerUrls []string `json:"issuer_urls,omitempty"`
	OcspUrls   []string `json:"ocsp_urls,omitempty"`
}

type BasicConstraints struct {
	MaxPathLen int  `json:"max_path_len,omitempty"`
	IsCa       bool `json:"is_ca,omitempty"`
}

type ExtendedKeyUsage struct {
	ClientAuth bool `json:"client_auth,omitempty"`
	ServerAuth bool `json:"server_auth,omitempty"`
}

type Validity struct {
	Start  time.Time `json:"start,omitempty"`
	Length int       `json:"length,omitempty"`
	End    time.Time `json:"end,omitempty"`
}

type Issuer struct {
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	CommonName         []string `json:"common_name,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
}

type Chain struct {
	IssuerDn               string             `json:"issuer_dn,omitempty"`
	FingerprintMd5         string             `json:"fingerprint_md5,omitempty"`
	Signature              Signature          `json:"signature,omitempty"`
	Redacted               bool               `json:"redacted,omitempty"`
	Subject                Subject            `json:"subject,omitempty"`
	SerialNumber           string             `json:"serial_number,omitempty"`
	Version                int                `json:"version,omitempty"`
	Issuer                 Issuer             `json:"issuer,omitempty"`
	FingerprintSha256      string             `json:"fingerprint_sha256,omitempty"`
	TbsNoctFingerprint     string             `json:"tbs_noct_fingerprint,omitempty"`
	Extensions             Extensions         `json:"extensions,omitempty"`
	TbsFingerprint         string             `json:"tbs_fingerprint,omitempty"`
	SubjectDn              string             `json:"subject_dn,omitempty"`
	FingerprintSha1        string             `json:"fingerprint_sha1,omitempty"`
	SignatureAlgorithm     SignatureAlgorithm `json:"signature_algorithm,omitempty"`
	SpkiSubjectFingerprint string             `json:"spki_subject_fingerprint,omitempty"`
	Validity               Validity           `json:"validity,omitempty"`
	ValidationLevel        string             `json:"validation_level,omitempty"`
}

type SubjectAltName struct {
	DNSNames []string `json:"dns_names,omitempty"`
}

type SignedCertificateTimestamps struct {
	LogID     string `json:"log_id,omitempty"`
	Signature string `json:"signature,omitempty"`
	Version   int    `json:"version,omitempty"`
	Timestamp int    `json:"timestamp,omitempty"`
}

type Extensions struct {
	SubjectKeyID                string                        `json:"subject_key_id,omitempty"`
	CrlDistributionPoints       []string                      `json:"crl_distribution_points,omitempty"`
	CertificatePolicies         []CertificatePolicies         `json:"certificate_policies,omitempty"`
	AuthorityKeyID              string                        `json:"authority_key_id,omitempty"`
	KeyUsage                    KeyUsage                      `json:"key_usage,omitempty"`
	SubjectAltName              SubjectAltName                `json:"subject_alt_name,omitempty"`
	SignedCertificateTimestamps []SignedCertificateTimestamps `json:"signed_certificate_timestamps,omitempty"`
	AuthorityInfoAccess         AuthorityInfoAccess           `json:"authority_info_access,omitempty"`
	BasicConstraints            BasicConstraints              `json:"basic_constraints,omitempty"`
	ExtendedKeyUsage            ExtendedKeyUsage              `json:"extended_key_usage,omitempty"`
}

type Certificate struct {
	IssuerDn               string             `json:"issuer_dn,omitempty"`
	FingerprintMd5         string             `json:"fingerprint_md5,omitempty"`
	Chain                  []Chain            `json:"chain,omitempty"`
	Src                    string             `json:"src,omitempty"`
	Signature              Signature          `json:"signature,omitempty"`
	Redacted               bool               `json:"redacted,omitempty"`
	Subject                Subject            `json:"subject,omitempty"`
	SerialNumber           string             `json:"serial_number,omitempty"`
	Version                int                `json:"version,omitempty"`
	Issuer                 Issuer             `json:"issuer,omitempty"`
	FingerprintSha256      string             `json:"fingerprint_sha256,omitempty"`
	TbsNoctFingerprint     string             `json:"tbs_noct_fingerprint,omitempty"`
	Extensions             Extensions         `json:"extensions,omitempty"`
	TbsFingerprint         string             `json:"tbs_fingerprint,omitempty"`
	SubjectDn              string             `json:"subject_dn,omitempty"`
	Names                  []string           `json:"names,omitempty"`
	FingerprintSha1        string             `json:"fingerprint_sha1,omitempty"`
	SignatureAlgorithm     SignatureAlgorithm `json:"signature_algorithm,omitempty"`
	SpkiSubjectFingerprint string             `json:"spki_subject_fingerprint,omitempty"`
	Validity               Validity           `json:"validity,omitempty"`
	ValidationLevel        string             `json:"validation_level,omitempty"`
}

type Target struct {
	Domain string `json:"domain,omitempty"`
	Type   string `json:"type,omitempty"`
}

type Location struct {
	Accuracy int     `json:"accuracy,omitempty"`
	Lat      float64 `json:"lat,omitempty"`
	Long     float64 `json:"long,omitempty"`
}

type Geo struct {
	Continent string   `json:"continent,omitempty"`
	Country   string   `json:"country,omitempty"`
	Tz        string   `json:"tz,omitempty"`
	Location  Location `json:"location,omitempty"`
}

type Net struct {
	Country      string   `json:"country,omitempty"`
	Address      string   `json:"address,omitempty"`
	City         string   `json:"city,omitempty"`
	Created      string   `json:"created,omitempty"`
	Range        string   `json:"range,omitempty"`
	Description  string   `json:"description,omitempty"`
	Handle       string   `json:"handle,omitempty"`
	Organization string   `json:"organization,omitempty"`
	StartIP      string   `json:"start_ip,omitempty"`
	Name         string   `json:"name,omitempty"`
	Cidr         []string `json:"cidr,omitempty"`
	NetSize      int      `json:"net_size,omitempty"`
	State        string   `json:"state,omitempty"`
	PostalCode   string   `json:"postal_code,omitempty"`
	Updated      string   `json:"updated,omitempty"`
	EndIP        string   `json:"end_ip,omitempty"`
}

type Asn struct {
	Number   []string `json:"number,omitempty"`
	Country  string   `json:"country,omitempty"`
	Registry string   `json:"registry,omitempty"`
	Name     string   `json:"name,omitempty"`
	Cidr     string   `json:"cidr,omitempty"`
	Updated  string   `json:"updated,omitempty"`
}

type Whois struct {
	RelatedNets []interface{} `json:"related_nets,omitempty"`
	Net         Net           `json:"net,omitempty"`
	Asn         Asn           `json:"asn,omitempty"`
}

type Headers struct {
	Date                    []string `json:"date,omitempty"`
	Server                  []string `json:"server,omitempty"`
	PermissionsPolicy       []string `json:"permissions_policy,omitempty"`
	ContentSecurityPolicy   []string `json:"content_security_policy,omitempty"`
	StrictTransportSecurity []string `json:"strict_transport_security,omitempty"`
	P3P                     []string `json:"p3p,omitempty"`
	XContentTypeOptions     []string `json:"x_content_type_options,omitempty"`
	SetCookie               []string `json:"set_cookie,omitempty"`
	ContentType             []string `json:"content_type,omitempty"`
	XRobotsTag              []string `json:"x_robots_tag,omitempty"`
	ReportTo                []string `json:"report_to,omitempty"`
	AcceptCh                []string `json:"accept_ch,omitempty"`
	Location                []string `json:"location,omitempty"`
	XXSSProtection          []string `json:"x_xss_protection,omitempty"`
	AltSvc                  []string `json:"alt_svc,omitempty"`
	ContentLength           []string `json:"content_length,omitempty"`
	XFrameOptions           []string `json:"x_frame_options,omitempty"`
}

type UnknownHeaders struct {
	Value []string `json:"value,omitempty"`
	Key   string   `json:"key,omitempty"`
}

type HTTPVersion struct {
	Minor int    `json:"minor,omitempty"`
	Major int    `json:"major,omitempty"`
	Name  string `json:"name,omitempty"`
}

type HTTP struct {
	Headers        Headers          `json:"headers,omitempty"`
	StatusCode     int              `json:"status_code,omitempty"`
	UnknownHeaders []UnknownHeaders `json:"unknown_headers,omitempty"`
	HTTPVersion    HTTPVersion      `json:"http_version,omitempty"`
	StatusLine     string           `json:"status_line,omitempty"`
}
