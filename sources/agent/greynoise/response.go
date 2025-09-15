package greynoise

// Response represents the GNQL API response
type Response struct {
	RequestMetadata RequestMetadata `json:"request_metadata"`
	Data            []GNQLItem      `json:"data"`
}

// RequestMetadata contains pagination and query information
type RequestMetadata struct {
	Complete         bool       `json:"complete"`
	Scroll           string     `json:"scroll"`
	Query            string     `json:"query"`
	AdjustedQuery    string     `json:"adjusted_query"`
	Count            int        `json:"count"`
	Message          string     `json:"message"`
	RestrictedFields [][]string `json:"restricted_fields"`
}

// GNQLItem represents a single search result
type GNQLItem struct {
	IP                          string                      `json:"ip"`
	InternetScannerIntelligence InternetScannerIntelligence `json:"internet_scanner_intelligence"`
	BusinessServiceIntelligence BusinessServiceIntelligence `json:"business_service_intelligence"`
}

// InternetScannerIntelligence describes technical intelligence about the IP
type InternetScannerIntelligence struct {
	IP             string   `json:"ip"`
	Seen           bool     `json:"seen"`
	Classification string   `json:"classification"`
	FirstSeen      string   `json:"first_seen"`
	LastSeen       string   `json:"last_seen"`
	LastSeenTS     string   `json:"last_seen_timestamp"`
	Found          bool     `json:"found"`
	Actor          string   `json:"actor"`
	Bot            bool     `json:"bot"`
	Spoofable      bool     `json:"spoofable"`
	CVEs           []string `json:"cves"`
	Tor            bool     `json:"tor"`
	VPN            bool     `json:"vpn"`
	VPNService     string   `json:"vpn_service"`

	Metadata Metadata `json:"metadata"`
	Tags     []Tag    `json:"tags"`
	RawData  RawData  `json:"raw_data"`
}

// Metadata contains host/network info
type Metadata struct {
	Mobile                  bool     `json:"mobile"`
	SourceCountry           string   `json:"source_country"`
	SourceCountryCode       string   `json:"source_country_code"`
	SourceCity              string   `json:"source_city"`
	Region                  string   `json:"region"`
	Organization            string   `json:"organization"`
	RDNS                    string   `json:"rdns"`
	ASN                     string   `json:"asn"`
	Category                string   `json:"category"`
	OS                      string   `json:"os"`
	DestinationCountries    []string `json:"destination_countries"`
	DestinationCountryCodes []string `json:"destination_country_codes"`
	DestinationCities       []string `json:"destination_cities"`
	DestinationASNs         []string `json:"destination_asns"`
	SingleDestination       bool     `json:"single_destination"`
	Carrier                 string   `json:"carrier"`
	Datacenter              string   `json:"datacenter"`
	Domain                  string   `json:"domain"`
	RDNSParent              string   `json:"rdns_parent"`
	RDNSValidated           bool     `json:"rdns_validated"`
	Latitude                float64  `json:"latitude"`
	Longitude               float64  `json:"longitude"`
	SensorCount             int      `json:"sensor_count"`
	SensorHits              int      `json:"sensor_hits"`
}

// Tags describes malware/actor classification
type Tag struct {
	ID             string   `json:"id"`
	Slug           string   `json:"slug"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Intention      string   `json:"intention"`
	Description    string   `json:"description"`
	References     []string `json:"references"`
	RecommendBlock bool     `json:"recommend_block"`
	CVEs           []string `json:"cves"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

// RawData contains lower-level scanner output
type RawData struct {
	Scan []struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"scan"`

	JA3 []struct {
		Fingerprint string `json:"fingerprint"`
		Port        int    `json:"port"`
	} `json:"ja3"`

	HASSH []struct {
		Fingerprint string `json:"fingerprint"`
		Port        int    `json:"port"`
	} `json:"hassh"`

	HTTP struct {
		MD5            string   `json:"md5"`
		CookieKeys     []string `json:"cookie_keys"`
		RequestAuth    []string `json:"request_authorization"`
		RequestCookies []string `json:"request_cookies"`
		RequestHeader  []string `json:"request_header"`
		Method         []string `json:"method"`
		RequestOrigin  []string `json:"request_origin"`
		Host           []string `json:"host"`
		URI            []string `json:"uri"`
		Path           []string `json:"path"`
		UserAgent      []string `json:"useragent"`
	} `json:"http"`

	TLS struct {
		Cipher string   `json:"cipher"`
		JA4    []string `json:"ja4"`
	} `json:"tls"`

	SSH struct {
		Key []string `json:"key"`
	} `json:"ssh"`

	Source struct {
		Bytes int `json:"bytes"`
	} `json:"source"`
}

// BusinessServiceIntelligence describes business context
type BusinessServiceIntelligence struct {
	Found       bool   `json:"found"`
	Category    string `json:"category"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Explanation string `json:"explanation"`
	LastUpdated string `json:"last_updated"`
	Reference   string `json:"reference"`
	TrustLevel  string `json:"trust_level"`
}
