package quake

import "time"

type responseData struct {
	Components []struct {
		ProductLevel   string   `json:"product_level"`
		ProductType    []string `json:"product_type"`
		ProductVendor  string   `json:"product_vendor"`
		ProductNameCn  string   `json:"product_name_cn"`
		ProductNameEn  string   `json:"product_name_en"`
		Id             string   `json:"id"`
		ProductCatalog []string `json:"product_catalog"`
		Version        string   `json:"version"`
	} `json:"components,omitempty"`
	Images []struct {
		Data   string   `json:"data"`
		Mime   string   `json:"mime"`
		Width  int      `json:"width"`
		Height int      `json:"height"`
		Md5    string   `json:"md5"`
		Tags   []string `json:"tags,omitempty"`
		S3Url  string   `json:"s3_url"`
	} `json:"images,omitempty"`
	Org       string `json:"org"`
	Ip        string `json:"ip"`
	IsIpv6    bool   `json:"is_ipv6"`
	Transport string `json:"transport"`
	Hostname  string `json:"hostname"`
	Port      int    `json:"port"`
	Service   struct {
		TlsJarm struct {
			JarmHash string   `json:"jarm_hash"`
			JarmAns  []string `json:"jarm_ans"`
		} `json:"tls-jarm,omitempty"`
		ResponseHash string `json:"response_hash"`
		Dns          struct {
			A           []string `json:"a"`
			Cname       []string `json:"cname"`
			AAAA        []string `json:"aaaa"`
			SupportIpv6 bool     `json:"support_ipv6"`
		} `json:"dns,omitempty"`
		Name     string `json:"name"`
		Response string `json:"response"`
		Http     struct {
			XPoweredBy string `json:"x_powered_by"`
			DomTree    struct {
				DomHash string `json:"dom_hash"`
				Simhash string `json:"simhash"`
			} `json:"dom_tree"`
			HeaderOrderHash string   `json:"header_order_hash"`
			Server          string   `json:"server"`
			StatusCode      int      `json:"status_code"`
			RobotsHash      string   `json:"robots_hash"`
			HttpLoadUrl     []string `json:"http_load_url"`
			PageType        []string `json:"page_type"`
			CookieElement   struct {
				OrderHash string `json:"order_hash"`
				Simhash   string `json:"simhash"`
			} `json:"cookie_element"`
			Favicon struct {
				Data     string `json:"data"`
				Location string `json:"location"`
				Hash     string `json:"hash"`
				S3Url    string `json:"s3_url"`
			} `json:"favicon"`
			Link struct {
				Img []struct {
					IsInner bool   `json:"is_inner"`
					Url     string `json:"url"`
					Md5     string `json:"md5,omitempty"`
				} `json:"img,omitempty"`
				Other []struct {
					IsInner bool   `json:"is_inner"`
					Url     string `json:"url"`
					Md5     string `json:"md5,omitempty"`
				} `json:"other,omitempty"`
				Script []struct {
					IsInner bool   `json:"is_inner"`
					Url     string `json:"url"`
					Md5     string `json:"md5,omitempty"`
				} `json:"script,omitempty"`
				Iframe []struct {
					Url string `json:"url"`
					Md5 string `json:"md5"`
				} `json:"iframe,omitempty"`
			} `json:"link,omitempty"`
			HttpLoadCount   int           `json:"http_load_count"`
			MetaKeywords    string        `json:"meta_keywords"`
			Title           string        `json:"title"`
			DataSources     int           `json:"data_sources"`
			PageTypeKeyword []interface{} `json:"page_type_keyword"`
			SitemapHash     string        `json:"sitemap_hash"`
			Path            string        `json:"path"`
			HtmlHash        string        `json:"html_hash"`
			ResponseHeaders string        `json:"response_headers"`
			Icp             struct {
				Licence     string    `json:"licence"`
				UpdateTime  time.Time `json:"update_time"`
				IsExpired   bool      `json:"is_expired"`
				LeaderName  string    `json:"leader_name"`
				Domain      string    `json:"domain"`
				MainLicence struct {
					Licence string `json:"licence"`
					Unit    string `json:"unit"`
					Nature  string `json:"nature"`
				} `json:"main_licence"`
				ContentTypeName string `json:"content_type_name"`
				LimitAccess     bool   `json:"limit_access"`
			} `json:"icp,omitempty"`
			Host        string `json:"host"`
			Robots      string `json:"robots"`
			Sitemap     string `json:"sitemap"`
			Information struct {
				Mail []string `json:"mail"`
			} `json:"information,omitempty"`
		} `json:"http,omitempty"`
		Cert string `json:"cert,omitempty"`
		Tls  struct {
			CommonNameWildcard   bool   `json:"common_name_wildcard"`
			Ja3S                 string `json:"ja3s"`
			Ja4S                 string `json:"ja4s,omitempty"`
			TwoWayAuthentication bool   `json:"two_way_authentication"`
			HandshakeLog         struct {
				ClientHello struct {
					ServerName string `json:"server_name"`
					Version    struct {
						Name  string `json:"name"`
						Value int    `json:"value"`
					} `json:"version"`
				} `json:"client_hello"`
				ServerCertificates struct {
					Certificate struct {
						Raw    string `json:"raw"`
						Parsed struct {
							IssuerDn       string `json:"issuer_dn"`
							FingerprintMd5 string `json:"fingerprint_md5"`
							SubjectKeyInfo struct {
								KeyAlgorithm struct {
									Name string `json:"name"`
								} `json:"key_algorithm"`
								RsaPublicKey struct {
									Length   int    `json:"length"`
									Modulus  string `json:"modulus"`
									Exponent int    `json:"exponent"`
								} `json:"rsa_public_key"`
								FingerprintSha256 string `json:"fingerprint_sha256"`
							} `json:"subject_key_info"`
							Redacted  bool `json:"redacted"`
							Signature struct {
								Valid              bool `json:"valid"`
								SignatureAlgorithm struct {
									Name string `json:"name"`
									Oid  string `json:"oid"`
								} `json:"signature_algorithm"`
								SelfSigned bool   `json:"self_signed"`
								Value      string `json:"value"`
							} `json:"signature"`
							Subject struct {
								CommonName         []string `json:"common_name"`
								Country            []string `json:"country,omitempty"`
								EmailAddress       []string `json:"email_address,omitempty"`
								Province           []string `json:"province,omitempty"`
								Organization       []string `json:"organization,omitempty"`
								Locality           []string `json:"locality,omitempty"`
								OrganizationalUnit []string `json:"organizational_unit,omitempty"`
							} `json:"subject"`
							SerialNumber string `json:"serial_number"`
							Version      int    `json:"version"`
							Issuer       struct {
								CommonName         []string `json:"common_name"`
								Country            []string `json:"country,omitempty"`
								EmailAddress       []string `json:"email_address,omitempty"`
								Province           []string `json:"province,omitempty"`
								Organization       []string `json:"organization,omitempty"`
								Locality           []string `json:"locality,omitempty"`
								OrganizationalUnit []string `json:"organizational_unit,omitempty"`
							} `json:"issuer"`
							FingerprintSha256  string `json:"fingerprint_sha256"`
							TbsNoctFingerprint string `json:"tbs_noct_fingerprint"`
							Extensions         struct {
								KeyUsage struct {
									DigitalSignature  bool `json:"digital_signature"`
									ContentCommitment bool `json:"content_commitment,omitempty"`
									KeyEncipherment   bool `json:"key_encipherment"`
									Value             int  `json:"value"`
								} `json:"key_usage,omitempty"`
								SubjectAltName struct {
									DnsNames    []string `json:"dns_names"`
									IpAddresses []string `json:"ip_addresses,omitempty"`
								} `json:"subject_alt_name,omitempty"`
								BasicConstraints struct {
									IsCa bool `json:"is_ca"`
								} `json:"basic_constraints"`
								ExtendedKeyUsage struct {
									ClientAuth bool `json:"client_auth,omitempty"`
									ServerAuth bool `json:"server_auth"`
								} `json:"extended_key_usage,omitempty"`
								SubjectKeyId        string `json:"subject_key_id,omitempty"`
								AuthorityKeyId      string `json:"authority_key_id,omitempty"`
								CertificatePolicies []struct {
									Cps []string `json:"cps,omitempty"`
									Id  string   `json:"id"`
								} `json:"certificate_policies,omitempty"`
								SignedCertificateTimestamps []struct {
									LogId     string `json:"log_id"`
									Signature string `json:"signature"`
									Version   int    `json:"version"`
									Timestamp int    `json:"timestamp"`
								} `json:"signed_certificate_timestamps,omitempty"`
								AuthorityInfoAccess struct {
									IssuerUrls []string `json:"issuer_urls"`
									OcspUrls   []string `json:"ocsp_urls"`
								} `json:"authority_info_access,omitempty"`
							} `json:"extensions"`
							TbsFingerprint         string   `json:"tbs_fingerprint"`
							Names                  []string `json:"names,omitempty"`
							SubjectDn              string   `json:"subject_dn"`
							FingerprintSha1        string   `json:"fingerprint_sha1"`
							SpkiSubjectFingerprint string   `json:"spki_subject_fingerprint"`
							Validity               struct {
								Length int       `json:"length"`
								Start  time.Time `json:"start"`
								End    time.Time `json:"end"`
							} `json:"validity"`
							ValidationLevel   string `json:"validation_level"`
							UnknownExtensions []struct {
								Critical bool   `json:"critical"`
								Id       string `json:"id"`
								Value    string `json:"value"`
							} `json:"unknown_extensions,omitempty"`
						} `json:"parsed"`
					} `json:"certificate"`
					Validation struct {
						MatchesDomain  bool   `json:"matches_domain"`
						BrowserTrusted bool   `json:"browser_trusted"`
						BrowserError   string `json:"browser_error"`
					} `json:"validation"`
					Chain []struct {
						Raw    string `json:"raw"`
						Parsed struct {
							IssuerDn  string `json:"issuer_dn"`
							SubjectDn string `json:"subject_dn"`
							Signature struct {
								Valid      bool `json:"valid"`
								SelfSigned bool `json:"self_signed"`
							} `json:"signature"`
							FingerprintSha256 string `json:"fingerprint_sha256"`
						} `json:"parsed"`
					} `json:"chain,omitempty"`
				} `json:"server_certificates"`
				ServerHello struct {
					CipherSuite struct {
						Name  string `json:"name"`
						Hex   string `json:"hex"`
						Value int    `json:"value"`
					} `json:"cipher_suite"`
					SupportedVersions struct {
						SelectedVersion struct {
							Name  string `json:"name"`
							Value int    `json:"value"`
						} `json:"selected_version"`
					} `json:"supported_versions,omitempty"`
					Version struct {
						Name  string `json:"name"`
						Value int    `json:"value"`
					} `json:"version"`
					AlpnProtocol string `json:"alpn_protocol,omitempty"`
				} `json:"server_hello"`
				ServerKeyExchange struct {
					EcdhParams struct {
						ServerPublic struct {
							X struct {
								Length int `json:"length"`
							} `json:"x"`
							Y struct {
								Length int `json:"length"`
							} `json:"y"`
						} `json:"server_public"`
						CurveId struct {
							Name string `json:"name"`
							Id   int    `json:"id"`
						} `json:"curve_id"`
					} `json:"ecdh_params"`
				} `json:"server_key_exchange,omitempty"`
				CertificateRequest struct {
					SupportedSignatureAlgorithms []int `json:"supported_signature_algorithms"`
					SignatureAndHashes           []struct {
						HashAlgorithm      string `json:"hash_algorithm"`
						SignatureAlgorithm string `json:"signature_algorithm"`
					} `json:"signature_and_hashes"`
				} `json:"certificate_request,omitempty"`
			} `json:"handshake_log"`
			Version    []string `json:"version"`
			Validation struct {
				MatchesDomain  bool   `json:"matches_domain"`
				BrowserTrusted bool   `json:"browser_trusted"`
				BrowserError   string `json:"browser_error"`
			} `json:"validation"`
		} `json:"tls,omitempty"`
		Version string `json:"version"`
		Net     struct {
			ServiceProbeName string `json:"service_probe_name"`
			Tcp              struct {
				Window int `json:"window"`
			} `json:"tcp"`
			RouterIp string `json:"router_ip"`
			Ip       struct {
				Distance   int `json:"distance"`
				InitialTtl int `json:"initial_ttl"`
				Tos        int `json:"tos"`
				Ttl        int `json:"ttl"`
			} `json:"ip"`
			PortResponseTime int `json:"port_response_time"`
		} `json:"net,omitempty"`
	} `json:"service"`
	Domain   string `json:"domain,omitempty"`
	Location struct {
		Owner       string    `json:"owner"`
		ProvinceCn  string    `json:"province_cn"`
		Isp         string    `json:"isp"`
		ProvinceEn  string    `json:"province_en"`
		CountryEn   string    `json:"country_en"`
		DistrictCn  string    `json:"district_cn"`
		Gps         []float64 `json:"gps"`
		StreetCn    string    `json:"street_cn"`
		CityEn      string    `json:"city_en"`
		DistrictEn  string    `json:"district_en"`
		CountryCn   string    `json:"country_cn"`
		StreetEn    string    `json:"street_en"`
		CityCn      string    `json:"city_cn"`
		CountryCode string    `json:"country_code"`
		Asname      string    `json:"asname"`
		SceneCn     string    `json:"scene_cn"`
		SceneEn     string    `json:"scene_en"`
		Radius      float64   `json:"radius"`
	} `json:"location"`
	Time   time.Time `json:"time"`
	Asn    int       `json:"asn"`
	Id     string    `json:"id"`
	OsName string    `json:"os_name,omitempty"`
}

type pagination struct {
	Count     int `json:"count"`
	PageIndex int `json:"page_index"`
	PageSize  int `json:"page_size"`
	Total     int `json:"total"`
}

type meta struct {
	Pagination pagination `json:"pagination"`
}

type Response struct {
	Data    []responseData `json:"data"`
	Message string         `json:"message"`
	Meta    meta           `json:"meta"`
}
