package zoomeye

type ZoomEyeResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Total   int    `json:"total"`
	Query   string `json:"query"`
	Data    []struct {
		Url                 string   `json:"url"`
		SslJarm             string   `json:"ssl.jarm"`
		SslJa3S             string   `json:"ssl.ja3s"`
		IconhashMd5         string   `json:"iconhash_md5"`
		RobotsMd5           string   `json:"robots_md5"`
		SecurityMd5         string   `json:"security_md5"`
		Ip                  string   `json:"ip"`
		Domain              string   `json:"domain"`
		Hostname            string   `json:"hostname"`
		Os                  string   `json:"os"`
		Port                int      `json:"port"`
		Service             string   `json:"service"`
		Title               []string `json:"title"`
		Version             string   `json:"version"`
		Device              string   `json:"device"`
		Rdns                string   `json:"rdns"`
		Product             string   `json:"product"`
		Header              string   `json:"header"`
		HeaderHash          string   `json:"header_hash"`
		Body                string   `json:"body"`
		BodyHash            string   `json:"body_hash"`
		Banner              string   `json:"banner"`
		UpdateTime          string   `json:"update_time"`
		HeaderServerName    string   `json:"header.server.name"`
		HeaderServerVersion string   `json:"header.server.version"`
		ContinentName       string   `json:"continent.name"`
		CountryName         string   `json:"country.name"`
		ProvinceName        string   `json:"province.name"`
		CityName            string   `json:"city.name"`
		Lon                 string   `json:"lon"`
		Lat                 string   `json:"lat"`
		IspName             string   `json:"isp.name"`
		OrganizationName    string   `json:"organization.name"`
		Zipcode             string   `json:"zipcode"`
		Idc                 int      `json:"idc"`
		Honeypot            int      `json:"honeypot"`
		Asn                 string   `json:"asn"`
		Protocol            string   `json:"protocol"`
		Ssl                 string   `json:"ssl"`
		PrimaryIndustry     string   `json:"primary_industry"`
		SubIndustry         string   `json:"sub_industry"`
		Rank                int      `json:"rank"`
	} `json:"data"`
}
