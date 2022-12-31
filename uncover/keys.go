package uncover

type Keys struct {
	CensysToken  string
	CensysSecret string
	Shodan       string
	FofaEmail    string
	FofaKey      string
	QuakeToken   string
	HunterToken  string
	ZoomEyeToken string
	NetlasToken  string
	CriminalIPToken string
}

func (keys Keys) Empty() bool {
	return keys.CensysSecret == "" &&
		keys.CensysToken == "" &&
		keys.Shodan == "" &&
		keys.FofaEmail == "" &&
		keys.FofaKey == "" &&
		keys.QuakeToken == "" &&
		keys.HunterToken == "" &&
		keys.ZoomEyeToken == "" &&
		keys.NetlasToken == "" &&
		keys.CriminalIPToken == ""
}
