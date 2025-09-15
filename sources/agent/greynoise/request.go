package greynoise

type Request struct {
	Query      string // GNQL query string (required)
	Size       int    // Number of results per page (1-10000, defaults to 10000)
	Scroll     string // Scroll token for pagination
	ExcludeRaw bool   // Optional: request without heavy raw_data
}
