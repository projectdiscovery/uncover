package driftnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/uncover/sources"
	iputil "github.com/projectdiscovery/utils/ip"
)

const (
	// OpenPortIPPortsURL is the API endpoint used for an IP or CIDR lookup
	// from is the date to start the search, ip is an IP or CIDR
	// The endpoint reports upto 100 ports per IP address and 1,024 IP addresses per query
	OpenPortIPPortsURL = "https://api.driftnet.io/v1/scan/ipports?from=%s&ip=%s"

	// DomainsURL is an API endpoint used for non IP or CIDR lookups.
	// from is the date to start the search, the last %s in the string is for the query, it can be keyword= OR field= OR query=
	DomainsURL = "https://api.driftnet.io/v1/scan/domains?from=%s&most_recent=true&%s"

	// ProtocolURL is an API endpoint used for non IP or CIDR lookups.
	// from is the date to start the search, the last %s in the string is for the query, it can be keyword= OR field= OR query=
	ProtocolURL = "https://api.driftnet.io/v1/scan/protocols?from=%s&most_recent=true&%s"

	// We hard limit to 100 pages on the protocols endpoint (of 100 results per page)
	PageMaxLimit = 100
)

type DriftnetRequest struct {
	Query       string
	ResultLimit int
	From        string
	Page        int
}

type Agent struct{}

func (agent *Agent) Name() string {
	return "driftnet"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.DriftnetToken == "" {
		return nil, errors.New("empty driftnet keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		// Stable From time across all queries for this request
		queryTime := time.Now()

		// Past 30 Days (30 days was not chosen for a specific reason, just a recent range)
		queryTime = queryTime.AddDate(0, 0, -30)

		// Create the driftnet request processing the query
		driftnetRequest := &DriftnetRequest{Query: query.Query, From: queryTime.Format(time.DateOnly), ResultLimit: query.Limit}

		// query will handle either an IP/CIDR or a field/keyword query
		agent.query(session, driftnetRequest, results)
	}()

	return results, nil
}

// query selects which query logic to run depending on if we have an IP/CIDR or a query
func (agent *Agent) query(session *sources.Session, driftnetRequest *DriftnetRequest, results chan sources.Result) {
	if iputil.IsIP(driftnetRequest.Query) || iputil.IsCIDR(driftnetRequest.Query) {
		// Input is an IP or CIDR we will report open ports.
		agent.queryIPCIDR(session, driftnetRequest, results)
	} else {
		// Input is a term search (e.g. product search)
		agent.querySearchTerm(session, driftnetRequest, results)
	}
}

// querySearchTerm handles the general term searches.
func (agent *Agent) querySearchTerm(session *sources.Session, driftnetRequest *DriftnetRequest, results chan sources.Result) {
	// totalReportedResults keeps track of how many results we have found
	totalReportedResults := 0

	// We first try protocols endpoint, if we have no hits or less than user limit we can also try domains endpoint
ENDPOINT_LOOP:
	for _, apiEndpoint := range []string{ProtocolURL, DomainsURL} {
		// Paginate up to the API endpoint max page limit
		for currentPage := 0; currentPage < PageMaxLimit; currentPage++ {
			// Set the page
			driftnetRequest.Page = currentPage

			// Make the request
			resp, queryError := agent.queryURL(session, apiEndpoint, driftnetRequest)

			if queryError != nil {
				// Driftnet will return 204 if no results are found for a query
				if resp != nil && resp.StatusCode == http.StatusNoContent {
					// Try the next endpoint
					continue ENDPOINT_LOOP
				}

				// Some non 204 error
				results <- sources.Result{Source: agent.Name(), Error: queryError}
				return
			}
			defer resp.Body.Close()

			// Parse the response
			driftnetResponse := &DriftnetAPIPaginatedResponse{}
			if err := json.NewDecoder(resp.Body).Decode(driftnetResponse); err != nil {
				results <- sources.Result{Source: agent.Name(), Error: err}
				return
			}

			for _, result := range driftnetResponse.Results {
				// Find the IP, port and potentially a host
				var ip string
				var port string
				var host string
				for _, item := range result.Items {
					// The info we are after is in driftnet empty context items
					if item.Context == "" {
						// Do we have a port-tcp or port-udp?
						if strings.HasPrefix(item.Type, "port-") {
							port = item.Value
						}

						// Do we have an ip
						if item.Type == "ip" {
							ip = item.Value
						}

						// Do we have a hostname
						if item.Type == "host" {
							host = item.Value
						}
					}
				}

				// If we have an IP and Port we can report a hit, we might also have a host
				if len(port) > 0 && len(ip) > 0 {
					portAsInt, conversionError := strconv.Atoi(port)
					if conversionError != nil {
						results <- sources.Result{Source: agent.Name(), Error: conversionError}
						// Move onto the next driftnet result
						continue
					}

					result := sources.Result{Source: agent.Name(), IP: ip, Port: portAsInt}

					// Add the host if we have it
					if len(host) > 0 {
						result.Host = host
					}

					result.Raw, _ = json.Marshal(result)

					results <- result
					// If we reported a result we add this to the count
					totalReportedResults += 1
				}

				// Have we reached the number of results the user requested?
				if driftnetRequest.ResultLimit > 0 && totalReportedResults >= driftnetRequest.ResultLimit {
					return
				}
			}

			// Results less than full page size (100), no point making another query to this endpoint as it will be empty
			if len(driftnetResponse.Results) < 100 {
				// Try the next endpoint
				continue ENDPOINT_LOOP
			}
		}
	}
}

// queryIPCIDR handles searches for IP addresses or CIDRs
func (agent *Agent) queryIPCIDR(session *sources.Session, driftnetRequest *DriftnetRequest, results chan sources.Result) {
	var targetCIDR = driftnetRequest.Query

	// If target is just a IP turn it into a CIDR for ease
	if iputil.IsIP(targetCIDR) {
		if iputil.IsIPv4(targetCIDR) {
			targetCIDR = iputil.AsIPV4CIDR(targetCIDR)
		} else if iputil.IsIPv6(targetCIDR) {
			targetCIDR = iputil.AsIPV6CIDR(targetCIDR)
		}
	}

	// Split CIDR into /22s
	// The endpoint limits to 1,024 IP results per query,
	// hence if we have a CIDR > /22 we will split it and iterate over CIDRs
	requestCIDRs, splitError := mapcidr.SplitByNumber(targetCIDR, 1024)
	if splitError != nil {
		results <- sources.Result{Source: agent.Name(), Error: splitError}
		return
	}

	// Loop over the CIDRs
	// totalReportedResults keeps track of how many results we have found
	totalReportedResults := 0
	for _, requestCIDR := range requestCIDRs {
		// Set the current /22 as the query target
		driftnetRequest.Query = requestCIDR.String()

		// Make the request to driftnet
		resp, queryError := agent.queryURL(session, OpenPortIPPortsURL, driftnetRequest)

		if queryError != nil {
			// Driftnet will return 204 if no results are found for a query
			if resp != nil && resp.StatusCode == http.StatusNoContent {
				// We might have more CIDRs to search
				continue
			}

			results <- sources.Result{Source: agent.Name(), Error: queryError}
			return
		}
		defer resp.Body.Close()

		driftnetResponse := &DriftnetAPIOpenIPPortResponse{}
		if err := json.NewDecoder(resp.Body).Decode(driftnetResponse); err != nil {
			results <- sources.Result{Source: agent.Name(), Error: err}
			return
		}

		for ip, portsResponse := range driftnetResponse.Values {
			result := sources.Result{Source: agent.Name(), IP: ip}
			result.Raw, _ = json.Marshal(driftnetResponse)

			// Iterate over summarised ports and report as we go, the API limited to 100 ports per IP address.
			for port := range portsResponse.Values {
				result.Port = port
				results <- result

				// Add one to the count of reported items
				totalReportedResults += 1

				// Have we reached the number of results the user requested?
				if driftnetRequest.ResultLimit > 0 && totalReportedResults >= driftnetRequest.ResultLimit {
					return
				}
			}
		}
	}
}

// queryURL runs the actual HTTP request to the API
func (agent *Agent) queryURL(session *sources.Session, URL string, driftnetRequest *DriftnetRequest) (*http.Response, error) {
	apiURL := fmt.Sprintf(URL, url.QueryEscape(driftnetRequest.From), processQuery(driftnetRequest.Query))

	// Page 0 is the default we don't need to supply the page param for that
	if driftnetRequest.Page > 0 {
		pageStr := strconv.Itoa(driftnetRequest.Page)
		apiURL = apiURL + "&page=" + pageStr
	}

	//  Make the actual request with the users token as Bearer
	request, err := sources.NewHTTPRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", `Bearer `+session.Keys.DriftnetToken)
	return session.Do(request, agent.Name())
}

// processQuery processes the users input to match the expected API query param structure
func processQuery(input string) string {
	// We can handle IP or CIDR with no change
	if iputil.IsIP(input) || iputil.IsCIDR(input) {
		return url.QueryEscape(input)
	}

	// We have a query rather than an IP or CIDR
	// Input can be comma seperated. The driftnet API will AND keys (field, keyword, query) and OR filters
	// e.g. field=server-banner:nginx,filter=port-tcp:80,filter=port-tcp:8080 - find nginx on TCP port 80 OR 8080
	inputParts := strings.Split(input, ",")

	var outputQueryParams []string
	for _, inputPart := range inputParts {
		// Check for space variations
		parsedInputPart := strings.TrimSpace(inputPart)

		// Is it a field
		fieldQuery, isField := strings.CutPrefix(parsedInputPart, "field=")
		if isField {
			outputQueryParams = append(outputQueryParams, "field="+url.QueryEscape(fieldQuery))
			continue
		}

		// Is it a keyword
		keywordQuery, isKeyword := strings.CutPrefix(parsedInputPart, "keyword=")
		if isKeyword {
			outputQueryParams = append(outputQueryParams, "keyword="+url.QueryEscape(keywordQuery))
			continue
		}

		// Is it a filter
		filterQuery, isFilter := strings.CutPrefix(parsedInputPart, "filter=")
		if isFilter {
			outputQueryParams = append(outputQueryParams, "filter="+url.QueryEscape(filterQuery))
			continue
		}

		// If we got here we just treat as a generic query, which might have the query= prefix
		queryQuery, _ := strings.CutPrefix(parsedInputPart, "query=")
		outputQueryParams = append(outputQueryParams, "query="+url.QueryEscape(queryQuery))
	}

	return strings.Join(outputQueryParams, "&")
}
