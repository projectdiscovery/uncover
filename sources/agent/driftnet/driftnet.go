package driftnet

import (
	"context"
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
	OpenPortIPPortsURL = "https://api.driftnet.io/v1/scan/ipports?from=%s&ip=%s"
	DomainsURL         = "https://api.driftnet.io/v1/scan/domains?from=%s&most_recent=true&%s"
	ProtocolURL        = "https://api.driftnet.io/v1/scan/protocols?from=%s&most_recent=true&%s"
	PageMaxLimit       = 100
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

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.DriftnetToken == "" {
		return nil, errors.New("empty driftnet keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		queryTime := time.Now().AddDate(0, 0, -30)

		driftnetRequest := &DriftnetRequest{Query: query.Query, From: queryTime.Format(time.DateOnly), ResultLimit: query.Limit}

		agent.query(ctx, session, driftnetRequest, results)
	}()

	return results, nil
}

func (agent *Agent) query(ctx context.Context, session *sources.Session, driftnetRequest *DriftnetRequest, results chan sources.Result) {
	if iputil.IsIP(driftnetRequest.Query) || iputil.IsCIDR(driftnetRequest.Query) {
		agent.queryIPCIDR(ctx, session, driftnetRequest, results)
	} else {
		agent.querySearchTerm(ctx, session, driftnetRequest, results)
	}
}

func (agent *Agent) querySearchTerm(ctx context.Context, session *sources.Session, driftnetRequest *DriftnetRequest, results chan sources.Result) {
	totalReportedResults := 0

ENDPOINT_LOOP:
	for _, apiEndpoint := range []string{ProtocolURL, DomainsURL} {
		for currentPage := 0; currentPage < PageMaxLimit; currentPage++ {
			if ctx.Err() != nil {
				return
			}
			driftnetRequest.Page = currentPage

			resp, queryError := agent.queryURL(ctx, session, apiEndpoint, driftnetRequest)

			if queryError != nil {
				if resp != nil && resp.StatusCode == http.StatusNoContent {
					continue ENDPOINT_LOOP
				}

				sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: queryError})
				return
			}
			defer func() {
				_ = resp.Body.Close()
			}()

			driftnetResponse := &DriftnetAPIPaginatedResponse{}
			if err := json.NewDecoder(resp.Body).Decode(driftnetResponse); err != nil {
				sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
				return
			}

			for _, result := range driftnetResponse.Results {
				var ip string
				var port string
				var host string
				for _, item := range result.Items {
					if item.Context == "" {
						if strings.HasPrefix(item.Type, "port-") {
							port = item.Value
						}

						if item.Type == "ip" {
							ip = item.Value
						}

						if item.Type == "host" {
							host = item.Value
						}
					}
				}

				if len(port) > 0 && len(ip) > 0 {
					portAsInt, conversionError := strconv.Atoi(port)
					if conversionError != nil {
						if !sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: conversionError}) {
							return
						}
						continue
					}

					out := sources.Result{Source: agent.Name(), IP: ip, Port: portAsInt}

					if len(host) > 0 {
						out.Host = host
					}

					out.Raw, _ = json.Marshal(out)

					if !sources.SendResult(ctx, results, out) {
						return
					}
					totalReportedResults += 1
				}

				if driftnetRequest.ResultLimit > 0 && totalReportedResults >= driftnetRequest.ResultLimit {
					return
				}
			}

			if len(driftnetResponse.Results) < 100 {
				continue ENDPOINT_LOOP
			}
		}
	}
}

func (agent *Agent) queryIPCIDR(ctx context.Context, session *sources.Session, driftnetRequest *DriftnetRequest, results chan sources.Result) {
	var targetCIDR = driftnetRequest.Query

	if iputil.IsIP(targetCIDR) {
		if iputil.IsIPv4(targetCIDR) {
			targetCIDR = iputil.AsIPV4CIDR(targetCIDR)
		} else if iputil.IsIPv6(targetCIDR) {
			targetCIDR = iputil.AsIPV6CIDR(targetCIDR)
		}
	}

	requestCIDRs, splitError := mapcidr.SplitByNumber(targetCIDR, 1024)
	if splitError != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: splitError})
		return
	}

	totalReportedResults := 0
	for _, requestCIDR := range requestCIDRs {
		if ctx.Err() != nil {
			return
		}
		driftnetRequest.Query = requestCIDR.String()

		resp, queryError := agent.queryURL(ctx, session, OpenPortIPPortsURL, driftnetRequest)

		if queryError != nil {
			if resp != nil && resp.StatusCode == http.StatusNoContent {
				continue
			}

			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: queryError})
			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		driftnetResponse := &DriftnetAPIOpenIPPortResponse{}
		if err := json.NewDecoder(resp.Body).Decode(driftnetResponse); err != nil {
			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
			return
		}

		for ip, portsResponse := range driftnetResponse.Values {
			result := sources.Result{Source: agent.Name(), IP: ip}
			result.Raw, _ = json.Marshal(driftnetResponse)

			for port := range portsResponse.Values {
				result.Port = port
				if !sources.SendResult(ctx, results, result) {
					return
				}

				totalReportedResults += 1

				if driftnetRequest.ResultLimit > 0 && totalReportedResults >= driftnetRequest.ResultLimit {
					return
				}
			}
		}
	}
}

func (agent *Agent) queryURL(ctx context.Context, session *sources.Session, URL string, driftnetRequest *DriftnetRequest) (*http.Response, error) {
	apiURL := fmt.Sprintf(URL, url.QueryEscape(driftnetRequest.From), processQuery(driftnetRequest.Query))

	if driftnetRequest.Page > 0 {
		pageStr := strconv.Itoa(driftnetRequest.Page)
		apiURL = apiURL + "&page=" + pageStr
	}

	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", `Bearer `+session.Keys.DriftnetToken)
	return session.Do(request, agent.Name())
}

func processQuery(input string) string {
	if iputil.IsIP(input) || iputil.IsCIDR(input) {
		return url.QueryEscape(input)
	}

	inputParts := strings.Split(input, ",")

	var outputQueryParams []string
	for _, inputPart := range inputParts {
		parsedInputPart := strings.TrimSpace(inputPart)

		fieldQuery, isField := strings.CutPrefix(parsedInputPart, "field=")
		if isField {
			outputQueryParams = append(outputQueryParams, "field="+url.QueryEscape(fieldQuery))
			continue
		}

		keywordQuery, isKeyword := strings.CutPrefix(parsedInputPart, "keyword=")
		if isKeyword {
			outputQueryParams = append(outputQueryParams, "keyword="+url.QueryEscape(keywordQuery))
			continue
		}

		filterQuery, isFilter := strings.CutPrefix(parsedInputPart, "filter=")
		if isFilter {
			outputQueryParams = append(outputQueryParams, "filter="+url.QueryEscape(filterQuery))
			continue
		}

		queryQuery, _ := strings.CutPrefix(parsedInputPart, "query=")
		outputQueryParams = append(outputQueryParams, "query="+url.QueryEscape(queryQuery))
	}

	return strings.Join(outputQueryParams, "&")
}
