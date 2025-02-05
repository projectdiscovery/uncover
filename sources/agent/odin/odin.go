package odin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/projectdiscovery/uncover/sources"
)

type Agent struct{}

const (
	OdinAPIURL = "https://api.odin.io/v1/hosts/search"
)

type OdinRequest struct {
	Limit int       `json:"limit"`
	Query string    `json:"query"`
	Start []float64 `json:"start,omitempty"`
}

func (agent *Agent) Name() string {
	return "odin"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.OdinToken == "" {
		return nil, errors.New("empty odin token")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		totalFetched := 0
		var startCursor []float64

		for {
			reqBody := OdinRequest{
				Limit: query.Limit,
				Query: query.Query,
			}
			if len(startCursor) == 2 {
				reqBody.Start = startCursor
			}
			odinResp := agent.query(session, &reqBody, results)
			if odinResp == nil {
				break
			}

			countData := len(odinResp.Data)
			totalFetched += countData

			if countData == 0 {
				break
			}
			startCursor = odinResp.Pagination.Last

			if totalFetched >= query.Limit || totalFetched >= odinResp.Pagination.Total {
				break
			}
		}
	}()

	return results, nil
}

func (agent *Agent) query(session *sources.Session, odinReq *OdinRequest, results chan sources.Result) *OdinResponse {
	reqBody, err := json.Marshal(odinReq)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: fmt.Errorf("failed to marshal request: %v", err)}
		return nil
	}

	httpReq, err := sources.NewHTTPRequest(http.MethodPost, OdinAPIURL, bytes.NewReader(reqBody))
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	httpReq.Header.Set("X-API-Key", session.Keys.OdinToken)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := session.Do(httpReq, agent.Name())
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}
	defer resp.Body.Close()

	var odinResp OdinResponse
	if err := json.NewDecoder(resp.Body).Decode(&odinResp); err != nil {
		results <- sources.Result{Source: agent.Name(), Error: fmt.Errorf("failed to decode odin response: %v", err)}
		return nil
	}

	for _, host := range odinResp.Data {
		for _, svc := range host.Services {
			result := sources.Result{
				Source: agent.Name(),
				IP:     host.IP,
				Port:   svc.Port,
			}
			rawBytes, _ := json.Marshal(host)
			result.Raw = rawBytes

			results <- result
		}
	}

	return &odinResp
}
