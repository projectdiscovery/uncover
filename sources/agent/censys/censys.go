package censys

import (
	"context"
	"encoding/json"

	"errors"

	censyssdkgo "github.com/censys/censys-sdk-go"
	"github.com/censys/censys-sdk-go/models/components"
	"github.com/censys/censys-sdk-go/models/operations"
	"github.com/projectdiscovery/uncover/sources"
)

const (
	MaxPerPage = 100
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "censys"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.CensysToken == "" || session.Keys.CensysOrgId == "" {
		return nil, errors.New("empty censys keys")
	}

	s := censyssdkgo.New(
		censyssdkgo.WithOrganizationID(session.Keys.CensysOrgId),
		censyssdkgo.WithSecurity(session.Keys.CensysToken),
		censyssdkgo.WithClient(
			session.Client.HTTPClient,
		),
	)

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		var numberOfResults int
		nextCursor := ""
		for {
			if ctx.Err() != nil {
				return
			}
			censysRequest := &CensysRequest{
				Query:   query.Query,
				PerPage: MaxPerPage,
				Cursor:  nextCursor,
			}
			censysResponse := agent.query(ctx, s, censysRequest, results)
			if censysResponse == nil {
				break
			}
			hasNextCursor := false
			if censysResponse.ResponseEnvelopeSearchQueryResponse.Result != nil && censysResponse.ResponseEnvelopeSearchQueryResponse.Result.NextPageToken != "" {
				hasNextCursor = true
			}

			if !hasNextCursor || numberOfResults > query.Limit || len(censysResponse.ResponseEnvelopeSearchQueryResponse.Result.Hits) == 0 {
				break
			}
			nextCursor = censysResponse.ResponseEnvelopeSearchQueryResponse.Result.NextPageToken
			numberOfResults += len(censysResponse.ResponseEnvelopeSearchQueryResponse.Result.Hits)
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(ctx context.Context, s *censyssdkgo.SDK, censysRequest *CensysRequest) (*operations.V3GlobaldataSearchQueryResponse, error) {
	return s.GlobalData.Search(ctx, operations.V3GlobaldataSearchQueryRequest{
		SearchQueryInputBody: components.SearchQueryInputBody{
			PageSize:  censyssdkgo.Int64(int64(censysRequest.PerPage)),
			Query:     censysRequest.Query,
			PageToken: &censysRequest.Cursor,
		},
	})
}

func (agent *Agent) query(ctx context.Context, s *censyssdkgo.SDK, censysRequest *CensysRequest, results chan sources.Result) *operations.V3GlobaldataSearchQueryResponse {
	resp, err := agent.queryURL(ctx, s, censysRequest)
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}

	if result := resp.ResponseEnvelopeSearchQueryResponse.Result; result != nil {
		for _, censysResult := range result.Hits {
			for _, host := range censysResult.WebpropertyV1.Resource.Endpoints {
				out := sources.Result{Source: agent.Name()}
				if host.IP != nil {
					out.IP = *host.IP
				}
				if host.Hostname != nil {
					out.Host = *host.Hostname
				}
				if host.Port != nil {
					out.Port = *host.Port
				}
				if host.HTTP != nil && host.HTTP.URI != nil {
					out.Url = *host.HTTP.URI
				}
				raw, _ := json.Marshal(host)
				out.Raw = raw
				if !sources.SendResult(ctx, results, out) {
					return resp
				}
			}
		}
	}

	return resp
}

type CensysRequest struct {
	Query   string
	PerPage int
	Cursor  string
}
