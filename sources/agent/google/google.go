package google

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/projectdiscovery/uncover/sources"
)

const (
	baseURL = "https://www.googleapis.com/customsearch/v1?key=%s&cx=%s&q=%s&start=%d&num=%d"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "google"
}

func (agent *Agent) Query(session *sources.Session, query *sources.Query) (chan sources.Result, error) {

	if session.Keys.GoogleKey == "" || session.Keys.GoogleCX == "" {
		return nil, errors.New("empty google keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		numberOfResults := 0
		pageQuery := 1

		escapedQuery := url.QueryEscape(query.Query)

		size := 10 // Max number of search results to return.
		if query.Limit < size {
			size = query.Limit
		}

		for {
			googleRequest := &Request{
				SearchTerms: escapedQuery,
				Count:       size,
				StartIndex:  pageQuery,
			}

			if numberOfResults > query.Limit {
				break
			}

			queryResult := agent.query(session, googleRequest, results)
			if queryResult == nil {
				break
			}

			if len(queryResult) == 0 {
				break
			}

			numberOfResults += len(queryResult)
			pageQuery += 1
		}
	}()

	return results, nil
}

func (agent *Agent) query(session *sources.Session, googleRequest *Request, results chan sources.Result) []string {

	resp, err := agent.queryURL(session, googleRequest)
	if err != nil {
		results <- sources.Result{Source: agent.Name(), Error: err}
		return nil
	}

	var apiResponse Response
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, errGzip := gzip.NewReader(resp.Body)
		if errGzip != nil {
			results <- sources.Result{Source: agent.Name(), Error: errGzip}
			return nil
		}
		defer gzipReader.Close()

		if errDecode := json.NewDecoder(gzipReader).Decode(&apiResponse); errDecode != nil {
			results <- sources.Result{Source: agent.Name(), Error: errDecode}
			return nil
		}
	} else {
		if errDecode := json.NewDecoder(resp.Body).Decode(&apiResponse); errDecode != nil {
			results <- sources.Result{Source: agent.Name(), Error: errDecode}
			return nil
		}
	}

	var lines []string
	if len(apiResponse.Items) > 0 {
		for _, googleResult := range apiResponse.Items {
			result := sources.Result{Source: agent.Name()}
			result.Url = googleResult.Link
			result.Host = agent.parseLink(googleResult.Link)
			result.IP = googleResult.Link
			raw, _ := json.Marshal(result)
			result.Raw = raw
			results <- result
			lines = append(lines, googleResult.Link)
		}
	}

	return lines
}

func (agent *Agent) queryURL(session *sources.Session, googleRequest *Request) (*http.Response, error) {

	googleURL := googleRequest.buildURL(session.Keys.GoogleKey, session.Keys.GoogleCX)
	request, err := sources.NewHTTPRequest(http.MethodGet, googleURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Accept-Encoding", "gzip")
	return session.Do(request, agent.Name())
}

func (agent *Agent) parseLink(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
