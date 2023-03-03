package hunterhow

import (
	"encoding/base64"
	"strconv"
	"time"
)

type Request struct {
	Query    string `json:"query"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

func (r *Request) buildURL(key string) string {
	timeFormat := "2006-01-02"
	now := time.Now()
	firstDay := time.Date(now.Year(), time.January, 1, 0, 0, 0, 0, now.Location())
	startTimeStr := firstDay.Format(timeFormat)
	endTimeStr := now.Format(timeFormat)

	queryStr := baseURL +
		baseEndpoint + "?api-key=" + key +
		"&query=" + base64.StdEncoding.EncodeToString([]byte(r.Query)) +
		"&start_time=" + startTimeStr +
		"&end_time=" + endTimeStr +
		"&page_size=" + strconv.Itoa(r.PageSize) +
		"&page=" + strconv.Itoa(r.Page)

	return queryStr
}
