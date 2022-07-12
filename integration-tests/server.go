//delete me

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/julienschmidt/httprouter"
)

func main() {
	exit := make(chan bool)
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("request")
		duration := time.Duration(5 * time.Minute)
		time.Sleep(duration)
		fmt.Fprintf(w, "Ok\n")
		r.Close = true
	}))
	ts := httptest.NewServer(router)
	fmt.Println("listening on:", ts.URL)
	<-exit
	defer ts.Close()
}
