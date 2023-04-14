package main

import (
	"net/http"

	"github.com/scorpio-id/oauth/internal/grants"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/token", grants.ClientCredentialsHandler).Methods(http.MethodPost)
	http.ListenAndServe(":8081", r)
}
