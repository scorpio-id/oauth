package main

import (
	"log"
	"net/http"

	_ "github.com/scorpio-id/oauth/docs"
	"github.com/scorpio-id/oauth/internal/config"
	"github.com/scorpio-id/oauth/internal/transport"
)

// @title Scorpio OAuth
// @version 1.0
// @description a Go OAuth2 issuer implementation
// @termsOfService http://swagger.io/terms/

// @securityDefinitions.oauth2 OAuth2

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://mit-license.org
func main() {
	// parse local config
	cfg := config.NewConfig("internal/config/local.yml")

	// create a new mux router
	router, _ := transport.NewRouter(cfg)

	// start the server
	log.Fatal(http.ListenAndServe(":"+cfg.Server.Port, router))
}

